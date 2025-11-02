#!/bin/bash
# NERRF Tracker - Public Dependency Installation Script
# Milestone: M1 - Tracker Alpha
# 
# This script installs all dependencies required to build and run the NERRF Tracker
# on Ubuntu/Debian and RHEL/CentOS systems.
#
# Requirements:
#   - Root or sudo access
#   - Internet connection
#   - Linux kernel 4.18+ with eBPF support
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Itz-Agasta/nerrf/m1/scripts/install-deps.sh | bash
#   # OR
#   wget -O- https://raw.githubusercontent.com/Itz-Agasta/nerrf/m1/scripts/install-deps.sh | bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GO_VERSION="1.23.0"
CLANG_MIN_VERSION="10"
KERNEL_MIN_VERSION="4.18"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. This is required for eBPF setup."
    elif command -v sudo >/dev/null 2>&1; then
        log_info "Will use sudo for privileged operations."
        SUDO="sudo"
    else
        log_error "This script requires root privileges or sudo access."
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$ID"
        VERSION="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
    else
        log_error "Unsupported Linux distribution"
        exit 1
    fi
    
    log_info "Detected: $DISTRO $VERSION"
}

# Check kernel version and eBPF support
check_kernel() {
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    
    log_info "Checking kernel version: $(uname -r)"
    
    # Check minimum kernel version
    if ! printf '%s\n%s\n' "$KERNEL_MIN_VERSION" "$kernel_version" | sort -V -C; then
        log_error "Kernel version $kernel_version is too old. Minimum required: $KERNEL_MIN_VERSION"
        exit 1
    fi
    
    # Check for eBPF support
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warning "BPF filesystem not mounted. Attempting to mount..."
        ${SUDO:-} mount -t bpf bpf /sys/fs/bpf || {
            log_error "Failed to mount BPF filesystem"
            exit 1
        }
    fi
    
    # Check for required kernel configs (if available)
    local config_file=""
    if [[ -f /proc/config.gz ]]; then
        config_file="/proc/config.gz"
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
    fi
    
    if [[ -n "$config_file" ]]; then
        log_info "Checking kernel eBPF configuration..."
        local configs=(
            "CONFIG_BPF=y"
            "CONFIG_BPF_SYSCALL=y"
            "CONFIG_BPF_EVENTS=y"
        )
        
        for config in "${configs[@]}"; do
            if ! zcat "$config_file" 2>/dev/null | grep -q "^$config" && ! grep -q "^$config" "$config_file" 2>/dev/null; then
                log_warning "Kernel config $config not found or disabled"
            fi
        done
    fi
    
    log_success "Kernel eBPF support verified"
}

# Install packages for Ubuntu/Debian
install_ubuntu_deps() {
    log_info "Installing dependencies for Ubuntu/Debian..."
    
    ${SUDO:-} apt-get update
    
    # Essential build tools
    ${SUDO:-} apt-get install -y \
        build-essential \
        clang \
        llvm \
        gcc-multilib \
        linux-headers-$(uname -r) \
        linux-tools-common \
        linux-tools-$(uname -r) \
        pkg-config \
        libelf-dev \
        libbpf-dev \
        bpftool \
        curl \
        wget \
        git \
        make
    
    # Protocol Buffers
    ${SUDO:-} apt-get install -y \
        protobuf-compiler \
        libprotobuf-dev
    
    log_success "Ubuntu/Debian dependencies installed"
}

# Install packages for RHEL/CentOS/Fedora
install_rhel_deps() {
    log_info "Installing dependencies for RHEL/CentOS/Fedora..."
    
    # Determine package manager
    if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    else
        log_error "No supported package manager found"
        exit 1
    fi
    
    # Install EPEL for RHEL/CentOS (if needed)
    if [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "centos" ]]; then
        ${SUDO:-} $PKG_MGR install -y epel-release || true
    fi
    
    # Essential build tools
    ${SUDO:-} $PKG_MGR install -y \
        gcc \
        gcc-c++ \
        clang \
        llvm \
        make \
        kernel-devel \
        kernel-headers \
        elfutils-libelf-devel \
        libbpf-devel \
        bpftool \
        curl \
        wget \
        git \
        pkgconfig
    
    # Protocol Buffers
    ${SUDO:-} $PKG_MGR install -y \
        protobuf-compiler \
        protobuf-devel
    
    log_success "RHEL/CentOS/Fedora dependencies installed"
}

# Install Go
install_go() {
    log_info "Checking Go installation..."
    
    if command -v go >/dev/null 2>&1; then
        local current_version
        current_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
        
        if printf '%s\n%s\n' "$GO_VERSION" "$current_version" | sort -V -C; then
            log_success "Go $current_version is already installed (>= $GO_VERSION)"
            return
        else
            log_info "Go $current_version found, but $GO_VERSION is required"
        fi
    fi
    
    log_info "Installing Go $GO_VERSION..."
    
    # Download and install Go
    local go_arch
    case $(uname -m) in
        x86_64) go_arch="amd64" ;;
        aarch64) go_arch="arm64" ;;
        armv6l) go_arch="armv6l" ;;
        armv7l) go_arch="armv6l" ;;
        *) log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    local go_tar="go${GO_VERSION}.linux-${go_arch}.tar.gz"
    local go_url="https://golang.org/dl/${go_tar}"
    
    # Remove existing Go installation
    ${SUDO:-} rm -rf /usr/local/go
    
    # Download and extract
    wget -O "/tmp/${go_tar}" "$go_url"
    ${SUDO:-} tar -C /usr/local -xzf "/tmp/${go_tar}"
    rm "/tmp/${go_tar}"
    
    # Add to PATH if not already there
    if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    
    if ! grep -q '/usr/local/go/bin' ~/.zshrc 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true
    fi
    
    # Set for current session
    export PATH=$PATH:/usr/local/go/bin
    
    log_success "Go $GO_VERSION installed"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check Go
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go not found in PATH. Please restart your shell or run: export PATH=\$PATH:/usr/local/go/bin"
        exit 1
    fi
    
    local go_version
    go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
    log_success "Go $go_version verified"
    
    # Check clang
    if ! command -v clang >/dev/null 2>&1; then
        log_error "clang not found"
        exit 1
    fi
    
    local clang_version
    clang_version=$(clang --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+' | head -n1)
    log_success "clang $clang_version verified"
    
    # Check protoc
    if ! command -v protoc >/dev/null 2>&1; then
        log_error "protoc not found"
        exit 1
    fi
    
    local protoc_version
    protoc_version=$(protoc --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    log_success "protoc $protoc_version verified"
    
    # Check bpftool (optional but recommended)
    if command -v bpftool >/dev/null 2>&1; then
        log_success "bpftool available"
    else
        log_warning "bpftool not found (optional for debugging)"
    fi
    
    log_success "All dependencies verified successfully!"
}

# Install Go tools for development
install_go_tools() {
    log_info "Installing Go development tools..."
    
    # Ensure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin
    
    # Install protoc-gen-go
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    
    # Add Go bin to PATH
    local go_bin_path
    go_bin_path=$(go env GOPATH)/bin
    
    if ! grep -q "$go_bin_path" ~/.bashrc; then
        echo "export PATH=\$PATH:$go_bin_path" >> ~/.bashrc
    fi
    
    if ! grep -q "$go_bin_path" ~/.zshrc 2>/dev/null; then
        echo "export PATH=\$PATH:$go_bin_path" >> ~/.zshrc 2>/dev/null || true
    fi
    
    log_success "Go tools installed"
}

# Main installation flow
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               NERRF Tracker Dependency Installer             ║"
    echo "║                     M1 - Tracker Alpha                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_privileges
    detect_distro
    check_kernel
    
    case "$DISTRO" in
        ubuntu|debian)
            install_ubuntu_deps
            ;;
        rhel|centos|fedora)
            install_rhel_deps
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    install_go
    install_go_tools
    verify_installation
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Installation Complete!                    ║"
    echo "║                                                              ║"
    echo "║  Next steps:                                                 ║"
    echo "║  1. Restart your shell or run: source ~/.bashrc             ║"
    echo "║  2. Clone NERRF: git clone https://github.com/Itz-Agasta/nerrf ║"
    echo "║  3. Build tracker: cd nerrf/tracker && make all             ║"
    echo "║  4. Run as root: sudo ./bin/tracker                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Run main function
main "$@"
