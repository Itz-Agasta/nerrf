# NERRF Benchmarks

This directory contains organized benchmarks for validating NERRF's ransomware recovery capabilities.

## Structure

```
benchmarks/
├── m0/                 # Basic validation benchmark
│   ├── scripts/        # M0-specific executables
│   ├── manifests/      # Kubernetes deployment configs
│   └── results/        # Generated datasets and traces
└── m1/                 # Enterprise-scale benchmark
    ├── scripts/        # M1-specific executables
    ├── manifests/      # Kubernetes deployment configs
    └── results/        # Generated datasets and traces
```

## Quick Start

### M0 (Basic - 13MB, 25 files)

```bash
cd benchmarks/m0/scripts
./m0_minikube_bootstrap.sh
```

### M1 (Enterprise - 108MB, 46 files)

```bash
cd benchmarks/m1/scripts
./m1_minikube_bootstrap.sh
```

## Integration with NERRF Components

- **eBPF Tracker**: Use trace patterns from `*_trace.jsonl`
- **GNN Training**: File paths and metadata become graph nodes
- **LSTM Models**: Attack phase sequences for temporal detection
- **MCTS Planning**: Ground truth provides optimal recovery paths
- **Firecracker**: Sandbox validation using generated datasets
