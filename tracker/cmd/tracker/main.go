// Package main implements the NERRF Tracker - M1 Milestone
//
// The NERRF Tracker is an eBPF-based system call tracer that captures file operations
// (openat, write, rename) from the Linux kernel and streams them via gRPC to AI models
// for ransomware detection and recovery planning.
//
// Architecture:
//   - eBPF tracepoints attached to syscall entry points
//   - Ring buffer for efficient kernel->userspace event passing
//   - gRPC streaming server for real-time event distribution
//   - Protobuf-based event schema for structured data
//
// This is part of the Neural Execution Reversal & Recovery Framework (NERRF)
// designed to enable AI-driven "undo computing" for post-ransomware recovery.
//
// Author: Itz-Agasta
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Itz-Agasta/nerrf/tracker/pkg/bpf"
	pb "github.com/Itz-Agasta/nerrf/tracker/pkg/pb"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// getenvDefault returns the value of environment variable k, or v if not set.
// Used for configurable runtime parameters like listening address.
func getenvDefault(k, v string) string {
	if val := os.Getenv(k); val != "" {
		return val
	}
	return v
}

// main initializes and runs the NERRF Tracker service.
//
// Startup sequence:
//  1. Locate and validate eBPF object file (tracepoints.o)
//  2. Set memory limits for eBPF programs
//  3. Load and attach eBPF tracepoints to kernel
//  4. Initialize ring buffer reader for kernel events
//  5. Start gRPC server for client connections
//  6. Begin event processing and broadcasting
//  7. Wait for shutdown signal and cleanup gracefully
//
// Environment Variables:
//
//	TRACKER_LISTEN_ADDR - gRPC server address (default: 127.0.0.1:50051)
//
// Requirements:
//   - Root privileges for eBPF operations
//   - Kernel 4.18+ with eBPF support
//   - CAP_SYS_ADMIN capability
func main() {
	// Get the directory of the executable (I was having some import issue prv.)
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)
	objPath := filepath.Join(execDir, "../bpf/tracepoints.o")

	// Validate BPF object exists
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		log.Fatalf("BPF object not found: %s", objPath)
	}

	// Set rlimit for eBPF - required for loading BPF programs
	// RLIM_INFINITY allows unlimited memory locking for BPF maps
	var rLimit unix.Rlimit
	rLimit.Cur = unix.RLIM_INFINITY
	rLimit.Max = unix.RLIM_INFINITY
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		log.Fatalf("setrlimit: %v", err)
	}

	// Load BPF object and attach tracepoints
	// This attaches our programs to sys_enter_openat, sys_enter_write, sys_enter_rename
	ringBufMap, links, err := bpf.LoadTracepoints(objPath)
	if err != nil {
		log.Fatalf("load tracepoints: %v", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Ring-buffer reader - reads events from kernel space
	// Ring buffers are more efficient than older perf events
	rd, err := ringbuf.NewReader(ringBufMap)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	// gRPC server setup
	addr := getenvDefault("TRACKER_LISTEN_ADDR", "127.0.0.1:50051")
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	serv := &server{
		rd:      rd,
		clients: make(map[chan *pb.EventBatch]struct{}),
	}

	// Calculate boot time for accurate event timestamps
	// eBPF uses CLOCK_MONOTONIC, we need to convert to wall clock time
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("clock_gettime: %v", err)
	}
	monoNs := ts.Sec*1000000000 + ts.Nsec
	serv.bootTime = time.Now().Add(-time.Duration(monoNs) * time.Nanosecond)

	// Register gRPC service and enable reflection for debugging
	pb.RegisterTrackerServer(s, serv)
	reflection.Register(s)
	log.Printf("Tracker listening on %s", addr)

	// Start background goroutines
	go serv.broadcastEvents() // Process events from ring buffer
	go func() {
		if err := s.Serve(lis); err != nil {
			if err == grpc.ErrServerStopped {
				log.Println("gRPC server stopped")
			} else {
				log.Fatalf("serve: %v", err)
			}
		}
	}()

	// Graceful shutdown on SIGINT or SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, unix.SIGTERM)
	<-sig
	rd.Close()
	s.GracefulStop()
}

// server implements the TrackerServer gRPC interface.
// It manages client connections and broadcasts eBPF events to all connected clients.
//
// The server maintains:
//   - rd: Ring buffer reader for kernel events
//   - clients: Map of active client channels
//   - bootTime: System boot time for timestamp conversion
//   - mu: Mutex for thread-safe client management
type server struct {
	pb.UnimplementedTrackerServer
	rd       *ringbuf.Reader
	mu       sync.Mutex
	clients  map[chan *pb.EventBatch]struct{}
	bootTime time.Time
}

// StreamEvents implements the gRPC streaming endpoint for event distribution.
// Each client gets their own channel and receives all events in real-time.
//
// The method:
//  1. Creates a buffered channel for this client
//  2. Registers the channel in the clients map
//  3. Streams events until client disconnects
//  4. Cleans up client channel on completion
//
// Channel buffer size (100) prevents blocking on slow clients.
func (s *server) StreamEvents(req *pb.Empty, stream pb.Tracker_StreamEventsServer) error {
	clientChan := make(chan *pb.EventBatch, 100)
	s.mu.Lock()
	s.clients[clientChan] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, clientChan)
		s.mu.Unlock()
		close(clientChan)
	}()
	for {
		select {
		case batch := <-clientChan:
			if err := stream.Send(batch); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// broadcastEvents is the main event processing loop.
// It continuously reads events from the eBPF ring buffer and distributes
// them to all connected clients.
//
// Process:
//  1. Read raw event from ring buffer
//  2. Parse binary data into Go struct
//  3. Convert to protobuf format with timestamp correction
//  4. Broadcast to all active client channels
//  5. Skip slow clients to prevent blocking
//
// This runs in a separate goroutine and terminates when ring buffer is closed.
func (s *server) broadcastEvents() {
	for {
		record, err := s.rd.Read()
		if err != nil {
			log.Printf("ringbuf read error: %v", err)
			return
		}

		// Parse the raw eBPF event data
		var e event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("binary read error: %v", err)
			continue
		}

		// Convert monotonic timestamp to wall clock time
		eventTime := s.bootTime.Add(time.Duration(e.Ts) * time.Nanosecond)

		// Create protobuf event with all available fields
		pbEvent := &pb.Event{
			Ts:      timestamppb.New(eventTime),
			Pid:     e.Pid,
			Tid:     e.Tid,
			Comm:    sanitizeString(e.Comm[:]),
			Syscall: syscallName(e.SyscallId),
			Path:    sanitizeString(e.Path[:]),
			NewPath: sanitizeString(e.NewPath[:]),
			RetVal:  e.RetVal,
			Bytes:   e.Bytes,
			// TODO: Add flags, inode, mode, uid, gid in future iterations
			Flags: pb.Event_O_RDONLY, // Default for now
		}

		batch := &pb.EventBatch{Events: []*pb.Event{pbEvent}}

		// Broadcast to all connected clients
		s.mu.Lock()
		for ch := range s.clients {
			select {
			case ch <- batch:
				// Event sent successfully
			default:
				// Skip if channel is full to avoid blocking
				// This prevents slow clients from affecting overall performance
			}
		}
		s.mu.Unlock()
	}
}

// event represents the raw data structure passed from eBPF to userspace.
// This must match exactly with the struct defined in tracepoints.c
//
// Fields:
//
//	Ts: Kernel timestamp (CLOCK_MONOTONIC nanoseconds)
//	Pid/Tid: Process and thread identifiers
//	Comm: Executable name (truncated to 16 chars by kernel)
//	SyscallId: Our custom syscall identifier (1=openat, 2=write, 3=rename)
//	RetVal: System call return value (file descriptor or error)
//	Bytes: Number of bytes for write operations
//	Path: File path for openat/rename (up to 256 chars)
//	NewPath: Destination path for rename operations
type event struct {
	Ts        uint64
	Pid       uint32
	Tid       uint32
	Comm      [16]byte
	SyscallId uint32
	RetVal    int64
	Bytes     uint64
	Path      [256]byte
	NewPath   [256]byte
}

// syscallName converts our custom syscall IDs to human-readable names.
// These IDs are defined in tracepoints.c and must match exactly.
//
// Mapping:
//
//	1 -> "openat"  (file open/create operations)
//	2 -> "write"   (file write operations - key for LockBit detection)
//	3 -> "rename"  (file rename/move operations - LockBit adds .lockbit extension)
//
// Future: Could extend to include unlink, chmod, etc. for more comprehensive tracking
func syscallName(id uint32) string {
	switch id {
	case 1:
		return "openat"
	case 2:
		return "write"
	case 3:
		return "rename"
	default:
		return "unknown"
	}
}

// sanitizeString converts byte arrays from eBPF into clean UTF-8 strings.
// eBPF strings are null-terminated and may contain invalid UTF-8 sequences.
//
// Process:
//  1. Remove null terminators from the byte array
//  2. Check if the resulting string is valid UTF-8
//  3. Replace invalid sequences with "?" if necessary
//
// This is important for protobuf compatibility and preventing encoding issues
// when transmitting events to clients.
func sanitizeString(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	if !utf8.ValidString(s) {
		// Replace invalid UTF-8 sequences
		s = strings.ToValidUTF8(s, "?")
	}
	return s
}
