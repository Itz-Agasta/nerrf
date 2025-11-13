```
tracker/
├── bpf/
│   └── tracepoints.c      # openat / write / rename
├── cmd/
│   └── tracker/           # main.go (gRPC server)
├── pkg/
│   ├── bpf/               # loader, ring-buffer
│   └── pb/                # generated trace.pb.go
├── Dockerfile.minimal     # single-stage, no kernel headers needed
├── scripts/
│   └── install-deps.sh    # One-liner for dev deps
├── go.mod                 # module github.com/Itz-Agasta/nerrf/tracker
├── Makefile               # `make run` → builds + starts server
└── README.md              # quick-start for contributors
```

```
protoc -I=proto \
  --go_out=tracker/pkg/pb --go_opt=paths=source_relative \
  --go-grpc_out=tracker/pkg/pb --go-grpc_opt=paths=source_relative \
  proto/trace.proto
```

```
cd tracker
make tracker
```

```
sudo ./tracker/bin/tracker
```

This will output `2025/09/09 11:49:25 Tracker listening on :50051`

To stream live events

```
grpcurl -plaintext -d '{}' localhost:50051 nerrf.trace.Tracker/StreamEvents
```

#### Docker Build

```bash
docker build -f tracker/Dockerfile.minimal -t nerrf/tracker:m1 .
```

![grpc](../docs/imgs/gRPC.svg)
