# NERRF Proto Schemas

This folder contains Protobuf schemas for NERRF's data exchange, e.g., eBPF event traces for dependency graphs and undo planning.

## trace.proto

- **Version**: 0.9 (M0 final)
- **Purpose**: Captures syscall events for LockBit simulations (e.g., write/rename for encryption).
- **Fields**: Temporal (ts_ns), process (pid/tid/comm), syscall (syscall/ret_val), file (path/new_path/flags/bytes), metadata (file_size/inode/mode), edges (edge_type/parent_inode/dependencies).
- **Usage**: Compile with `protoc --go_out=. trace.proto` for Go code.
- **Example**: Event for a "write" during encryption: {ts_ns: 123456789, syscall: "write", file_path: "/app/uploads/file.dat", bytes: 512000, edge_type: WRITE}.

## Compilation Test

```bash
cd proto/
chmod +x compile_test.sh && compile_test.sh

```

or, Run `protoc --go_out=. proto/trace.proto` to test. No errors means success.

## Example

```json
{
  "ts": "2025-11-02T12:35:01.123Z",
  "pid": 1234,
  "tid": 1234,
  "comm": "python3",
  "syscall": "write",
  "path": "/home/user/data.txt",
  "new_path": "",
  "flags": "O_WRONLY",
  "ret_val": 12,
  "bytes": 12,
  "inode": "123456789",
  "mode": 420,
  "uid": 1000,
  "gid": 1000,
  "dependencies": ["input.txt"]
}
```

## Future Extensions

- Add Timestamp for absolute time (M2 AI integration).
- More enums for LockBit-specific TTPs.

For details, see docs/attack_scenario.md.
