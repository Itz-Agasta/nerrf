# Makefile  – zero-surprise build
SHELL        := /bin/bash
CLANG        ?= clang
KERNELRELEASE := $(shell uname -r)
BPF_OBJ      := bpf/tracepoints.o
TRACKER_BIN  := bin/tracker
DOCKER_TAG   := nerrf/tracker:m1

.PHONY: all clean bpf tracker docker test test-unit test-bench test-minikube install-deps

all: bpf tracker

bpf: $(BPF_OBJ)
$(BPF_OBJ): bpf/tracepoints.c
	@mkdir -p bpf bin
	$(CLANG) -O2 -g -target bpf -c $< -o $@

tracker: $(TRACKER_BIN)
$(TRACKER_BIN): go.mod $(shell find . -name '*.go')
	go mod tidy
	go build -o $@ ./cmd/tracker

docker:
	docker build -f Dockerfile.minimal -t $(DOCKER_TAG) .

# M1 Milestone Tests
test: test-unit test-bench
	@echo "✅ All M1 milestone tests completed"

test-unit:
	@echo "Running unit tests..."
	cd test && go test -v -run Test

test-bench:
	@echo "Running performance benchmarks..."
	cd test && go test -bench=Benchmark -benchtime=60s

test-minikube:
	@echo "Running Minikube integration tests..."
	cd test && go test -v -run TestMinikube

test-full: bpf tracker
	@echo "Running full M1 milestone validation..."
	./scripts/test.sh

# Install dependencies (requires root)
install-deps:
	@echo "📦 Installing dependencies..."
	curl -sSL https://raw.githubusercontent.com/Itz-Agasta/nerrf/tracker/scripts/install-deps.sh | bash

clean:
	rm -rf bin/ bpf/*.o test/benchmark_results.txt test/cpu_benchmark.txt