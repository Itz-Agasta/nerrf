#!/usr/bin/env bash
set -euo pipefail

# test.sh  – CI-friendly Minikube test
CLUSTER="nerrf-m1-test"
IMAGE="nerrf/tracker:m1"
POD="m0-victim"
EVENT_THRESHOLD=10

# Cleanup function
cleanup() {
  echo "🧹 Cleaning up..."
  kubectl delete pod $POD --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete pod nerrf-tracker --ignore-not-found >/dev/null 2>&1 || true
  # docker stop tracker >/dev/null 2>&1 || true
  # minikube delete >/dev/null 2>&1 || true
}

# Set trap for cleanup on exit
trap cleanup EXIT

echo "🔧 1.  Start minikube"
# Check if minikube is already running and healthy
if minikube status >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1; then
  echo "Minikube is already running and healthy, skipping start..."
else
  if minikube status >/dev/null 2>&1; then
    echo "Minikube is running but kubectl can't connect, restarting..."
    minikube delete
  fi
  minikube start --cpus=2 --memory=4g --driver=docker
fi

echo "📦 2.  Load tracker image into minikube"
minikube image load "$IMAGE"

echo "📄 2.5. Create ConfigMap for simulation script"
kubectl create configmap lockbit-simulator --from-file=sim_lockbit.py=/home/agasta/res/nerrf/benchmarks/m0/scripts/sim_lockbit.py --dry-run=client -o yaml | kubectl apply -f -

echo "🚀 3.  Deploy tracker pod"
kubectl apply -f /home/agasta/res/nerrf/benchmarks/m0/manifests/tracker-pod.yaml
kubectl wait --for=condition=Ready pod/nerrf-tracker --timeout=60s

echo "⏳ 4.  Wait for gRPC ready"
# Wait for container to be running
sleep 3

# Get minikube IP for gRPC connection
MINIKUBE_IP=$(minikube ip)
echo "Tracker pod is running, waiting for gRPC service on $MINIKUBE_IP:50051..."
sleep 5  # Give more time for the service to start

# Simple gRPC check
echo "Testing gRPC connection..."
for i in {1..10}; do
  if grpcurl -plaintext $MINIKUBE_IP:50051 list >/dev/null 2>&1; then
    echo "✅ gRPC service is ready"
    break
  else
    echo "Attempt $i: gRPC not ready yet..."
    sleep 2
  fi
done

if ! grpcurl -plaintext $MINIKUBE_IP:50051 list >/dev/null 2>&1; then
  echo "❌ gRPC service failed to start"
  exit 1
fi

echo "📊 5.  Inject LockBit sim"
kubectl apply -f /home/agasta/res/nerrf/benchmarks/m0/manifests/m0_victim.yaml
kubectl wait --for=condition=Ready pod/$POD --timeout=60s

echo "🔍 6.  Capture 10 s of events"
# Capture events with error handling - look for any file operations
echo "Starting event capture..."
timeout 15 bash -c "
grpcurl -plaintext $MINIKUBE_IP:50051 nerrf.trace.Tracker/StreamEvents 2>/dev/null | 
jq -r '.events[] | select(.path != null and (.path | contains(\".dat\") or contains(\".lockbit\"))) | .syscall' 2>/dev/null | 
wc -l
" > event_count.txt 2>/dev/null || echo "0" > event_count.txt

EVENT_COUNT=$(cat event_count.txt)
echo "📈 Events captured: $EVENT_COUNT"

if (( EVENT_COUNT >= EVENT_THRESHOLD )); then
  echo "✅ PASS – Captured $EVENT_COUNT events from LockBit simulation"
else
  echo "❌ FAIL – Only captured $EVENT_COUNT events (< $EVENT_THRESHOLD expected)"
  exit 1
fi

echo "🧹 7.  Clean-up"
kubectl delete pod $POD --ignore-not-found
kubectl delete pod nerrf-tracker --ignore-not-found
# minikube delete
# docker stop tracker || true