#!/bin/sh
# Gives the cluster something to be read. A fresh k3s has coredns and the local
# path provisioner and nothing else, which proves the list commands run but
# never proves they page, group by namespace, or show a workload in trouble.
#
# Nothing here hides an error: a lab that silently plants nothing looks exactly
# like a tool that silently reads nothing, and that was worth an hour once.
set +e

IMAGE=alpine:3.20

try() {
  label=$1
  shift
  output=$("$@" 2>&1)
  if [ $? -eq 0 ]; then
    echo "  + $label"
  else
    echo "  ! $label —— $(printf '%s' "$output" | head -1)"
  fi
}

echo "建命名空间…"
for ns in payments frontend jobs; do
  try "$ns" kubectl create namespace "$ns"
done

# A namespace is usable a moment before its default ServiceAccount exists, and
# a pod created in that window is refused outright. On a cold cluster this hit
# often enough to lose a workload every other run.
echo "等默认 ServiceAccount…"
for ns in payments frontend jobs; do
  for _ in $(seq 1 30); do
    kubectl -n "$ns" get serviceaccount default >/dev/null 2>&1 && break
    sleep 2
  done
done

echo "建工作负载…"
# A healthy multi-replica Deployment: scaling it is the mutation the tool plans.
try "payments/ledger (3)" kubectl -n payments create deployment ledger \
  --image="$IMAGE" --replicas=3 -- sleep infinity

try "frontend/storefront (2)" kubectl -n frontend create deployment storefront \
  --image="$IMAGE" --replicas=2 -- sleep infinity

# A Deployment that can never become ready: the pod list has to show a real
# failing state, not just Running rows.
try "jobs/nightly-report（镜像拉不到，故意的）" kubectl -n jobs create deployment nightly-report \
  --image=lovelyres-lab/does-not-exist:9.9 --replicas=1

# A pod that exits and restarts forever, so RESTARTS is not always 0. It says
# why before it dies, so the logs of the run before a restart have a cause in
# them — the line a responder opens 上次日志 to find.
try "jobs/flapping-worker（反复重启，故意的）" kubectl -n jobs run flapping-worker \
  --image="$IMAGE" --restart=Always --command -- sh -c \
  'echo "flapping-worker lab-marker: cannot reach queue, exiting 1"; sleep 5; exit 1'

# A pod that writes to stdout, so the log reader has something to page.
try "frontend/access-logger（持续输出日志）" kubectl -n frontend run access-logger \
  --image="$IMAGE" --restart=Never --command -- sh -c \
  'i=0; while true; do i=$((i+1)); echo "$(date -Iseconds) request id=$i path=/health status=200"; sleep 2; done'

echo "等工作负载调度…"
for _ in $(seq 1 40); do
  running=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c Running)
  [ "${running:-0}" -ge 7 ] && break
  sleep 5
done

echo "--- 现状 ---"
kubectl get pods -A --no-headers 2>&1 | head -20
echo "命名空间 $(kubectl get ns --no-headers 2>/dev/null | wc -l) 个，Pod $(kubectl get pods -A --no-headers 2>/dev/null | wc -l) 个，节点 $(kubectl get nodes --no-headers 2>/dev/null | wc -l) 个"
