#!/usr/bin/env bash
# Kubernetes WireGuard dynamic-peer e2e against a local kind cluster.
#
# Builds the workspace into a kind-loaded image, applies the e2e kustomize
# overlay (examples base + *-e2e isolation), and drives the full lifecycle:
# register -> handoff -> restricted-agent contract -> tunnel data path ->
# lease/peer tables -> heartbeat -> deregister/expiry -> peer revocation.
#
# The manifests are the source of truth (examples/kubernetes/kustomization +
# e2e/kubernetes-wireguard-e2e-overlay); this script only builds the image,
# applies the overlay, and asserts. It does not template YAML.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY="${ROOT}/e2e/kubernetes-wireguard-e2e-overlay"
DOCKERFILE="${ROOT}/Dockerfile"

CLUSTER_NAME="${CLAWPATROL_E2E_CLUSTER:-kind}"
KUBE_CONTEXT="${CLAWPATROL_E2E_CONTEXT:-kind-${CLUSTER_NAME}}"
TIMEOUT="${CLAWPATROL_E2E_TIMEOUT:-180s}"
SKIP_BUILD="${CLAWPATROL_E2E_SKIP_BUILD:-0}"
KEEP_RESOURCES="${CLAWPATROL_E2E_KEEP_RESOURCES:-0}"
CHECK_HEARTBEAT="${CLAWPATROL_E2E_CHECK_HEARTBEAT:-1}"
CHECK_EXPIRY="${CLAWPATROL_E2E_CHECK_EXPIRY:-0}"
GOARCH_OVERRIDE="${CLAWPATROL_E2E_GOARCH:-}"

# These are fixed by the overlay (images: transformer, namespaces, RBAC
# names, gateway.hcl). Keep them in sync with the overlay if you change it.
IMAGE="clawpatrol-kind-e2e:dev"
GATEWAY_NS="clawpatrol-e2e"
AGENTS_NS="agents-e2e"
CLUSTER_ROLE_NAME="clawpatrol-tokenreview-e2e"
E2E_POD="clawpatrol-agent-example"
E2E_HTTP="clawpatrol-e2e-http"

KUBECTL=(kubectl --context "${KUBE_CONTEXT}")
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/clawpatrol-k8s-e2e.XXXXXX")"

# LEASE_TTL is read from the overlay config (in preflight, after the files
# are confirmed to exist) so the heartbeat wait stays in sync with what the
# gateway actually enforces.
LEASE_TTL="30s"

usage() {
  cat <<'USAGE'
Run the Kubernetes WireGuard dynamic-peer e2e against a local kind cluster.

  ./e2e/kubernetes-wireguard-e2e.sh

Environment knobs:
  CLAWPATROL_E2E_CLUSTER         kind cluster name, default: kind
  CLAWPATROL_E2E_CONTEXT         kubectl context, default: kind-${cluster}
  CLAWPATROL_E2E_TIMEOUT         kubectl wait timeout, default: 180s
  CLAWPATROL_E2E_SKIP_BUILD      set 1 to skip go/docker build + kind load
  CLAWPATROL_E2E_KEEP_RESOURCES  set 1 to skip final namespace cleanup
  CLAWPATROL_E2E_CHECK_HEARTBEAT set 0 to skip the heartbeat advancement check
  CLAWPATROL_E2E_CHECK_EXPIRY    set 1 to test TTL cleanup (force-delete sidecar)
  CLAWPATROL_E2E_GOARCH          override node arch for the Linux build

Image tag, namespaces, lease TTL, and RBAC names live in the overlay
(e2e/kubernetes-wireguard-e2e-overlay); edit there, not here.
USAGE
}

log() { printf '[e2e] %s\n' "$*"; }
fail() {
  printf '[e2e] error: %s\n' "$*" >&2
  exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"; }

seconds_from_duration() {
  case "$1" in
    *s) printf '%s\n' "${1%s}" ;;
    *m) printf '%s\n' "$(( ${1%m} * 60 ))" ;;
    *h) printf '%s\n' "$(( ${1%h} * 3600 ))" ;;
    *) printf '30\n' ;;
  esac
}

wait_until() {
  local desc="$1" timeout_s="$2"
  shift 2
  local deadline=$((SECONDS + timeout_s))
  until "$@"; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 2
  done
  log "${desc}"
}

cleanup_cluster() {
  "${KUBECTL[@]}" delete clusterrolebinding "${CLUSTER_ROLE_NAME}" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete clusterrole "${CLUSTER_ROLE_NAME}" --ignore-not-found >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete namespace "${AGENTS_NS}" "${GATEWAY_NS}" --ignore-not-found --wait=true --timeout="${TIMEOUT}" >/dev/null 2>&1 || true
}

on_exit() {
  local status=$?
  [[ "${KEEP_RESOURCES}" == "1" ]] || cleanup_cluster
  rm -rf "${WORKDIR}"
  exit "${status}"
}
trap on_exit EXIT

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${ROOT}"

need kubectl
need kind
need sed
if [[ "${SKIP_BUILD}" != "1" ]]; then
  need go
  need docker
fi
[[ -f "${OVERLAY}/kustomization.yaml" ]] || fail "e2e overlay not found: ${OVERLAY}"
[[ -f "${OVERLAY}/gateway.hcl" ]] || fail "e2e gateway config not found: ${OVERLAY}/gateway.hcl"
[[ -f "${DOCKERFILE}" ]] || fail "Dockerfile not found: ${DOCKERFILE}"

# Keep the heartbeat wait in sync with the lease the gateway enforces.
LEASE_TTL="$(sed -n 's/.*lease_ttl[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${OVERLAY}/gateway.hcl" | head -1)"
LEASE_TTL="${LEASE_TTL:-30s}"

if ! kind get clusters | grep -Fxq "${CLUSTER_NAME}"; then
  fail "kind cluster ${CLUSTER_NAME} not found"
fi
if ! "${KUBECTL[@]}" get nodes >/dev/null; then
  fail "kubectl context ${KUBE_CONTEXT} is not reachable"
fi

log "cleaning previous e2e resources in ${GATEWAY_NS}/${AGENTS_NS}"
cleanup_cluster

NODE_ARCH="$("${KUBECTL[@]}" get node -o jsonpath='{.items[0].status.nodeInfo.architecture}')"
GOARCH="${GOARCH_OVERRIDE:-${NODE_ARCH}}"
case "${GOARCH}" in
  amd64|arm64) ;;
  *) fail "unsupported node architecture ${GOARCH}; set CLAWPATROL_E2E_GOARCH" ;;
esac

if [[ "${SKIP_BUILD}" != "1" ]]; then
  log "building Linux/${GOARCH} clawpatrol binary"
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" make build
  cp "${ROOT}/clawpatrol" "${WORKDIR}/clawpatrol"

  log "building image ${IMAGE}"
  DOCKER_BUILDKIT=0 docker build --platform "linux/${GOARCH}" -f "${DOCKERFILE}" -t "${IMAGE}" "${WORKDIR}"

  log "loading image ${IMAGE} into kind cluster ${CLUSTER_NAME}"
  kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
else
  log "skipping image build/load; expecting ${IMAGE} to exist in kind"
fi

log "applying e2e overlay into ${GATEWAY_NS}/${AGENTS_NS}"
"${KUBECTL[@]}" apply -k "${OVERLAY}"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout restart statefulset/clawpatrol-gateway

log "waiting for gateway rollout"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout status statefulset/clawpatrol-gateway --timeout="${TIMEOUT}"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" wait --for=condition=Ready pod -l app=clawpatrol-gateway --timeout="${TIMEOUT}"

# The agent's sidecar registers once; recreate it now that the gateway is
# ready so its first (and only) register attempt can't lose a startup race.
log "recreating agent pod against the ready gateway"
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --ignore-not-found --wait=true >/dev/null
"${KUBECTL[@]}" apply -k "${OVERLAY}"

"${KUBECTL[@]}" -n "${AGENTS_NS}" wait --for=condition=Ready "pod/${E2E_HTTP}" --timeout="${TIMEOUT}"

GATEWAY_POD="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get pod -l app=clawpatrol-gateway -o jsonpath='{.items[0].metadata.name}')"
HTTP_CLUSTER_IP="$("${KUBECTL[@]}" -n "${AGENTS_NS}" get svc "${E2E_HTTP}" -o jsonpath='{.spec.clusterIP}')"

agent_exec() { "${KUBECTL[@]}" -n "${AGENTS_NS}" exec "${E2E_POD}" -c agent -- "$@"; }
gateway_exec() { "${KUBECTL[@]}" -n "${GATEWAY_NS}" exec "${GATEWAY_POD}" -c gateway -- "$@"; }
sqlite_query() { gateway_exec sqlite3 -cmd '.timeout 5000' /opt/clawpatrol/clawpatrol.db "$1"; }

lease_count() { sqlite_query "SELECT count(*) FROM dynamic_peer_leases WHERE display_name = '${AGENTS_NS}/${E2E_POD}';" 2>/dev/null; }
lease_present() { [[ "$(lease_count || printf '0')" -ge 1 ]]; }
lease_absent() { [[ "$(lease_count || printf '1')" -eq 0 ]]; }

log "waiting for sidecar handoff files"
wait_until "sidecar wrote ready/env/ca files" 120 \
  agent_exec sh -lc 'test -f /clawpatrol/ready && test -s /clawpatrol/env && test -s /clawpatrol/ca.crt'

log "checking restricted agent container contract"
agent_exec sh -lc 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token'
agent_exec sh -lc 'test ! -e /var/run/secrets/tokens/clawpatrol-token'
agent_exec sh -lc 'test ! -e /dev/net/tun'
agent_exec sh -lc 'test "$(awk "/CapEff:/ {print \$2}" /proc/self/status)" = "0000000000000000"'
agent_exec sh -lc '! ip route add blackhole 198.51.100.0/24 2>/tmp/route.err'
agent_exec sh -lc '! sh -c "printf x >/clawpatrol/agent-write-test" 2>/tmp/write.err'
agent_exec sh -lc "! grep -R -i -E 'api_token|private_key|wireguard_private' /clawpatrol 2>/dev/null"
agent_exec sh -lc 'ip route show default | grep -q "dev clawpatrol0"'

log "checking tunnel route and a relayed TCP request"
agent_exec sh -lc "ip route get '${HTTP_CLUSTER_IP}' | grep -q 'dev clawpatrol0'"
agent_exec sh -lc "test \"\$(curl -sS --max-time 10 'http://${HTTP_CLUSTER_IP}:8081/')\" = 'ok'"

log "checking dynamic peer lease and WireGuard peer tables"
gateway_exec sh -lc 'command -v sqlite3 >/dev/null'
wait_until "dynamic peer lease is present" 60 lease_present
PEER_IP="$(sqlite_query "SELECT peer_ip FROM dynamic_peer_leases WHERE display_name = '${AGENTS_NS}/${E2E_POD}' LIMIT 1;")"
[[ -n "${PEER_IP}" ]] || fail "dynamic peer lease did not include peer_ip"
sqlite_query "SELECT count(*) FROM wg_peers WHERE ip = '${PEER_IP}';" | grep -qx '1'
log "registered peer ${PEER_IP}"

if [[ "${CHECK_HEARTBEAT}" == "1" ]]; then
  TTL_SECONDS="$(seconds_from_duration "${LEASE_TTL}")"
  SLEEP_SECONDS=$(( TTL_SECONDS / 2 + 7 ))
  (( SLEEP_SECONDS >= 8 )) || SLEEP_SECONDS=8
  BEFORE_HEARTBEAT="$(sqlite_query "SELECT last_heartbeat_ns FROM dynamic_peer_leases WHERE peer_ip = '${PEER_IP}';")"
  log "waiting ${SLEEP_SECONDS}s for heartbeat"
  sleep "${SLEEP_SECONDS}"
  AFTER_HEARTBEAT="$(sqlite_query "SELECT last_heartbeat_ns FROM dynamic_peer_leases WHERE peer_ip = '${PEER_IP}';")"
  [[ "${AFTER_HEARTBEAT}" -gt "${BEFORE_HEARTBEAT}" ]] || fail "heartbeat did not advance"
  log "heartbeat advanced"
fi

if [[ "${CHECK_EXPIRY}" == "1" ]]; then
  TTL_SECONDS="$(seconds_from_duration "${LEASE_TTL}")"
  log "force deleting sidecar pod to test TTL expiry cleanup"
  "${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --force --grace-period=0 --wait=true
  wait_until "dynamic peer lease expired and was swept" "$((TTL_SECONDS + 75))" lease_absent
else
  log "deleting e2e pod and checking graceful deregistration"
  "${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --wait=true --timeout=60s
  wait_until "dynamic peer lease removed" 45 lease_absent
fi

sqlite_query "SELECT count(*) FROM wg_peers WHERE ip = '${PEER_IP}';" | grep -qx '0'
log "WireGuard peer ${PEER_IP} was revoked"
log "e2e passed"
