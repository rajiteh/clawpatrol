#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLUSTER_NAME="${CLAWPATROL_E2E_CLUSTER:-kind}"
KUBE_CONTEXT="${CLAWPATROL_E2E_CONTEXT:-kind-${CLUSTER_NAME}}"
IMAGE="${CLAWPATROL_E2E_IMAGE:-clawpatrol-kind-e2e:dev}"
DOCKERFILE="${CLAWPATROL_E2E_DOCKERFILE:-Dockerfile}"
MANIFEST="${CLAWPATROL_E2E_MANIFEST:-examples/kubernetes-wireguard.yaml}"
TIMEOUT="${CLAWPATROL_E2E_TIMEOUT:-180s}"
LEASE_TTL="${CLAWPATROL_E2E_LEASE_TTL:-30s}"
SKIP_BUILD="${CLAWPATROL_E2E_SKIP_BUILD:-0}"
KEEP_RESOURCES="${CLAWPATROL_E2E_KEEP_RESOURCES:-0}"
CHECK_HEARTBEAT="${CLAWPATROL_E2E_CHECK_HEARTBEAT:-1}"
CHECK_EXPIRY="${CLAWPATROL_E2E_CHECK_EXPIRY:-0}"
GOARCH_OVERRIDE="${CLAWPATROL_E2E_GOARCH:-}"
NAMESPACE_SUFFIX="${CLAWPATROL_E2E_NAMESPACE_SUFFIX:--e2e}"
GATEWAY_NS="${CLAWPATROL_E2E_GATEWAY_NAMESPACE:-clawpatrol${NAMESPACE_SUFFIX}}"
AGENTS_NS="${CLAWPATROL_E2E_AGENTS_NAMESPACE:-agents${NAMESPACE_SUFFIX}}"
if [[ -n "${CLAWPATROL_E2E_CLUSTER_RESOURCE_SUFFIX+x}" ]]; then
  CLUSTER_RESOURCE_SUFFIX="${CLAWPATROL_E2E_CLUSTER_RESOURCE_SUFFIX}"
else
  CLUSTER_RESOURCE_SUFFIX="${NAMESPACE_SUFFIX#-}"
  [[ -n "${CLUSTER_RESOURCE_SUFFIX}" ]] || CLUSTER_RESOURCE_SUFFIX="e2e"
fi
if [[ -n "${CLUSTER_RESOURCE_SUFFIX}" ]]; then
  CLUSTER_ROLE_NAME="clawpatrol-tokenreview-${CLUSTER_RESOURCE_SUFFIX}"
else
  CLUSTER_ROLE_NAME="clawpatrol-tokenreview"
fi

E2E_POD="clawpatrol-agent-e2e"
E2E_HTTP="clawpatrol-e2e-http"
TMP_ROOT="${TMPDIR:-/tmp}"
WORKDIR="$(mktemp -d "${TMP_ROOT%/}/clawpatrol-k8s-e2e.XXXXXX")"

KUBECTL=(kubectl --context "${KUBE_CONTEXT}")

usage() {
  cat <<'USAGE'
Run the Kubernetes WireGuard dynamic-peer e2e flow against a local kind cluster.

Default invocation:
  ./examples/kubernetes-wireguard-e2e.sh

Environment knobs:
  CLAWPATROL_E2E_CLUSTER        kind cluster name, default: kind
  CLAWPATROL_E2E_CONTEXT        kubectl context, default: kind-${cluster}
  CLAWPATROL_E2E_IMAGE          local image tag to build/load, default: clawpatrol-kind-e2e:dev
  CLAWPATROL_E2E_DOCKERFILE     image Dockerfile, default: Dockerfile
  CLAWPATROL_E2E_MANIFEST       base manifest, default: examples/kubernetes-wireguard.yaml
  CLAWPATROL_E2E_TIMEOUT        kubectl wait timeout, default: 180s
  CLAWPATROL_E2E_LEASE_TTL      rendered gateway lease TTL, default: 30s
  CLAWPATROL_E2E_NAMESPACE_SUFFIX namespace suffix, default: -e2e
  CLAWPATROL_E2E_GATEWAY_NAMESPACE override gateway namespace, default: clawpatrol-e2e
  CLAWPATROL_E2E_AGENTS_NAMESPACE override agent namespace, default: agents-e2e
  CLAWPATROL_E2E_CLUSTER_RESOURCE_SUFFIX cluster role/binding suffix, default: e2e
  CLAWPATROL_E2E_SKIP_BUILD     set 1 to skip go/docker build and kind load
  CLAWPATROL_E2E_KEEP_RESOURCES set 1 to skip final namespace cleanup for debugging
  CLAWPATROL_E2E_CHECK_HEARTBEAT set 0 to skip heartbeat advancement check
  CLAWPATROL_E2E_CHECK_EXPIRY   set 1 to test TTL cleanup after deleting the sidecar forcefully
  CLAWPATROL_E2E_GOARCH         override node architecture for the Linux build
USAGE
}

log() {
  printf '[e2e] %s\n' "$*"
}

fail() {
  printf '[e2e] error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

seconds_from_duration() {
  case "$1" in
    *s) printf '%s\n' "${1%s}" ;;
    *m) printf '%s\n' "$(( ${1%m} * 60 ))" ;;
    *h) printf '%s\n' "$(( ${1%h} * 3600 ))" ;;
    *) printf '30\n' ;;
  esac
}

sed_replacement_escape() {
  printf '%s' "$1" | sed -e 's/[&|]/\\&/g'
}

wait_until() {
  local desc="$1"
  local timeout_s="$2"
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

  if [[ "${KEEP_RESOURCES}" != "1" ]]; then
    cleanup_cluster
  fi
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

[[ -f "${MANIFEST}" ]] || fail "manifest not found: ${MANIFEST}"
if [[ "${DOCKERFILE}" = /* ]]; then
  DOCKERFILE_PATH="${DOCKERFILE}"
else
  DOCKERFILE_PATH="${ROOT}/${DOCKERFILE}"
fi
[[ -f "${DOCKERFILE_PATH}" ]] || fail "Dockerfile not found: ${DOCKERFILE}"

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
  DOCKER_BUILDKIT=0 docker build --platform "linux/${GOARCH}" -f "${DOCKERFILE_PATH}" -t "${IMAGE}" "${WORKDIR}"

  log "loading image ${IMAGE} into kind cluster ${CLUSTER_NAME}"
  kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
else
  log "skipping image build/load; expecting ${IMAGE} to exist in kind"
fi

IMAGE_ESCAPED="$(sed_replacement_escape "${IMAGE}")"
LEASE_TTL_ESCAPED="$(sed_replacement_escape "${LEASE_TTL}")"
GATEWAY_NS_ESCAPED="$(sed_replacement_escape "${GATEWAY_NS}")"
AGENTS_NS_ESCAPED="$(sed_replacement_escape "${AGENTS_NS}")"
CLUSTER_ROLE_NAME_ESCAPED="$(sed_replacement_escape "${CLUSTER_ROLE_NAME}")"
sed \
  -e "s|image: ghcr.io/denoland/clawpatrol:latest|image: ${IMAGE_ESCAPED}|g" \
  -e "s|image: debian:stable-slim|image: ${IMAGE_ESCAPED}|g" \
  -e "s|lease_ttl = \"2m\"|lease_ttl = \"${LEASE_TTL_ESCAPED}\"|g" \
  -e "s|name: clawpatrol-tokenreview|name: ${CLUSTER_ROLE_NAME_ESCAPED}|g" \
  -e "s|name: clawpatrol$|name: ${GATEWAY_NS_ESCAPED}|g" \
  -e "s|name: agents$|name: ${AGENTS_NS_ESCAPED}|g" \
  -e "s|namespace: clawpatrol$|namespace: ${GATEWAY_NS_ESCAPED}|g" \
  -e "s|namespace: agents$|namespace: ${AGENTS_NS_ESCAPED}|g" \
  -e "s|namespace       = \"agents\"|namespace       = \"${AGENTS_NS_ESCAPED}\"|g" \
  -e "s|clawpatrol-wg.clawpatrol.svc|clawpatrol-wg.${GATEWAY_NS_ESCAPED}.svc|g" \
  -e "s|clawpatrol-api.clawpatrol.svc|clawpatrol-api.${GATEWAY_NS_ESCAPED}.svc|g" \
  "${MANIFEST}" >"${WORKDIR}/base.yaml"

log "applying base manifest into ${GATEWAY_NS}/${AGENTS_NS}"
"${KUBECTL[@]}" apply -f "${WORKDIR}/base.yaml"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout restart statefulset/clawpatrol-gateway

log "removing sample agent pod so the e2e pod is the only dynamic peer"
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod clawpatrol-agent-example --ignore-not-found --wait=false >/dev/null

log "waiting for gateway rollout"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" rollout status statefulset/clawpatrol-gateway --timeout="${TIMEOUT}"
"${KUBECTL[@]}" -n "${GATEWAY_NS}" wait --for=condition=Ready pod -l app=clawpatrol-gateway --timeout="${TIMEOUT}"

GATEWAY_POD="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get pod -l app=clawpatrol-gateway -o jsonpath='{.items[0].metadata.name}')"
API_CLUSTER_IP="$("${KUBECTL[@]}" -n "${GATEWAY_NS}" get svc clawpatrol-api -o jsonpath='{.spec.clusterIP}')"
GATEWAY_URL="http://${API_CLUSTER_IP}:8080"

cat >"${WORKDIR}/http-echo.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${E2E_HTTP}
  namespace: ${AGENTS_NS}
  labels:
    app: ${E2E_HTTP}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: http
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-lc"]
      args:
        - |
          set -eu
          while true; do
            printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n' | nc -l -p 8081 -q 1
          done
      ports:
        - name: http
          containerPort: 8081
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
---
apiVersion: v1
kind: Service
metadata:
  name: ${E2E_HTTP}
  namespace: ${AGENTS_NS}
spec:
  selector:
    app: ${E2E_HTTP}
  ports:
    - name: http
      port: 8081
      targetPort: http
EOF

log "creating e2e HTTP relay target"
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_HTTP}" --ignore-not-found --wait=true >/dev/null
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete service "${E2E_HTTP}" --ignore-not-found >/dev/null
"${KUBECTL[@]}" apply -f "${WORKDIR}/http-echo.yaml"
"${KUBECTL[@]}" -n "${AGENTS_NS}" wait --for=condition=Ready "pod/${E2E_HTTP}" --timeout="${TIMEOUT}"
HTTP_CLUSTER_IP="$("${KUBECTL[@]}" -n "${AGENTS_NS}" get svc "${E2E_HTTP}" -o jsonpath='{.spec.clusterIP}')"

cat >"${WORKDIR}/agent-e2e.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${E2E_POD}
  namespace: ${AGENTS_NS}
  labels:
    clawpatrol.dev/profile: default
spec:
  serviceAccountName: agent-runner
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 20
  volumes:
    - name: clawpatrol
      emptyDir: {}
    - name: clawpatrol-token
      projected:
        sources:
          - serviceAccountToken:
              path: clawpatrol-token
              audience: clawpatrol
              expirationSeconds: 600
    - name: dev-net-tun
      hostPath:
        path: /dev/net/tun
        type: CharDevice
  containers:
    - name: wireguard-sidecar
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      args:
        - run
        - --tun
        - --gateway-url=${GATEWAY_URL}
        - --dynamic-peer-authorizer=kubernetes_token_review/agents
        - --kubernetes-token-path=/var/run/secrets/tokens/clawpatrol-token
        - --env-out=/clawpatrol/env
        - --ca-out=/clawpatrol/ca.crt
        - --ready-file=/clawpatrol/ready
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          add: ["NET_ADMIN"]
      env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: POD_UID
          valueFrom:
            fieldRef:
              fieldPath: metadata.uid
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumeMounts:
        - name: clawpatrol
          mountPath: /clawpatrol
        - name: clawpatrol-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
        - name: dev-net-tun
          mountPath: /dev/net/tun
    - name: agent
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-lc"]
      args:
        - |
          set -eu
          while [ ! -f /clawpatrol/ready ]; do sleep 0.2; done
          . /clawpatrol/env
          env | sort | grep -E '^(AWS_CA_BUNDLE|CLAWPATROL|CURL_CA_BUNDLE|DENO_CERT|GIT_SSL_CAINFO|NODE_EXTRA_CA_CERTS|PIP_CERT|REQUESTS_CA_BUNDLE|SSL_CERT_FILE)=' || true
          sleep 3600
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - name: clawpatrol
          mountPath: /clawpatrol
          readOnly: true
EOF

log "creating e2e agent pod"
"${KUBECTL[@]}" -n "${AGENTS_NS}" delete pod "${E2E_POD}" --ignore-not-found --wait=true >/dev/null
"${KUBECTL[@]}" apply -f "${WORKDIR}/agent-e2e.yaml"

agent_exec() {
  "${KUBECTL[@]}" -n "${AGENTS_NS}" exec "${E2E_POD}" -c agent -- "$@"
}

gateway_exec() {
  "${KUBECTL[@]}" -n "${GATEWAY_NS}" exec "${GATEWAY_POD}" -c gateway -- "$@"
}

sqlite_query() {
  gateway_exec sqlite3 -cmd '.timeout 5000' /opt/clawpatrol/clawpatrol.db "$1"
}

lease_count() {
  sqlite_query "SELECT count(*) FROM dynamic_peer_leases WHERE display_name = '${AGENTS_NS}/${E2E_POD}';" 2>/dev/null
}

lease_present() {
  [[ "$(lease_count || printf '0')" -ge 1 ]]
}

lease_absent() {
  [[ "$(lease_count || printf '1')" -eq 0 ]]
}

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
  if (( SLEEP_SECONDS < 8 )); then
    SLEEP_SECONDS=8
  fi
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
