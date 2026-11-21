#!/usr/bin/env bash
set +x
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: sandbox.sh up [port=18080] | down OWNER | status OWNER | logs OWNER' \
        'OWNER is the secretkit-sdk-<8hex> identifier printed by up.' \
        'logs reports per-container line counts only; raw logs may contain secrets.'
}

fail() {
    printf 'sandbox: %s\n' "$1" >&2
    exit 1
}

template="$(dirname -- "${BASH_SOURCE[0]}")/pod.yaml"
port_pattern='[1-9][0-9]{0,4}'

podman() {
    command podman --remote=false "$@"
}

valid_port() {
    [[ $1 =~ ^${port_pattern}$ ]] && (( $1 <= 65535 && $1 != 80 ))
}

owned_pod() {
    local evidence
    evidence=$(podman pod inspect --format \
        '{{.ID}} {{.Name}} {{index .Labels "secretkit-sdk-owned"}} {{index .Labels "secretkit-sdk-lifecycle"}}' \
        "$owner" 2>/dev/null) || fail 'Could not inspect the selected pod.'
    [[ $evidence =~ ^([0-9a-f]{64})\ ${owner}\ true\ live-infisical-v1$ ]] ||
        fail 'Refusing a pod without the exact sandbox ownership labels and name.'
    pod_id=${BASH_REMATCH[1]}
}

owned_container() {
    local evidence
    evidence=$(podman container inspect --format '{{.ID}} {{.Pod}} {{.Name}}' "$owner-$1" 2>/dev/null) ||
        fail "Could not inspect the $1 container."
    [[ $evidence =~ ^([0-9a-f]{64})\ ${pod_id}\ ${owner}-$1$ ]] ||
        fail "The $1 container does not belong to the selected pod."
    printf '%s\n' "${BASH_REMATCH[1]}"
}

verified_port() {
    local actual expected ingress
    expected=$(awk -F@ '/^[[:space:]]*image: docker\.io\/infisical\/infisical@sha256:/ { print $2 }' "$template")
    actual=$(podman container inspect --format '{{.ImageDigest}}' "$1" 2>/dev/null) ||
        fail 'Could not inspect the app image.'
    [[ $expected =~ ^sha256:[0-9a-f]{64}$ && $actual == "$expected" ]] ||
        fail 'App image digest does not match pod.yaml.'
    ingress=$(podman port "$1" 2>/dev/null) || fail 'Could not inspect app ingress.'
    [[ $ingress =~ ^8080/tcp\ -\>\ 127\.0\.0\.1:(${port_pattern})$ ]] ||
        fail 'Expected exactly one IPv4 loopback mapping for 8080/tcp.'
    valid_port "${BASH_REMATCH[1]}" || fail 'Unexpected host port.'
    port=${ingress##*:}
}

app_ready() {
    local code
    code=$(curl -q --noproxy '*' --max-time 2 --silent --output /dev/null \
        --write-out '%{http_code}' "http://127.0.0.1:$port/api/status") && [[ $code == 200 ]]
}

sidecars_ready() {
    podman exec "$postgres_id" pg_isready -q -t 1 -h 127.0.0.1 -U infisical -d infisical &&
        [[ $(podman exec "$redis_id" redis-cli --raw -h 127.0.0.1 ping) == PONG ]]
}

wait_ready() {
    local deadline=$((SECONDS + $1))
    shift
    # Probe actual service readiness, with a finite deadline.
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < deadline )) || return 1
        sleep 1
    done
}

render_pod() {
    local line
    while IFS= read -r line; do
        line=${line//__OWNER__/$owner}
        line=${line//__PORT__/$port}
        line=${line//__ENCRYPTION_KEY__/$encryption_key}
        line=${line//__AUTH_SECRET__/$auth_secret}
        printf '%s\n' "${line//__DB_PASSWORD__/$db_password}"
    done < "$template"
}

up() {
    local requested_port=$1 encryption_key auth_secret db_password app_id postgres_id redis_id
    port=$requested_port
    valid_port "$port" || fail 'Use a decimal port from 1 to 65535, other than 80.'
    [[ $(uname -m) == x86_64 ]] || fail 'The approved app manifest is Linux x86-64 only.'
    owner="secretkit-sdk-$(openssl rand -hex 4)" || fail 'Could not generate an owner.'
    [[ $owner =~ ^secretkit-sdk-[0-9a-f]{8}$ ]] || fail 'Invalid generated owner.'
    encryption_key=$(openssl rand -hex 16) || fail 'Could not generate encryption key.'
    auth_secret=$(openssl rand -base64 32) || fail 'Could not generate auth secret.'
    db_password=$(openssl rand -hex 32) || fail 'Could not generate database password.'

    printf 'Creating %s; if startup fails, use down %s to remove it.\n' "$owner" "$owner" >&2
    # Stream secrets without a checkout file, environment export, or command argument.
    render_pod | podman kube play --no-pod-prefix --start=false - >/dev/null 2>&1 ||
        fail 'Pod creation failed.'
    unset encryption_key auth_secret db_password
    owned_pod
    postgres_id=$(owned_container postgres)
    redis_id=$(owned_container redis)
    app_id=$(owned_container app)
    podman start "$postgres_id" "$redis_id" >/dev/null 2>&1 || fail 'Sidecar startup failed.'
    wait_ready 60 sidecars_ready || fail 'Sidecars did not become ready.'
    podman start "$app_id" >/dev/null 2>&1 || fail 'App startup failed.'
    verified_port "$app_id"
    [[ $port == "$requested_port" ]] || fail 'Host port does not match the requested port.'
    wait_ready 120 app_ready || fail 'Infisical did not become ready.'
    printf 'owner=%s\norigin=http://127.0.0.1:%s\nhealth=ready\n' "$owner" "$port"
}

case ${1:-} in
    -h|--help) usage; exit 0 ;;
    up) (( $# <= 2 )) || fail 'Usage: sandbox.sh up [port]'; up "${2-18080}"; exit ;;
    down|status|logs) ;;
    *) usage >&2; exit 1 ;;
esac

[[ $# == 2 && $2 =~ ^secretkit-sdk-[0-9a-f]{8}$ ]] || fail 'An exact sandbox owner is required.'
owner=$2
owned_pod
case $1 in
    down)
        # Act on the inspected ID, never a name that could have been reused.
        podman pod rm --force "$pod_id" >/dev/null 2>&1 || fail 'Could not remove the owned pod.'
        printf 'removed=%s\n' "$owner"
        ;;
    status)
        app_id=$(owned_container app)
        verified_port "$app_id"
        printf 'owner=%s\norigin=http://127.0.0.1:%s\n' "$owner" "$port"
        app_ready || fail 'Infisical is not ready.'
        printf 'health=ready\n'
        ;;
    logs)
        for component in app postgres redis; do
            id=$(owned_container "$component")
            count=$(podman logs --tail 100 "$id" 2>&1 | wc -l) || fail "Could not read $component logs."
            printf '%s: %s recent log lines (content withheld)\n' "$component" "$count"
        done
        ;;
esac
