#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

usage() {
    printf '%s\n' \
        'Usage: bash eng/live-infisical/live.sh <local|remote> <scenario> [options]' \
        '  installed-narrative [--candidate DIR]' \
        '  native-conformance --candidate DIR --request FILE --settings-template FILE' \
        '  owned-sandbox | baseline (local only)' \
        'Use a bootstrapped local sandbox or an explicitly authorized remote organization.' \
        'Native: supply an owner-only template whose family coordinates match the selected fixture identities and projects.' \
        'A fixture naming prefix does not establish qualification.' \
        'The runner verifies readiness, reconciles fixtures, and stores sanitized evidence in artifacts/live/.'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then
    usage
    exit 0
fi
if (( $# < 2 )); then
    usage >&2
    exit 2
fi

target=$1
scenario=$2
shift 2
case "$target:$scenario" in
    local:owned-sandbox|local:baseline|local:installed-narrative|remote:installed-narrative|\
        local:native-conformance|remote:native-conformance) ;;
    *) usage >&2; exit 2 ;;
esac

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$root"
project=tools/SecretKit.LiveProvisioner/SecretKit.LiveProvisioner.csproj
flock -o /tmp/secretkit-provider-engineering-build.lock \
    env MSBUILDTERMINALLOGGER=off dotnet build "$project" --configuration Release
exec dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll \
    --mode "$target" run "$scenario" "$@"
