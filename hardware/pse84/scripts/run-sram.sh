#!/usr/bin/env bash
set -euo pipefail

elf=${1:?usage: run-sram.sh ELF}
probe=${PSE84_PROBE:-04b4:f155-0:1F110F98012D2400}
chip=${PSE84_CHIP:-PSE846GPS2DBZC4A}
server_log=$(mktemp)
server_pid=

cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -f "$server_log"
}
trap cleanup EXIT INT TERM

probe-rs gdb --reset-halt --chip "$chip" --probe "$probe" "$elf" \
    >"$server_log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
    if rg -q 'Firing up GDB stub' "$server_log"; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        sed -n '1,160p' "$server_log" >&2
        exit 1
    fi
    sleep 0.1
done
if ! rg -q 'Firing up GDB stub' "$server_log"; then
    sed -n '1,160p' "$server_log" >&2
    exit 1
fi

gdb -q -batch "$elf" \
    -ex 'set architecture arm' \
    -ex 'target remote :1337' \
    -ex 'load' \
    -ex 'set $msp_s = *(unsigned int*)0x34008000' \
    -ex 'set $msp = *(unsigned int*)0x34008000' \
    -ex 'set $pc = *(unsigned int*)0x34008004' \
    -ex 'detach'

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

exec probe-rs attach --chip "$chip" --probe "$probe" \
    --scan-region 0x34028000..0x34058000 "$elf"
