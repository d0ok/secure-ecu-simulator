#!/usr/bin/env bash
# Live integration test. Requires: vcan0 up, `make` already run, can-utils.
set -u
IFACE="${1:-vcan0}"
export SECURE_ECU_KEY_HEX="${SECURE_ECU_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
cd "$(dirname "$0")/.." || exit 1

LOG="$(mktemp)"
RX=""
trap 'rm -f "$LOG"; [ -n "$RX" ] && kill "$RX" 2>/dev/null' EXIT

./build/can_receiver "$IFACE" >"$LOG" 2>&1 &
RX=$!
sleep 0.5
if ! kill -0 "$RX" 2>/dev/null; then
    echo "Receiver failed to start:"; cat "$LOG"; exit 1
fi

send()    { ./build/secoc_sender "$IFACE" "$@" >/dev/null; sleep 0.1; }
rawsend() { cansend "$IFACE" "$1"; sleep 0.1; }

send valid 10          # ping, accepted
send valid 10          # replay
send valid 5           # stale
send forged 11         # bad tag
send valid 11          # accepted: forged 11 did not consume the counter
send valid 5000        # jump too large
send valid 12 01       # lock
send valid 13 03       # status
rawsend 123#1122334455                                   # classic CAN
rawsend 123##000112233445566778899AABBCCDDEEFF           # 16-byte FD frame
rawsend "124##0$(printf '00%.0s' {1..24})"               # wrong CAN ID

sleep 0.3
kill -INT "$RX"; wait "$RX" 2>/dev/null; RX=""

cat "$LOG"; echo "-----"

expected=( "[ACCEPT]" "replayed counter" "stale counter" "HMAC validation failed"
           "[ACCEPT]" "counter jump too large" "[ACCEPT]" "[ACCEPT]"
           "classic CAN" "incorrect secured payload length" "unexpected CAN identifier" )
mapfile -t lines < <(grep -E '^\[(ACCEPT|REJECT)\]' "$LOG")

fail=0
if [ "${#lines[@]}" -ne "${#expected[@]}" ]; then
    echo "[FAIL] expected ${#expected[@]} accept/reject lines, got ${#lines[@]}"; fail=1
fi
for i in "${!expected[@]}"; do
    if [[ "${lines[$i]:-}" == *"${expected[$i]}"* ]]; then
        echo "[PASS] frame $((i + 1)): ${expected[$i]}"
    else
        echo "[FAIL] frame $((i + 1)): expected '${expected[$i]}', got '${lines[$i]:-<none>}'"; fail=1
    fi
done
grep -q '^\[ECU\] doors locked$' "$LOG"                  && echo "[PASS] lock executed"    || { echo "[FAIL] lock not executed"; fail=1; }
grep -q '^\[ECU\] state=LOCKED executed=3$' "$LOG"       && echo "[PASS] status reports LOCKED after 3 commands" || { echo "[FAIL] status line wrong"; fail=1; }

[ "$fail" -eq 0 ] && echo "ALL INTEGRATION CHECKS PASSED" || echo "INTEGRATION CHECKS FAILED"
exit "$fail"
