#!/usr/bin/env bash
# Live integration test. Requires: vcan0 up, `make` already run, can-utils.
set -u
IFACE="${1:-vcan0}"
export SECURE_ECU_KEY_HEX="${SECURE_ECU_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
cd "$(dirname "$0")/.." || exit 1

LOG="$(mktemp)"; LOG2="$(mktemp)"; LOG3="$(mktemp)"
CTR="$(mktemp -u)"                       # throwaway counter file (does not exist yet)
export SECURE_ECU_COUNTER_FILE="$CTR"
RX=""
cleanup() {
    [ -n "$RX" ] && kill "$RX" 2>/dev/null
    rm -f "$LOG" "$LOG2" "$LOG3" "$CTR" "$CTR.tmp"
}
trap cleanup EXIT

start_rx() {
    ./build/can_receiver "$IFACE" >"$1" 2>&1 &
    RX=$!
    sleep 0.5
    if ! kill -0 "$RX" 2>/dev/null; then
        echo "Receiver failed to start:"; cat "$1"; exit 1
    fi
}
stop_rx() { kill -INT "$RX"; wait "$RX" 2>/dev/null; RX=""; }

send()    { ./build/secoc_sender "$IFACE" "$@" >/dev/null; sleep 0.1; }
rawsend() { cansend "$IFACE" "$1"; sleep 0.1; }

fail=0
pass() { echo "[PASS] $1"; }
bad()  { echo "[FAIL] $1"; fail=1; }

echo "=== Phase 1: valid, forged, replayed, stale and malformed frames ==="
start_rx "$LOG"
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
stop_rx
cat "$LOG"; echo "-----"

expected=( "[ACCEPT]" "replayed counter" "stale counter" "HMAC validation failed"
           "[ACCEPT]" "counter jump too large" "[ACCEPT]" "[ACCEPT]"
           "classic CAN" "incorrect secured payload length" "unexpected CAN identifier" )
mapfile -t lines < <(grep -E '^\[(ACCEPT|REJECT)\]' "$LOG")

if [ "${#lines[@]}" -ne "${#expected[@]}" ]; then
    bad "expected ${#expected[@]} accept/reject lines, got ${#lines[@]}"
fi
for i in "${!expected[@]}"; do
    if [[ "${lines[$i]:-}" == *"${expected[$i]}"* ]]; then
        pass "frame $((i + 1)): ${expected[$i]}"
    else
        bad "frame $((i + 1)): expected '${expected[$i]}', got '${lines[$i]:-<none>}'"
    fi
done
grep -q '^\[ECU\] doors locked$' "$LOG"            && pass "lock executed" || bad "lock not executed"
grep -q '^\[ECU\] state=LOCKED executed=3$' "$LOG" && pass "status reports LOCKED after 3 commands" || bad "status line wrong"
grep -q '^No counter file at ' "$LOG"              && pass "first start had no counter file" || bad "first-start message missing"
[ "$(cat "$CTR" 2>/dev/null)" = "v1 13 fffffff2" ] && pass "counter file holds 13" || bad "counter file content wrong: $(cat "$CTR" 2>/dev/null)"

echo "=== Phase 2: restart must not reopen the replay window ==="
start_rx "$LOG2"
send valid 13 03       # last accepted counter before the restart: must be a replay
send valid 14 03       # next counter: accepted
sleep 0.3
stop_rx
cat "$LOG2"; echo "-----"

grep -q '^Restored last accepted counter 13 ' "$LOG2" && pass "counter restored after restart" || bad "counter not restored"
mapfile -t lines2 < <(grep -E '^\[(ACCEPT|REJECT)\]' "$LOG2")
[[ "${lines2[0]:-}" == *"replayed counter"* ]] && pass "pre-restart counter 13 rejected as replay" || bad "counter 13 not rejected after restart: ${lines2[0]:-<none>}"
[[ "${lines2[1]:-}" == *"[ACCEPT]"* ]]         && pass "counter 14 accepted after restart"          || bad "counter 14 not accepted: ${lines2[1]:-<none>}"

echo "=== Phase 3: corrupt counter file must stop the receiver ==="
echo "garbage" > "$CTR"
./build/can_receiver "$IFACE" >"$LOG3" 2>&1; rc=$?
cat "$LOG3"; echo "-----"
[ "$rc" -ne 0 ]                        && pass "receiver exited with an error"    || bad "receiver started despite a corrupt file"
grep -q 'Refusing to start' "$LOG3"    && pass "refusal message printed"          || bad "refusal message missing"

[ "$fail" -eq 0 ] && echo "ALL INTEGRATION CHECKS PASSED" || echo "INTEGRATION CHECKS FAILED"
exit "$fail"
