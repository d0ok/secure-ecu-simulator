# Threat Model

This document states what the Secure ECU Simulator protects, against whom, and where its protection ends. It is an educational design, so the limits matter as much as the defenses. See [ARCHITECTURE.md](ARCHITECTURE.md) for how the defenses are built and [TEST-REPORT.md](TEST-REPORT.md) for how they are tested.

## What is being protected

- **Command integrity and authenticity:** the ECU should execute a command only if it came from a holder of the shared key and was not altered in transit.
- **Command freshness:** an old, valid command should not be accepted again, including after the ECU restarts.
- **Availability of the receiver:** malformed or hostile frames should not crash the receiver or change its state.

Confidentiality is not a goal. Frames are authenticated, not encrypted, so anyone on the bus can read commands.

## Assumptions

- The sender and the ECU share one 256-bit key, provisioned out of band. The simulator reads it from the `SECURE_ECU_KEY_HEX` environment variable, and the repository uses a published test key only.
- The attacker can read, inject, drop, and replay frames on the CAN bus.
- The attacker cannot read the key, and cannot modify the receiver process or its memory.
- The receiver's counter file is stored where the attacker cannot write to it. The simulator enforces this only through file permissions (mode `0600`).

## Attackers considered

| Attacker | Capabilities |
|---|---|
| Bus injector | Sends arbitrary frames on the bus, with or without knowledge of earlier traffic |
| Eavesdropper and replayer | Records valid frames and sends them again later, in the same session or after a restart |
| Malformed-frame sender | Sends frames with wrong sizes, flags, identifiers, or payloads, to crash or confuse the receiver |

## Threats and defenses

| Threat | Defense | Evidence |
|---|---|---|
| Forged command with no key | A 128-bit truncated HMAC-SHA-256 tag over the CAN ID, Data ID, command, parameters, and counter. Guessing a tag is a 2^-128 event per attempt. | Unit, integration, and fuzz tests |
| Modified command, parameters, or counter in a valid frame | Every one of those fields is covered by the tag | `test_secoc`, fuzz mutations |
| Valid frame re-sent under another CAN ID | The CAN ID is part of the authenticated data | `test_secoc`, `test_sec_layer` |
| Replay of a recorded frame in the same session | The counter must be strictly greater than the last accepted one | Integration frame 2 |
| Replay of an older frame | Lower counters are rejected as stale | Integration frame 3 |
| Replay after the ECU restarts | The last accepted counter is saved to a file before the command executes and restored at startup | Integration phase 2 |
| Forged frames used to push the counter forward and lock out the real sender | Freshness is evaluated only after the tag is verified, so forged frames never change the counter | `test_sec_layer`, integration frames 4 and 5, fuzz |
| One valid frame with a huge counter used to lock out the real sender | A forward jump larger than `FRESHNESS_MAX_JUMP` is rejected | Integration frame 6 |
| Tag-guessing by timing | The tag comparison is constant-time (`CRYPTO_memcmp`) | Design requirement; check with `grep CRYPTO_memcmp src/secoc.c` |
| Crashes or memory errors from malformed frames | Strict frame validation before any parsing, and exact length checks | `test_sec_layer`, fuzz under sanitizers |
| Command executed but replayable after a crash | The counter is saved before the command runs. A crash can lose a command but cannot make it replayable. | Design, `can_receiver.c` |
| Counter file corrupted or truncated | A check value in the file detects damage, and the receiver refuses to start rather than reset | `test_counter_store`, integration phase 3 |

## What this design does not protect against

**Key compromise.** The key is symmetric and shared. Anyone who obtains it can forge any command, and the receiver cannot tell the real sender from an impersonator. The key sits in an environment variable, which is visible in `/proc/<pid>/environ` to the same user and may appear in shell history. There is no key rotation, per-ECU key diversification, or secure key storage.

**Tampering with the counter file.** The file's check value detects accidents, not attacks. Anyone who can write to the file can rewrite it with a valid record, including a lower counter, and re-open the replay window. Deleting the file has the same effect, since a missing file means a first start at 0. A real ECU would keep the counter in protected non-volatile memory.

**Delay and suppression.** A counter says a frame is newer than the last one, not that it is recent. An attacker who jams a valid frame so the receiver never sees it can deliver the same frame later, and it will be accepted if no newer counter has been used in between. There is no timestamp or maximum frame age.

**Sender and receiver losing synchronization.** If the sender's counter falls behind the receiver's, or jumps ahead by more than the jump limit, the receiver rejects its frames until someone intervenes. There is no resynchronization protocol. The jump limit protects against lockout by an attacker, but it makes lockout by an honest mistake possible. When the counter reaches `UINT32_MAX`, all frames are rejected, and there is no rollover or re-keying.

**Denial of service on the bus.** An attacker can flood the bus or send frames faster than the receiver can verify them. Rejected frames cost a frame check and, for well-formed ones, one HMAC computation. There is no rate limiting.

**A compromised host or ECU.** The receiver trusts its own process, memory, and files. Any process on the host that can open `vcan0` can send or read frames. A virtual interface offers none of the physical-layer properties of a real bus.

**Confidentiality.** Commands, counters, and tags are sent in clear text.

**Per-message-ID separation and multiple senders.** Only one identifier (`0x123`) and one sender-to-receiver direction are modelled. Responses are not authenticated, since the ECU does not send any.

## Design choices worth defending

- **128-bit truncated tag.** Truncating HMAC-SHA-256 to 16 bytes keeps the secured frame within a 24-byte CAN FD payload while leaving a very large guessing space.
- **Verify before state.** Authenticating first means unauthenticated traffic cannot influence the counter, which is the main reason a counter-based scheme is not a denial-of-service lever.
- **Fail closed.** A corrupt counter file stops the receiver, a failed save stops the command, and unknown frames are rejected. Each choice prefers refusing work over accepting an uncertain frame.
- **Save before execute.** It trades possible loss of one command after a crash for a guarantee that no command can be replayed after a crash.

## Comparison with AUTOSAR SecOC

The simulator borrows the core ideas of SecOC: a Data ID, secured data, a freshness value, and a truncated authentication tag. It is simplified. It does not implement the SecOC PDU format, freshness value construction from a trip counter and reset counter, freshness synchronization with a master, or key management through a key manager. It makes no claim of compliance with any AUTOSAR release.

## Possible future work

- Add a resynchronization step or a trip and reset counter scheme to recover from counter mismatches.
- Add per-session keys or key rotation.
- Store the counter in simulated protected memory, with write wear limits.
- Bound frame age with a timestamp or a challenge-response exchange for critical commands.
- Add rate limiting on rejected frames.
