# Architecture

This document describes how the Secure ECU Simulator is structured, how a frame moves through it, and which module is responsible for each decision. For the security reasoning, see [THREAT-MODEL.md](THREAT-MODEL.md). For test evidence, see [TEST-REPORT.md](TEST-REPORT.md).

The design is AUTOSAR-inspired for learning purposes. It is not a complete AUTOSAR SecOC implementation and does not claim compliance with an AUTOSAR release.

## Layers

```mermaid
flowchart TD
    BUS["CAN FD bus (vcan0)"]
    subgraph COMM["Communication layer: can_if"]
        RX["Read frame, decode identifier, length and frame type"]
    end
    subgraph SEC["Security layer: sec_layer"]
        FC["1. Frame checks"]
        MAC["2. HMAC verification (secoc)"]
        FR["3. Freshness check (freshness)"]
    end
    STORE[("Counter file (counter_store)")]
    subgraph APP["Application layer: ecu_app"]
        CMD["Command handler: lock, unlock, status, ping"]
    end

    BUS --> RX --> FC --> MAC --> FR
    FR -->|"accepted"| STORE
    STORE -->|"saved"| CMD
    STORE -. "restored at startup" .-> FR
```

Each layer only knows about the layer next to it:

| Layer | Module | Responsibility | Knows nothing about |
|---|---|---|---|
| Communication | `can_if` | Opens the CAN socket, reads one frame, and reports its identifier, length, payload, and frame type | Keys, counters, commands |
| Security | `sec_layer` | Runs the validation pipeline and returns one result per frame | Sockets, ECU commands |
| Security | `secoc` | Builds and verifies the truncated HMAC-SHA-256 tag | Counters, sockets |
| Security | `freshness` | Decides whether a counter is new enough, and tracks the last accepted value | Keys, frames |
| Persistence | `counter_store` | Saves and restores the last accepted counter | What the counter means |
| Application | `ecu_app` | Executes a command on the simulated ECU state | Where the command came from |
| Program | `can_receiver` | Wires the layers together in a receive loop | |

Because `sec_layer` has no socket code, it can be tested with hand-built frames, and the fuzz harness can drive it millions of times without a CAN interface.

## Check order for every frame

The order is deliberate. Cheap structural checks come first, authentication comes before any state is touched, and the command runs last.

```mermaid
flowchart TD
    A["Frame read from socket"] --> B{"Valid SocketCAN frame?"}
    B -- "no" --> R0["REJECT: malformed SocketCAN frame"]
    B -- "yes" --> C{"CAN FD frame?"}
    C -- "no" --> R1["REJECT: classic CAN not accepted"]
    C -- "yes" --> D{"Payload length is 24?"}
    D -- "no" --> R2["REJECT: incorrect payload length"]
    D -- "yes" --> E{"Standard data frame?"}
    E -- "no" --> R3["REJECT: extended, remote or error frame"]
    E -- "yes" --> F{"CAN ID is 0x123?"}
    F -- "no" --> R4["REJECT: unexpected CAN identifier"]
    F -- "yes" --> G{"HMAC tag valid?"}
    G -- "no" --> R5["REJECT: HMAC validation failed"]
    G -- "yes" --> H{"Counter fresh?"}
    H -- "no" --> R6["REJECT: replayed, stale, jump too large, or exhausted"]
    H -- "yes" --> I{"Counter saved to disk?"}
    I -- "no" --> R7["REJECT: cannot persist counter, command not executed"]
    I -- "yes" --> J["ACCEPT and execute the command"]
```

Three properties follow from this order:

1. **A forged frame never moves the counter.** Freshness is evaluated only after the HMAC passes.
2. **A rejected frame never changes state.** Every rejection path leaves the stored counter, the counter file, and the ECU state untouched.
3. **A command never runs before its counter is durable.** The counter is saved before the command executes. If the save fails, the command is not executed. A crash after the save can therefore lose a command, but it can never let the same frame be replayed after a restart.

## Secured message format

A 24-byte CAN FD payload on identifier `0x123`:

| Field | Offset | Size | Description |
|---|---:|---:|---|
| Command | 0 | 1 byte | Requested ECU operation |
| Parameters | 1 | 3 bytes | Command parameters (authenticated, unused by the current commands) |
| Freshness counter | 4 | 4 bytes | Unsigned, big-endian |
| Authentication tag | 8 | 16 bytes | Truncated HMAC-SHA-256 |

The tag covers the CAN identifier, the configured Data ID (`0x1234`), the command, the parameters, and the full freshness counter. The receiver compares tags in constant time.

## Accepted frame, step by step

```mermaid
sequenceDiagram
    participant S as Sender
    participant C as can_if
    participant Y as sec_layer
    participant F as counter_store
    participant A as ecu_app

    S->>C: CAN FD frame, ID 0x123, 24 bytes
    C->>Y: decoded message
    Y->>Y: frame checks
    Y->>Y: verify HMAC tag
    Y->>Y: check counter is new and within the jump limit
    Y-->>C: accepted: command, parameters, counter
    C->>F: save counter
    F-->>C: saved (temp file, fsync, rename)
    C->>A: execute command
    A-->>C: result text
```

In the code, the receive loop in `can_receiver.c` plays the role of the coordinator shown above.

## Freshness rules

After the HMAC check passes, a counter is accepted only if all of these hold:

- The last accepted counter is not `UINT32_MAX`.
- The new counter is strictly greater than the last accepted one.
- The forward jump is at most `FRESHNESS_MAX_JUMP` (default 1000). A limit of 0 disables the check.

A repeated counter is reported as a replay, a lower one as stale, and a larger-than-allowed jump as too large. Every rejection leaves the stored counter unchanged.

## Counter persistence

The last accepted counter lives in a file: `$SECURE_ECU_COUNTER_FILE`, or `~/.secure_ecu_counter` by default.

- **Missing file:** first start, the counter begins at 0.
- **Corrupt or unreadable file:** the receiver refuses to start. A silent reset would reopen the replay window.
- **Writes:** the value is written to a temporary file, flushed with `fsync`, and renamed over the real file, so a crash cannot leave a half-written counter.
- **Format:** one line, `v1 <counter> <bitwise complement in hex>`, which detects truncation and garbage.

## Build and test layout

| Program | Sources | Purpose |
|---|---|---|
| `can_receiver` | `can_receiver.c`, `can_if.c`, `sec_layer.c`, `secoc.c`, `freshness.c`, `counter_store.c`, `ecu_app.c` | The ECU |
| `secoc_sender` | `secoc_sender.c`, `secoc.c` | Sends valid and deliberately forged test frames |
| `test_*` | One per module | Unit tests (`make test`) |
| `fuzz_ecu` | `fuzz_ecu.c` plus every module except the socket layer | Fuzz and property tests under sanitizers (`make fuzz`) |
| `tests/live_test.sh` | Uses `can_receiver` and `secoc_sender` | Live integration test over `vcan0` (`make integration`) |
