# Secure ECU Simulator in C with SecOC

[![CI](https://github.com/d0ok/secure-ecu-simulator/actions/workflows/ci.yml/badge.svg)](https://github.com/d0ok/secure-ecu-simulator/actions/workflows/ci.yml)

A lightweight Electronic Control Unit (ECU) simulator written in C that uses Linux SocketCAN for CAN communication and OpenSSL for HMAC-SHA-256 message authentication.

The project explores automotive cybersecurity concepts through a modular, AUTOSAR-inspired architecture, including message authentication, freshness management, replay protection, and secure command processing.


## Objectives

- Implement CAN and CAN FD communication using the Linux SocketCAN API.
- Authenticate incoming ECU messages using HMAC-SHA-256.
- Reject messages with invalid authentication tags or modified authenticated data.
- Implement freshness validation to prevent replay attacks.
- Organize the software using AUTOSAR-inspired layers.
- Build automated tests for valid, forged, malformed, and replayed messages.
- Document the architecture, security mechanisms, and testing procedures.

## Features

### Implemented

- SocketCAN raw socket integration with CAN FD support (`vcan0`).
- OpenSSL-based HMAC-SHA-256 authentication with a 16-byte truncated tag.
- Configurable test key through an environment variable.
- Receiver-side freshness counter tracking, with rejection of duplicate and stale messages.
- Bounded forward counter jump and counter-exhaustion handling.
- Persistent freshness counter that survives receiver restarts, with atomic file writes and a refusal to start on a corrupt counter file.
- Layered software: communication, security, and ECU application.
- Simulated ECU commands (lock, unlock, status, ping) that run only after authentication and freshness validation succeed.
- Unit tests for each layer, and an automated live integration test.
- Fuzz and property tests run under AddressSanitizer and UndefinedBehaviorSanitizer.
- Continuous integration with GitHub Actions (build, unit tests, short fuzz run).
- Documentation: architecture with diagrams, a test report, and a threat model in `docs/`.

### Possible future work

- Counter resynchronization between sender and receiver.
- Per-session keys or key rotation.
- Counter storage in simulated protected memory.
- Frame-age bounds to limit delayed delivery of valid frames.
- Rate limiting of rejected frames.

## Architecture

```text
         CAN / CAN FD Network
                  |
                  v
        +--------------------+
        |  Communication     |   can_if
        |  (SocketCAN)       |   open, receive, decode flags
        +--------------------+
                  |
                  v
        +--------------------+
        |  Security layer    |   sec_layer
        |  1. frame checks   |   classic CAN, length, flags, CAN ID
        |  2. SecOC / HMAC   |   secoc
        |  3. freshness      |   freshness
        +--------------------+
                  |  only if all three pass
                  v
        +--------------------+
        |  ECU application   |   ecu_app
        |  command handler   |
        +--------------------+
```

Checks always run in this order: frame validation, HMAC verification, freshness. A forged frame therefore never advances the stored counter, and a command is never executed unless every check passes.

| Layer | Module | Responsibility |
|---|---|---|
| Communication | `can_if` | Opens the CAN socket, reads frames, and reports identifier, length, and frame type without any security logic. |
| Security | `sec_layer` | Runs the validation pipeline and returns one result per frame. Has no socket code, so it is unit-tested with hand-built frames. |
| Security | `secoc` | Builds and verifies the truncated HMAC-SHA-256 tag. |
| Security | `freshness` | Tracks the last accepted counter and rejects replayed, stale, or implausible counters. |
| Security | `counter_store` | Saves and restores the last accepted counter so replay protection survives a restart. |
| Application | `ecu_app` | Executes supported commands on a simulated ECU state. |

The project uses an AUTOSAR-inspired design for learning purposes. It is not a complete AUTOSAR implementation and does not claim compliance with an AUTOSAR release.

## Secured Message Format

The educational secured-message profile uses a 24-byte CAN FD payload.

| Field | Offset | Size | Description |
|---|---:|---:|---|
| Command | 0 | 1 byte | Requested ECU operation |
| Parameters | 1 | 3 bytes | Command parameters |
| Freshness counter | 4 | 4 bytes | Unsigned counter, big-endian |
| Authentication tag | 8 | 16 bytes | Truncated HMAC-SHA-256 |
| **Total** | | **24 bytes** | |

The authentication calculation covers the configured CAN identifier, Data ID, command, parameters, and full freshness counter.

The authentication tag is calculated using HMAC-SHA-256 and truncated to 16 bytes. The receiver compares the supplied and calculated tags using a constant-time comparison.

The CAN identifier used for the example profile is `0x123`, and the configured Data ID is `0x1234`.

This message format is a simplified educational profile inspired by AUTOSAR SecOC concepts, not the complete standardized SecOC PDU format.

## ECU Commands

| Command | Name | Effect |
|---:|---|---|
| `0x01` | Lock | Sets the simulated door state to locked |
| `0x02` | Unlock | Sets the simulated door state to unlocked |
| `0x03` | Status | Reports the lock state and the number of commands executed so far |
| `0xA1` | Ping | Replies `pong` |

An authenticated, fresh frame with any other command value is accepted by the security layer but reported by the application as unsupported, and it changes no ECU state. The `PARAMS` bytes are carried and authenticated but not used by the current command set.

## Freshness Policy

After a frame passes frame validation and HMAC verification, the receiver applies these rules to its freshness counter:

| Condition | Result |
|---|---|
| Counter greater than last accepted, within the allowed jump | Accepted; stored counter updated |
| Counter equal to last accepted | Rejected as replay |
| Counter lower than last accepted | Rejected as stale |
| Counter ahead by more than `FRESHNESS_MAX_JUMP` (default 1000) | Rejected; stored counter unchanged |
| Last accepted counter is `UINT32_MAX` | Everything rejected as exhausted |

Every rejection leaves the stored counter unchanged. A jump limit of 0 disables the jump check.

## Counter Persistence

The last accepted counter is stored in a file, so frames captured before a restart cannot be replayed afterwards.

- **Location:** `$SECURE_ECU_COUNTER_FILE` if set, otherwise `~/.secure_ecu_counter`.
- **Startup:** A missing file means a first start at counter 0. A corrupt or unreadable file stops the receiver, because silently resetting would reopen the replay window.
- **Save before execute:** An accepted counter is written to disk before the command runs. If the save fails, the command is not executed.
- **Atomic writes:** The counter is written to a temporary file, flushed to disk, and renamed over the real file, so a crash cannot leave a half-written counter.
- **Format:** One line, `v1 <counter> <bitwise complement in hex>`, which detects truncation and garbage.

To start over during development, delete the file (`rm -f ~/.secure_ecu_counter`) or point `SECURE_ECU_COUNTER_FILE` at a new path.

## Project Structure

```text
secure-ecu-simulator/
├── .github/
│   └── workflows/
│       └── ci.yml
├── include/
│   ├── can_if.h
│   ├── counter_store.h
│   ├── ecu_app.h
│   ├── freshness.h
│   ├── sec_layer.h
│   └── secoc.h
├── src/
│   ├── can_if.c
│   ├── can_receiver.c
│   ├── counter_store.c
│   ├── ecu_app.c
│   ├── freshness.c
│   ├── sec_layer.c
│   ├── secoc.c
│   └── secoc_sender.c
├── tests/
│   ├── fuzz_ecu.c
│   ├── live_test.sh
│   ├── test_counter_store.c
│   ├── test_ecu_app.c
│   ├── test_freshness.c
│   ├── test_sec_layer.c
│   └── test_secoc.c
├── docs/
│   ├── ARCHITECTURE.md
│   ├── TEST-REPORT.md
│   ├── THREAT-MODEL.md
│   └── test-evidence-*.txt
├── Makefile
├── LICENSE
├── README.md
└── .gitignore
```

- `src/can_receiver.c`: The ECU program. It wires the three layers together in a receive loop.
- `src/secoc_sender.c`: Utility for sending valid and deliberately forged test messages.
- `tests/live_test.sh`: Starts the receiver, sends a scripted sequence of valid, forged, replayed, and malformed frames over `vcan0`, and checks the output.
- `docs/`: Test evidence and documentation.

The `build/` directory holds generated binaries and is excluded from version control.

## Documentation

- [Architecture](docs/ARCHITECTURE.md): layers, the order of checks for every frame, message format, freshness rules, and counter persistence, with diagrams.
- [Test report](docs/TEST-REPORT.md): every test level, what each covers, requirement coverage, how to reproduce the results, and the limits of the testing.
- [Threat model](docs/THREAT-MODEL.md): what is protected, which attackers are considered, what is defended, and what is not.

## Requirements

The development environment is Linux, such as Kali Linux or Ubuntu.

Required tools and libraries:

- GCC
- GNU Make
- Git
- Linux SocketCAN
- `can-utils`
- `iproute2`
- OpenSSL development libraries
- `pkg-config`

Install the dependencies on Kali Linux or Ubuntu:

```bash
sudo apt update

sudo apt install -y \
    build-essential \
    git \
    can-utils \
    iproute2 \
    libssl-dev \
    pkg-config
```

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/d0ok/secure-ecu-simulator.git
cd secure-ecu-simulator
```

### 2. Configure the virtual CAN interface

Load the virtual CAN kernel module and create `vcan0`:

```bash
sudo modprobe vcan

sudo ip link add dev vcan0 type vcan
sudo ip link set dev vcan0 mtu 72
sudo ip link set dev vcan0 up
```

If `vcan0` already exists, skip the `ip link add` command. The interface does not persist across reboots, so repeat these commands after restarting.

Verify the interface:

```bash
ip -details link show vcan0
```

The virtual interface enables CAN communication testing without physical automotive hardware.

## Build

```bash
make
```

Remove generated binaries and rebuild:

```bash
make clean
make
```

The build produces the receiver, the sender, and one test program per module in `build/`. The exact targets are defined in the Makefile.

## Unit Tests

```bash
make test
```

This runs five suites:

- **SecOC:** key parsing, payload construction, acceptance of authentic payloads, rejection of modified commands, parameters, freshness values, tags, CAN identifiers, and payload lengths.
- **Freshness:** increasing counters, duplicate and older counters, jump limits, unchanged state after a rejection, unlimited jumps, counter exhaustion and wraparound, and NULL arguments.
- **Security layer:** the full validation pipeline using hand-built frames, including forged tags that must not consume the counter, classic CAN, wrong length, extended, remote, and error frames, wrong CAN identifier, and a tag signed for a different identifier.
- **ECU application:** each command, state changes, unsupported commands changing nothing, truncated output buffers, and invalid arguments.
- **Counter store:** saving and loading, the file format and permissions, atomic replacement, corrupt and truncated files, unwritable locations, and path resolution.

## Fuzz Testing

```bash
make fuzz
```

`tests/fuzz_ecu.c` generates reproducible random and mutated inputs and checks properties that must always hold. It is built with AddressSanitizer and UndefinedBehaviorSanitizer, so memory errors and undefined behavior abort the run. If you see missing `libasan` or `libubsan` errors, install them with `sudo apt install libasan8 libubsan1`.

| Phase | Properties checked |
|---|---|
| Freshness | Outcomes match an independent model of the rules, including counters near `UINT32_MAX`. A rejection never changes the stored counter. |
| Key parsing | Only exactly 64 hex characters are accepted. Odd lengths and arbitrary bytes never crash the parser. |
| Payload verification | Random payloads never verify. A valid payload verifies only under its own CAN ID. Wrong lengths are tested on exact-size heap buffers to catch over-reads. |
| Security layer | Correctly signed frames follow the freshness rules. Replayed, mutated, wrong-key, wrong-ID, and random frames are always rejected, and none of them changes the stored counter. |
| ECU application | Behavior matches a state model, output is always NUL-terminated, and any buffer size is handled safely. |
| Counter file | Garbage and damaged files never load as a different value. Saving and loading round-trips, and no temporary file is left behind. |

Choose the size and seed with `make fuzz FUZZ_ITERS=1000000 FUZZ_SEED=7`. On a given build, the same seed produces the same cases, so a reported violation can be reproduced. The exact case sequence can differ between compilers or machines, so compare violations by seed on the same build. The default run takes a few seconds.

The harness was also checked against deliberately broken code: forging a frame that consumes the counter, accepting stale counters, overflowing the ECU output buffer, and ignoring the counter-file check value are each detected.

## Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and on pull requests. It installs the dependencies on Ubuntu, builds everything, runs `make test`, and runs a short `make fuzz` pass. The live SocketCAN integration test needs a virtual CAN interface (`vcan`), which GitHub-hosted runners generally do not provide, so run `make integration` locally.

## Live SocketCAN Testing

### Automated

With `vcan0` up:

```bash
make integration
```

The script uses a throwaway counter file and runs three phases:

1. Valid, forged, replayed, stale, oversized-jump, and malformed frames, with lock and status commands. The malformed frames are sent with `cansend` from `can-utils`.
2. A receiver restart on the same counter file. The last counter accepted before the restart must be rejected as a replay, and the next counter must be accepted.
3. A corrupted counter file, which must make the receiver refuse to start.

It finishes with `ALL INTEGRATION CHECKS PASSED` when every check matches.

### Manual

Use the following key only for local development, and export it in both terminals:

```bash
export SECURE_ECU_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

In Terminal 1:

```bash
./build/can_receiver vcan0
```

In Terminal 2:

```bash
./build/secoc_sender vcan0 valid 10      # accepted (ping)
./build/secoc_sender vcan0 valid 10      # rejected: replayed counter
./build/secoc_sender vcan0 valid 5       # rejected: stale counter
./build/secoc_sender vcan0 forged 11     # rejected: HMAC validation failed
./build/secoc_sender vcan0 valid 11      # accepted: the forged frame did not consume the counter
./build/secoc_sender vcan0 valid 5000    # rejected: counter jump too large
./build/secoc_sender vcan0 valid 12 01   # accepted: lock
./build/secoc_sender vcan0 valid 13 03   # accepted: status
```

The sender usage is `secoc_sender <interface> <valid|forged> <counter> [command-hex]`. The command defaults to `A1` (ping). The counter persists between runs, so counters must keep increasing. To start over, run `rm -f ~/.secure_ecu_counter` or set `SECURE_ECU_COUNTER_FILE` to a new path. On a fresh start, the first counter must be within `FRESHNESS_MAX_JUMP` of 0.

Example receiver output for an accepted command:

```text
[ACCEPT] ID=0x123 CMD=0x01 PARAMS=10 20 30 FRESHNESS=12
[ECU] doors locked
```

## Security Considerations

- **Authentication:** HMAC-SHA-256 verifies message integrity and possession of the shared secret.
- **Tag truncation:** The prototype uses a 128-bit authentication tag derived from HMAC-SHA-256.
- **Check ordering:** Frame checks, then HMAC, then freshness. Commands run only after all three pass, and forged frames cannot advance the counter.
- **Jump limit:** A bounded forward jump prevents a single authenticated frame from pushing the counter near `UINT32_MAX` and locking out the legitimate sender.
- **Counter exhaustion:** Once the counter reaches `UINT32_MAX`, all frames are rejected. A real system would need key or session rollover.
- **Counter persistence:** The counter is saved to a file and restored at startup, so frames recorded before a restart are rejected as replays. A corrupt counter file stops the receiver instead of resetting it. The file is not protected: anyone who can edit or delete it can reset the counter, and the simulator saves after every accepted frame. A real ECU would keep the counter in protected non-volatile memory, limit write frequency to reduce wear, and resynchronize with the sender through a protocol.
- **Key management:** The environment variable is a development convenience. A real automotive implementation requires appropriate secret provisioning, access controls, and key lifecycle management.
- **Transport:** `vcan0` is a software testing interface, not a physical CAN bus.
- **Safety:** The simulator is not intended for deployment in a production vehicle or safety-critical ECU.

See the [threat model](docs/THREAT-MODEL.md) for the full list of what the design does and does not protect against.

## Roadmap

- [x] Initialize project and Git repository.
- [x] Integrate SocketCAN.
- [x] Receive CAN and CAN FD frames.
- [x] Implement HMAC-SHA-256 authentication.
- [x] Test valid messages and authentication failures.
- [x] Implement freshness counter validation.
- [x] Reject duplicate and stale messages.
- [x] Complete live valid, forged, and replay integration testing.
- [x] Implement AUTOSAR-inspired software layers.
- [x] Add ECU command processing after security checks.
- [x] Persist the freshness counter across restarts.
- [x] Add fuzz testing for malformed frames.
- [x] Add architecture diagrams and test documentation to `docs/`.
- [x] Configure continuous integration.

## Learning Outcomes

This project provides practical experience with:

- C systems programming on Linux.
- SocketCAN and CAN FD communication.
- HMAC-based message authentication with OpenSSL.
- Automotive cybersecurity and SecOC concepts.
- Freshness counters and replay attack prevention.
- Modular embedded-software architecture.
- Unit testing, integration testing, and Git-based development.

## License

This project is released under the [MIT License](LICENSE). It is intended for educational and research purposes and comes with no warranty.
