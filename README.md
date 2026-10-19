# Secure ECU Simulator in C with SecOC

A lightweight Electronic Control Unit (ECU) simulator written in C that uses Linux SocketCAN for CAN communication and OpenSSL for HMAC-SHA-256 message authentication.

The project explores automotive cybersecurity concepts through a modular, AUTOSAR-inspired architecture, including message authentication, freshness management, replay protection, and secure command processing.

> **Project status:** In development. SocketCAN integration, SecOC authentication, and receiver-side freshness validation are implemented and unit-tested. The layered architecture and ECU command processing are planned next.

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

- SocketCAN raw socket integration.
- Virtual CAN interface support using `vcan0`.
- CAN FD frame reception.
- OpenSSL-based HMAC-SHA-256 authentication.
- A 16-byte truncated authentication tag.
- Configurable test key through an environment variable.
- Receiver-side freshness counter tracking.
- Rejection of duplicate (replayed) and stale messages.
- Bounded forward counter jump and counter-exhaustion handling.
- Unit tests for valid messages, tampering, malformed input, and freshness rules.

### Planned

- Separation of communication, security, freshness, and application layers.
- ECU command execution only after successful authentication and freshness validation.
- Persistent freshness counter across receiver restarts.
- Expanded integration tests and continuous integration.
- Architecture and test documentation in `docs/`.

## Architecture

The current processing flow is:

```text
         CAN / CAN FD Network
                  |
                  v
        +--------------------+
        |    SocketCAN       |
        |   Communication    |
        +--------------------+
                  |
                  v
        +--------------------+
        |  Frame Validation  |
        +--------------------+
                  |
                  v
        +--------------------+
        |   SecOC / HMAC     |
        |  Authentication    |
        +--------------------+
                  |
                  v
        +--------------------+
        |  Freshness Manager |
        +--------------------+
                  |
                  v
        +--------------------+
        |   ECU Application  |
        | Command Processing |
        |     (Planned)      |
        +--------------------+
```

Authentication is always evaluated before freshness. A forged frame can therefore never advance the stored counter.

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

## Project Structure

```text
secure-ecu-simulator/
├── include/
│   ├── secoc.h
│   └── freshness.h
├── src/
│   ├── can_receiver.c
│   ├── secoc.c
│   ├── secoc_sender.c
│   └── freshness.c
├── tests/
│   ├── test_secoc.c
│   └── test_freshness.c
├── docs/
├── Makefile
├── LICENSE
├── README.md
└── .gitignore
```

- `include/secoc.h`: Public definitions and interfaces for the authentication module.
- `include/freshness.h`: Interface for the freshness manager.
- `src/can_receiver.c`: SocketCAN receiver, frame validation, authentication, and freshness checks.
- `src/secoc.c`: Message construction, HMAC generation, and authentication verification.
- `src/secoc_sender.c`: Utility for sending valid and deliberately forged test messages.
- `src/freshness.c`: Counter validation and replay rejection logic.
- `tests/test_secoc.c`: Authentication unit tests.
- `tests/test_freshness.c`: Freshness unit tests.
- `docs/`: Architecture documentation and test evidence.

The `build/` directory holds generated binaries and is excluded from version control.

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
git clone <YOUR_GITHUB_REPOSITORY_URL>
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

Compile the project:

```bash
make
```

Remove generated binaries and rebuild:

```bash
make clean
make
```

The expected executables are:

```text
build/can_receiver
build/secoc_sender
build/test_secoc
build/test_freshness
```

The exact build targets are defined in the Makefile.

## Unit Tests

Run both test suites:

```bash
make test
```

The authentication suite covers:

- Parsing a hexadecimal authentication key.
- Rejecting a malformed key.
- Creating an authenticated message.
- Accepting a valid message.
- Decoding the big-endian freshness value.
- Rejecting modified commands and parameters.
- Rejecting modified freshness values.
- Rejecting an altered authentication tag.
- Rejecting an incorrect CAN identifier.
- Rejecting malformed payload lengths.

The freshness suite covers:

- Accepting increasing counters.
- Rejecting duplicate and older counters.
- Accepting a jump of exactly the maximum and rejecting anything larger.
- Leaving state unchanged after a rejected jump.
- Unlimited jumps when the limit is 0.
- Rejecting all frames after counter exhaustion, including wraparound to 0.
- Rejecting a NULL state argument.

## Live SocketCAN Testing

### 1. Configure the test key

Use the following key only for local development:

```bash
export SECURE_ECU_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

The same key must be set in the receiver and sender terminals.

### 2. Start the ECU receiver

In Terminal 1:

```bash
export SECURE_ECU_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

./build/can_receiver vcan0
```

### 3. Send test messages

In Terminal 2, with the same key exported:

```bash
./build/secoc_sender vcan0 valid 10      # accepted
./build/secoc_sender vcan0 valid 10      # rejected: replayed counter
./build/secoc_sender vcan0 valid 5       # rejected: stale counter
./build/secoc_sender vcan0 forged 11     # rejected: HMAC validation failed
./build/secoc_sender vcan0 valid 11      # accepted: the forged frame did not consume the counter
./build/secoc_sender vcan0 valid 5000    # rejected: counter jump too large
./build/secoc_sender vcan0 valid 12      # accepted
```

The first counter after a receiver start must be within `FRESHNESS_MAX_JUMP` of 0.

## Security Considerations

- **Authentication:** HMAC-SHA-256 verifies message integrity and possession of the shared secret.
- **Tag truncation:** The prototype uses a 128-bit authentication tag derived from HMAC-SHA-256.
- **Freshness:** The receiver accepts only strictly increasing counters, and only after the tag is verified. Forged frames cannot advance the counter.
- **Jump limit:** A bounded forward jump prevents a single authenticated frame from pushing the counter near `UINT32_MAX` and locking out the legitimate sender.
- **Counter exhaustion:** Once the counter reaches `UINT32_MAX`, all frames are rejected. A real system would need key or session rollover.
- **Counter persistence:** The counter is stored in RAM and resets to 0 when the receiver restarts. Frames recorded earlier could be replayed after a restart. Real ECUs persist the counter in non-volatile memory or resynchronize through a protocol.
- **Key management:** The environment variable is a development convenience. A real automotive implementation requires appropriate secret provisioning, access controls, and key lifecycle management.
- **Transport:** `vcan0` is a software testing interface, not a physical CAN bus.
- **Safety:** The simulator is not intended for deployment in a production vehicle or safety-critical ECU.

## Roadmap

- [x] Initialize project and Git repository.
- [x] Integrate SocketCAN.
- [x] Receive CAN and CAN FD frames.
- [x] Implement HMAC-SHA-256 authentication.
- [x] Test valid messages and authentication failures.
- [x] Implement freshness counter validation.
- [x] Reject duplicate and stale messages (unit-tested).
- [x] Complete live valid, forged, and replay integration testing.
- [ ] Implement AUTOSAR-inspired software layers.
- [ ] Add ECU command processing after security checks.
- [ ] Persist the freshness counter across restarts.
- [ ] Expand integration tests and security documentation.
- [ ] Configure continuous integration.

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
