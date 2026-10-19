# Secure ECU Simulator in C with SecOC

A lightweight Electronic Control Unit (ECU) simulator written in C that uses Linux SocketCAN for CAN communication and OpenSSL for HMAC-SHA-256 message authentication.

The project explores automotive cybersecurity concepts through a modular, AUTOSAR-inspired architecture, including message authentication, freshness management, replay protection, and secure command processing.

> **Project status:** In development. SocketCAN integration is implemented, and SecOC authentication unit tests are passing. Receiver-side replay protection and the complete layered architecture are planned next.

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
- Unit tests for valid messages, tampering, and malformed input.

### Planned

- Receiver-side freshness counter tracking.
- Rejection of duplicate and stale messages.
- Separation of communication, security, freshness, and application layers.
- ECU command execution only after successful authentication and freshness validation.
- Expanded security tests and continuous integration.
- GitHub publication with architecture and test documentation.

## Architecture

The intended processing flow is:

```text
         CAN / CAN FD Network
                  |
                  v
        +--------------------+
        |    SocketCAN       |
        | Communication      |
        +--------------------+
                  |
                  v
        +--------------------+
        |   Frame Validation |
        +--------------------+
                  |
                  v
        +--------------------+
        |  SecOC / HMAC      |
        | Authentication    |
        +--------------------+
                  |
                  v
        +--------------------+
        | Freshness Manager  |
        | (Planned)          |
        +--------------------+
                  |
                  v
        +--------------------+
        | ECU Application    |
        | Command Processing |
        +--------------------+
```

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

## Project Structure

```text
secure-ecu-simulator/
├── include/
│   └── secoc.h
├── src/
│   ├── can_receiver.c
│   ├── secoc.c
│   └── secoc_sender.c
├── tests/
│   └── test_secoc.c
├── docs/
├── build/
├── Makefile
├── README.md
└── .gitignore
```

- `include/secoc.h`: Public definitions and interfaces for the authentication module.
- `src/can_receiver.c`: SocketCAN receiver and secured-frame validation.
- `src/secoc.c`: Message construction, HMAC generation, and authentication verification.
- `src/secoc_sender.c`: Utility for sending valid and deliberately forged test messages.
- `tests/test_secoc.c`: Automated authentication unit tests.
- `docs/`: Architecture documentation and test evidence.
- `build/`: Generated binaries.

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

After publishing the repository on GitHub:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd secure-ecu-simulator
```

Alternatively, use the existing local project directory.

### 2. Configure the virtual CAN interface

Load the virtual CAN kernel module and create `vcan0`:

```bash
sudo modprobe vcan

sudo ip link add dev vcan0 type vcan
sudo ip link set dev vcan0 mtu 72
sudo ip link set dev vcan0 up
```

If `vcan0` already exists, skip the `ip link add` command.

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
```

The exact build targets are defined in the Makefile.

## Unit Tests

Run the authentication test suite:

```bash
make test
```

The authentication unit tests currently pass.

The test suite covers cases such as:

- Parsing a hexadecimal authentication key.
- Creating an authenticated message.
- Accepting a valid message.
- Rejecting modified commands and parameters.
- Rejecting modified freshness values.
- Rejecting an altered authentication tag.
- Rejecting an incorrect CAN identifier.
- Rejecting malformed payload lengths.

These tests validate authentication behavior. They do not yet establish that replayed messages are rejected by the receiver.

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
cd ~/Desktop/secure-ecu-simulator

export SECURE_ECU_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

./build/can_receiver vcan0
```

### 3. Send a valid authenticated message

In Terminal 2:

```bash
cd ~/Desktop/secure-ecu-simulator

export SECURE_ECU_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

./build/secoc_sender vcan0 valid 1
```

The expected behavior is a successful authentication message from the receiver.

### 4. Send a forged message

In Terminal 2:

```bash
./build/secoc_sender vcan0 forged 2
```

The sender deliberately modifies the authentication tag. The receiver should reject the message.

These commands are intended for the project's local virtual CAN test environment.

## Security Considerations

- **Authentication:** HMAC-SHA-256 verifies message integrity and possession of the shared secret.
- **Tag truncation:** The prototype uses a 128-bit authentication tag derived from HMAC-SHA-256.
- **Freshness:** The counter is authenticated, but receiver-side freshness enforcement is still planned. Replaying an unchanged, correctly authenticated message may therefore still succeed.
- **Key management:** The environment variable is a development convenience. A real automotive implementation requires appropriate secret provisioning, access controls, and key lifecycle management.
- **Transport:** `vcan0` is a software testing interface, not a physical CAN bus.
- **Safety:** The simulator is not intended for deployment in a production vehicle or safety-critical ECU.

## Roadmap

- [x] Initialize project and Git repository.
- [x] Integrate SocketCAN.
- [x] Receive CAN and CAN FD frames.
- [x] Implement HMAC-SHA-256 authentication.
- [x] Test valid messages and authentication failures.
- [ ] Complete live valid-versus-forged integration testing.
- [ ] Implement freshness counter validation.
- [ ] Reject duplicate and stale messages.
- [ ] Implement AUTOSAR-inspired software layers.
- [ ] Add ECU command processing after security checks.
- [ ] Expand integration tests and security documentation.
- [ ] Configure continuous integration.
- [ ] Publish the project on GitHub.

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

This project is intended for educational and research purposes. Add a license, such as MIT, if you decide to publish the code under that license.

## Author

**Dhia Benothmen**

Telecommunications Engineering Student  
Interests: Automotive Cybersecurity, Embedded Systems, CAN Bus Security, and Secure ECU Communication.
