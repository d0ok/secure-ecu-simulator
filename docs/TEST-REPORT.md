# Test Report

This report describes what is tested in the Secure ECU Simulator, how to reproduce each test, and which requirements each test covers. The raw output of each run is kept in `docs/test-evidence-*.txt`.

## Test levels

| Level | Command | What it exercises | Needs `vcan0` |
|---|---|---|---|
| Unit tests | `make test` | Each module in isolation | No |
| Integration test | `make integration` | The real receiver and sender over a virtual CAN interface | Yes |
| Fuzz and property tests | `make fuzz` | Random and mutated inputs against the security layer, parsers, and ECU application, under AddressSanitizer and UBSan | No |
| Continuous integration | GitHub Actions | Build, unit tests, and a short fuzz run on every push | No |

## Unit tests

| Suite | Checks | Covers |
|---|---:|---|
| `test_secoc` | 11 | Key parsing, payload construction, acceptance of authentic payloads, big-endian counter decoding, rejection of a modified command, parameters, counter, tag, CAN ID, and payload length |
| `test_freshness` | 14 | Increasing, duplicate, and older counters, jump limit boundaries, unchanged state after a rejection, unlimited jumps, counter exhaustion and wraparound, NULL state |
| `test_sec_layer` | 19 | The full validation pipeline with hand-built frames: valid frames, replay, forged tags not consuming the counter, stale counters, large jumps, classic CAN, wrong length, extended, remote, and error frames, wrong CAN ID, a tag signed for another ID, NULL arguments |
| `test_ecu_app` | 10 | Each command, state changes, unsupported commands changing nothing, truncated output buffers, invalid arguments |
| `test_counter_store` | 27 | Save and load, file format and permissions, atomic replacement, nine kinds of corrupt files, unwritable locations, NULL arguments, path resolution |
| **Total** | **81** | |

Pass criterion: every suite prints `All N ... tests passed.` and `make test` exits with status 0.

## Integration test

`tests/live_test.sh` starts the receiver on `vcan0` with a throwaway counter file and runs three phases. It contains 20 checks.

**Phase 1: frame handling (15 checks)**

| Frame sent | Expected result |
|---|---|
| Valid, counter 10 (ping) | Accepted |
| Same frame again | Rejected: replayed counter |
| Valid, counter 5 | Rejected: stale counter |
| Forged tag, counter 11 | Rejected: HMAC validation failed |
| Valid, counter 11 | Accepted (the forged frame did not consume the counter) |
| Valid, counter 5000 | Rejected: counter jump too large |
| Valid, counter 12 (lock) | Accepted, doors locked |
| Valid, counter 13 (status) | Accepted, `state=LOCKED executed=3` |
| Classic CAN frame | Rejected |
| 16-byte CAN FD frame | Rejected: incorrect payload length |
| Frame on CAN ID 0x124 | Rejected: unexpected CAN identifier |

It also checks that the first start reports no counter file, and that the counter file holds 13 afterwards.

**Phase 2: restart (3 checks).** The receiver is restarted on the same counter file. It must restore counter 13, reject counter 13 as a replay, and accept counter 14.

**Phase 3: corrupt counter file (2 checks).** With garbage in the counter file, the receiver must exit with an error and print the refusal message.

Pass criterion: the script ends with `ALL INTEGRATION CHECKS PASSED` and exits with status 0.

## Fuzz and property tests

`tests/fuzz_ecu.c` generates reproducible random cases from a seed and verifies properties that must always hold. It is built with `-fsanitize=address,undefined` and `-fno-sanitize-recover=all`, so any memory error or undefined behavior aborts the run.

| Phase | Properties checked |
|---|---|
| Freshness | Outcomes match an independent 64-bit model of the rules, including counters near `UINT32_MAX`. A rejection never changes the stored counter. |
| Key parsing | Only exactly 64 hex characters are accepted. A valid lower-case key is never rejected. |
| Payload verification | Random payloads never verify. A valid payload verifies only under its own CAN ID. A flipped bit or a wrong length always fails, and wrong lengths are tested on exact-size heap buffers. |
| Security layer | Correctly signed frames follow the freshness rules. Replayed, mutated, wrong-key, wrong-ID, and random frames are always rejected, and none of them changes the stored counter. |
| ECU application | State matches a model, output is always NUL-terminated, and any buffer size is handled safely. |
| Counter file | Garbage and damaged files never load as a different value. Saving and loading round-trips. No temporary file is left behind. |

The default run (`make fuzz`) uses 100,000 iterations per phase and seed 1, which is 430,201 cases. The CI run uses 50,000 iterations, which is 215,201 cases. Choose other sizes and seeds with `make fuzz FUZZ_ITERS=1000000 FUZZ_SEED=7`. A violation is printed with its phase and iteration, and on the same build the same seed reproduces it. The exact case sequence can differ between compilers or machines, so the per-phase statistics printed by one build may not match those of another.

Pass criterion: the output ends with `FUZZ PASSED ... no violations, no sanitizer findings`.

### Checking the fuzzer itself

A fuzzer that never fails proves little, so the harness was run against deliberately broken versions of the code. Each of these is detected:

| Seeded bug | How it is detected |
|---|---|
| Freshness updated before the HMAC check | Security-layer property: a forged frame changed the stored counter |
| Stale counters no longer rejected | Freshness model mismatch |
| Output buffer overflow in the ECU application | AddressSanitizer heap-buffer-overflow |
| Counter-file check value ignored | Counter-file property: a record with a wrong check value was accepted |

## Requirement coverage

| Requirement | Unit | Integration | Fuzz |
|---|---|---|---|
| Authentic messages are accepted | `test_secoc`, `test_sec_layer` | Frames 1, 5, 7, 8 | Security layer |
| Modified command, parameters, counter, or tag is rejected | `test_secoc` | Frame 4 (forged tag) | Payload verification, mutations |
| A tag is valid only for its CAN ID | `test_secoc`, `test_sec_layer` | Frame 11 | Payload verification, wrong-ID frames |
| Replayed messages are rejected | `test_freshness`, `test_sec_layer` | Frame 2 | Security layer replays |
| Stale counters are rejected | `test_freshness`, `test_sec_layer` | Frame 3 | Freshness model |
| A forged frame cannot consume the counter | `test_sec_layer` | Frames 4 and 5 | Security layer |
| Implausible counter jumps are rejected | `test_freshness`, `test_sec_layer` | Frame 6 | Freshness model |
| Counter exhaustion is handled | `test_freshness` | | Freshness model |
| Malformed frames are rejected | `test_sec_layer` | Frames 9, 10, 11 | Security layer garbage |
| Replay after a restart is rejected | `test_counter_store` | Phase 2 | Counter file |
| A corrupt counter file stops the receiver | `test_counter_store` | Phase 3 | Counter file |
| Commands run only after every check passes | `test_ecu_app` | Lock and status frames | ECU application |
| No memory errors or undefined behavior in the logic layers | | | All phases under sanitizers |

## Reproducing the results

Set up `vcan0` as described in the README, then:

```bash
make clean && make
make test
make integration | tee docs/test-evidence-integration.txt
make fuzz | tee docs/test-evidence-fuzz.txt
```

## Limitations of the testing

- Everything runs on a virtual CAN interface. No physical CAN transceiver, bus load, or hardware timing is tested.
- `can_if.c` and `secoc_sender.c` are exercised only through the integration test. They have no unit tests and are not fuzzed.
- The integration test is not part of CI, because GitHub-hosted runners generally lack the `vcan` kernel module.
- There are no performance, latency, or concurrency tests, and no tests with several senders at once.
- Fuzzing is deterministic and driven by a simple generator. It is not coverage-guided.
- The tests use a fixed development key. Key provisioning and rotation are not tested because they are not implemented.
