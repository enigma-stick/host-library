# Enigma host library: agent guidance

## Purpose and collaboration

This repository is the Rust host/driver library for the Enigma Stick, an ESP32-C3 + NXP SE051 USB cryptographic token. The firmware has reached a functional early-release milestone. The user is starting the host library to replace a Go CLI/test harness that currently also acts as the driver.

The user wants to learn and understand the implementation, not have an agent build the entire project unasked. Explain Rust ownership, lifetimes, errors, and API tradeoffs as needed. Review when asked to review; implement bounded changes when asked to implement. Prefer small concrete steps, no speculative frameworks. Do not assume prior permission to write firmware business logic also authorizes cross-repo edits.

As of the initial handoff (September 2026), `Cargo.toml` declares package `enigma`, version `0.1.0`, edition 2024, no dependencies, and `src/lib.rs` is the starter template. Reinspect current files before acting; this is a checkpoint, not a permanent state description.

## Intended direction

- Rust core library owns transport, framing, typed commands/results, and device errors.
- A separate real CLI will consume it. Interactive PIN prompting, terminal output, and automatic auth/retry UX should stay outside the core initially.
- A thin C ABI is planned for Node/Python/other consumers. Do not implement FFI prematurely. When requested, use opaque handles, explicit buffer ownership/freeing, stable C types, and prevent panics crossing the boundary; never expose Rust layouts as ABI.
- PKCS#11 and possibly an SSH agent are later integrations, not prerequisites for this library's first milestone.
- Suggested first vertical slice: USB connection -> frame codec -> typed errors -> status/authenticate/lock, then key management and crypto commands.
- Prefer a straightforward synchronous API initially unless the user chooses otherwise. Keep transport and pure codec code separable enough to test without hardware; do not create a plugin/backend framework just for future possibilities.

## Authoritative references

Firmware repository: `/home/jonah/Dev/esp/keymgr`.

Read these as needed before encoding any operation:

- `main/protocol.h/.c`: frame layout, IDs, error mapping.
- `main/commands.c/.h`: actual payload decoding/encoding and handler behavior. C struct field order/size is NOT the wire specification.
- `main/serial.c/.h`: big-endian primitives, length-prefixed strings and arrays.
- `main/key.h`: key types/usages, public encoding and filters.
- `main/token.h`, `main/se_worker.h`: status enums.
- `main/se_worker.c`: exact mechanisms and operation limits.
- `main/usb_transport.c`: response framing and USB transport.

Existing Go test harness: `/home/jonah/Dev/firmware/cli/keymgr`. Its `command.go`, `serial.go`, `usb.go`, and tests are useful behavioral references, but confirm they match firmware rather than blindly porting implementation quirks. Test key files and payloads in that directory may contain secrets: do not print, commit, or copy them into this repo.

Do not modify these sibling repositories without an explicit request. If unavailable, ask for relevant files instead of guessing the protocol.

## Protocol checkpoint (verify against current firmware)

Header is 8 bytes: `KMGR` (4 ASCII bytes), version `u8`, command/response `u8`, payload length `u16` big-endian. Current version is 1; firmware accepts at most 1024 incoming payload bytes. Development changes have reused version 1, so matching version alone is not enough for historical compatibility.

Integers are explicitly big-endian. Strings have a `u32` byte length then bytes, with no terminating NUL. Array lengths follow the specific serializer. Reject truncated/oversized fields before allocating. Do not encode enums via Rust's native representation. Preserve binary data as bytes; base64/hex belong at presentation boundaries.

Commands:

| ID | Operation |
| --- | --- |
| 0x01 / 0x02 | ping / status |
| 0x10 / 0x11 / 0x12 | initialize / authenticate / lock |
| 0x20 | generate key |
| 0x21 / 0x22 | encrypt / decrypt |
| 0x23 / 0x24 | sign / verify (verify currently HMAC) |
| 0x25 | ECDH + HKDF |
| 0x30 | export public key |
| 0x40 / 0x41 | list keys / destroy key |

Success with no payload uses response `0x00`; data responses generally use their matching operation IDs (check firmware). Error response `0xFF` contains **code `u8` + message length `u32` big-endian + message bytes**. Empty messages are valid (5-byte payload). Codes:

| Code | Meaning |
| --- | --- |
| 0x00 | OK enum value; not a normal error |
| 0x01 / 0x02 | authentication required / authentication failed |
| 0x03 / 0x04 | invalid input / unsupported operation |
| 0x05 / 0x06 | missing key / policy rejection |
| 0x07 / 0x08 | storage / bad command |
| 0x09 / 0x0A / 0x0B | serialization / initialization failed / invalid state |
| 0xFF | generic failure |

Authentication-required is NOT response type `0x01`; an obsolete firmware enum may still name that old response. Branch on error codes, not English messages. Preserve unknown device codes and their messages, and distinguish transport/protocol errors from device errors. Generic firmware failures are not proof of bad PIN, policy denial, or a missing key.

Status encodes token state (uninitialized=0, provisioning=1, ready=2) and session state (closed=0, authenticated=1, fault=2); check response serializer for field widths. Key types are AES=1, RSA=2, EC=3, HMAC=4; usage encrypt=1, sign=2, derive=3. Read exact payloads from firmware rather than inferring from this summary.

## Device behavior and crypto

- PIN unlock opens a reusable authenticated ESP-to-SE session; inactivity or explicit lock closes it. Do not require PIN entry for each operation or assume a cached host status prevents a later auth-required response. The encrypted ESP-to-SE channel does NOT imply the USB PIN exchange is encrypted.
- RSA/EC private and customer symmetric keys remain on the SE. Host API normally receives object IDs, not private bytes. Key IDs can be reused after deletion; labels need not be unique. Metadata is on ESP NVS and is separate from SE existence.
- AES-GCM wire blob is nonce[12] || ciphertext || tag[16], currently no AAD. Firmware handles the internal nonce. No streaming/file encryption protocol exists yet.
- RSA signing: PSS/SHA-256. RSA decryption: OAEP/SHA-1 (installed SSS backend limitation). EC signing supports P-256/SHA-256, P-384/SHA-384, P-521/SHA-512. Confirm signature formats with firmware/test vectors; do not silently convert DER ECDSA to fixed-width r||s.
- Public-key export is DER SubjectPublicKeyInfo, encoding enum 1. PEM conversion can be a host convenience.
- HMAC supports SHA-256 and SHA-512 MAC creation/verification. Do not assume the generic verify command also verifies RSA/ECDSA on device.
- ECDH: send local EC derive-key ID, peer SPKI DER with matching curve, result label, and host timestamp in the order specified by firmware. Device internally derives a shared secret, then HKDF-SHA-256 Extract+Expand to a persistent AES-256 key. Response contains key ID, salt, and info. Current info is `enigma/ecdh/aes256/v1`; consume returned values. Salt is public, currently 16 bytes. Host OpenSSL ECDH/HKDF + authenticated AES-GCM decryption has passed interoperability testing.
- Generate/ECDH timestamps are `u32` Unix seconds supplied by host, not an authenticated device clock. Do not confuse persisted metadata schema with wire list entries.
- Broad mechanism selection, private-key import/export/wrapping, and bulk file streaming are not implemented. Never invent wire capabilities to fit a host API.
- SE storage visibility is possible via firmware's `se05x_esp_admin_get_memory_info`, but a host command requires firmware support; do not invent an ID.

## Transport reliability and safety

The Go harness currently uses libusb/gousb with VID:PID `303a:1001`, config 1, interface 1, alternate 0, OUT `0x01`, IN `0x81`. These identify the ESP development interface, not a unique Enigma device; validate selection, especially with multiple devices. Inspect descriptors when needed, and discuss Rust dependency/platform choices before locking them in.

- USB reads are byte chunks, not frame boundaries. Handle fragmented headers/payloads and buffered extra bytes; bound lengths and handle partial writes.
- Serialize request/response transactions per device. The protocol has no request IDs; arbitrary concurrent commands cannot be correlated safely.
- RSA generation can take many seconds (the harness moved from ~2s to ~30s timeouts). Support configurable deadlines.
- A timeout/disconnect does not prove a command failed. Do not automatically replay provisioning, key generation, ECDH, or deletion. After ambiguous timeout, address late responses/resynchronization before issuing another command. Retry after explicit auth-required is a separate caller-controlled decision.
- The Go harness has a known driver-detach/reattach issue: `/dev/ttyACM0` can disappear while USB remains present. Do not copy blanket auto-detach/drain behavior without understanding it. Release claimed resources reliably and avoid detaching unrelated interfaces. Coordinate permission/udev changes with the user; do not require running the whole library as root by default.
- Do not embed terminal prompts, process exit, or unredacted packet dumps in the library. Errors/debug logs must not leak PINs, plaintext, or authentication frames. Keep PIN buffers short-lived and discuss appropriate zeroization without promising impossible guarantees.
- Do not flash, erase/provision a token, delete keys, or run mutating hardware tests without authorization.

## Development and tests

Use idiomatic Rust with explicit `Result` handling; avoid panics/unchecked indexing for device input. Keep dependencies proportionate, and explain nontrivial choices. Use `cargo fmt --check`, `cargo check`, `cargo test`, and `cargo clippy --all-targets` as applicable. Pure codec tests should not require attached USB hardware or root.

Add golden-wire tests checked against firmware/Go serializers, particularly the new u8 error code, empty error messages, unknown codes, ECDH timestamp, and public DER. Test malformed/truncated frames, length limits, partial I/O, and response-type mismatches. Keep hardware integration tests explicit/opt-in and identify destructive operations. Distinguish build/unit-test success from actual device validation.
