# Peerline

**Two peers. One authenticated conversation.** A direct terminal messenger built with Python asyncio and the platform TLS implementation. No message relay or central account service.

## Requirements

Python 3.11+, OpenSSL 1.1.1+ with Ed25519 support; macOS or Linux for the interactive stdin event loop. Direct network reachability between peers is required. Start with the localhost demonstration.

## Two-terminal demonstration

Create two separate identities (each command refuses an existing directory):

```sh
python3 peerline.py identity identities/alice
python3 peerline.py identity identities/bob
```

Terminal 1:

```sh
python3 peerline.py listen --identity identities/alice --trust identities/bob/public.pem
```

Terminal 2:

```sh
python3 peerline.py connect --identity identities/bob --trust identities/alice/public.pem
```

Type a line and press Enter. `/quit` ends the session. Messages are not saved by the application.

For two computers, exchange **only `public.pem`** over a channel you trust. Compare SHA-256 fingerprints independently:

```sh
python3 peerline.py fingerprint path/to/peer-public.pem
```

The listener can explicitly bind its LAN interface with `--host LAN_IP`; the connector uses that IP and the matching port. Do not share `private.key`. SSH is not required by this rebuilt implementation.

## Trust and protocol

```text
Peer A certificate ← trusted out-of-band exchange → Peer B certificate
                         ↓
           mutual TLS 1.3 + exact certificate fingerprint
                         ↓
            4-byte big-endian length | UTF-8 JSON frame
```

JSON contains `version`, `sequence`, and `text`. Sequence starts at zero independently in each direction. TLS handles encryption and transport authentication; application validation checks sequence and frame shape. Partial TCP reads are handled with readexactly. Frames are capped at 65,536 bytes; text at 16,000 UTF-8 bytes. A partially received body times out after 15 seconds. Terminal escape/control characters are sanitized before display.

Identities use self-signed Ed25519 certificates with one-year validity. Private files are created under a restrictive umask in a mode-700 directory. Both endpoints require a trusted certificate, and the application also checks the exact leaf fingerprint. Hostname checks are not the identity mechanism: trust comes from the explicitly exchanged certificate.

## Verify

```sh
python3 -m unittest -v
```

Tests exercise Unicode and fragmented frames, invalid size/sequence, terminal sanitization, an actual mutual-TLS round trip, and rejection of an untrusted server certificate. Tests bind temporary localhost ports and generate temporary identities.

## Threat model and limits

Protects a direct session against an unauthenticated network peer when certificates were exchanged authentically and endpoint private keys remain private. Endpoint compromise, malicious trusted peers, traffic metadata, and certificate-exchange impersonation are outside that protection. This is an educational prototype, not independently audited secure messaging software.

No NAT traversal, peer discovery, offline queues, group chat, persistent history, automatic key rotation, or application-level double ratchet. A listener accepts one conversation and exits afterward. It is decentralized only in the narrow sense that the live conversation requires no central server.

## Repository description

Direct peer-to-peer terminal messaging with mutual TLS 1.3, certificate fingerprint verification, and bounded message framing.

## Provenance

New October 2026 rebuild created with AI assistance. MIT licensed. Uses Python's standard ssl implementation, not custom cryptography.
