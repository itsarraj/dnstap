# Contributing to dnstap

Thank you for contributing to `dnstap`.

## Guidelines

1. **Standalone Architecture**: Keep this crate self-contained with no workspace coupling.
2. **RFC 1035 Compliance**: Wire encoding and decoding must follow RFC 1035 / RFC 3596 specifications.
3. **Verification**: All features (UDP, TCP, latency injection, SERVFAIL spoofing, TC truncation bit, address overrides) must be verified through automated tests against real UDP/TCP sockets.
4. **Code Quality**: No compiler warnings, zero AI attributions in code or commit messages.
