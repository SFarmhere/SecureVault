# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

We take the security of SecureVault seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please create a private advisory at:
https://github.com/SFarmhere/SecureVault/security/advisories/new

You should receive a response within 48 hours. If for some reason you do not, please follow up via GitHub Issues to ensure we received your message.

### What to include

- Type of issue (buffer overflow, privilege escalation, etc.)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

### What to expect

- We will acknowledge receipt within 48 hours
- We will provide an estimated timeline for a fix
- We will notify you when the issue is resolved
- We will credit you in the release notes (unless you prefer to remain anonymous)

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the issue and determine affected versions
2. Audit code to find any similar issues
3. Prepare fixes for all supported versions
4. Release fixes as soon as possible

## Security Features

### Cryptographic Security

- **Algorithm**: AES-256-GCM for data encryption, RSA-4096 for key wrapping
- **Key storage**: Private keys never leave the hardware token (PKCS#11)
- **Post-quantum**: Kyber1024 available for forward secrecy
- **Randomness**: Hardware-generated random numbers from token

### Anti-Tampering

- **Anti-debug**: Detects ptrace, NtGlobalFlag, hardware breakpoints
- **Integrity check**: PE/ELF/Mach-O hash verification at startup
- **Anti-cold-boot**: Keys encrypted in RAM, mlockall to prevent swapping
- **DMA protection**: IOMMU configuration, Thunderbolt security level check

### Side-Channel Protection

- Constant-time cryptographic operations
- Cache line flushing after sensitive operations
- LFENCE serialization after conditional branches
- No data-dependent memory access patterns

### TPM Integration

- PCR measurements for boot integrity
- Sealed key storage tied to platform state
- Remote attestation support

## Known Security Considerations

- The security module is currently in beta for Windows ARM64
- FIDO2/WebAuthn support is planned for v2.1
- Formal verification (Frama-C) is planned for v3.0

## Hall of Fame

We thank the following researchers for their responsible disclosures:

*None yet. Be the first.*

---

## License

This security policy is part of the SecureVault project, licensed under GNU GPL v3.