# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**pgpkms** is a Python library and CLI tool that performs OpenPGP (RFC 4880 v4) signing using AWS KMS or Google Cloud KMS RSA keys. It generates GnuPG-compatible public keys and detached signatures without requiring local private key material.

## Commands

### Install
```bash
pip install .
```

### Run tests
```bash
python -m unittest discover tests -v
```

### Run a single test file
```bash
python -m unittest tests.test_aws_kms -v
python -m unittest tests.test_gcp_kms -v
python -m unittest tests.test_generic -v
```

### CLI usage (after install)
```bash
pgpkms export    # Export public key in PGP format
pgpkms sign      # Create detached signature
pgpkms message   # Wrap message with signature
```

## Architecture

### Core modules (`pgpkms/`)

- **`pgpkms.py`** — `KmsPgpKey` class: the central component. Fetches the RSA public key from KMS, constructs OpenPGP v4 key packets, and produces RFC 4880 compliant signatures. Methods: `to_pgp()`, `sign()`, `message()`.
- **`kms_providers.py`** — KMS provider abstraction. Abstract base class `KMSProvider` with two implementations: `AWSKMSProvider` and `GoogleCloudKMSProvider`. Factory function `get_kms_provider(key_id, kms_client)` auto-detects the provider from the key ID format (UUID/ARN → AWS, `projects/*/locations/*` → GCP, defaults to AWS).
- **`armour.py`** — PGP ASCII armoring (base64 + CRC24 checksum).
- **`__main__.py`** — CLI entry point with `export`, `sign`, `message` subcommands. Reads configuration from environment variables and CLI options.

### CLI scripts (`bin/`)

- `pgpkms` — Main CLI
- `pgpkms-git` — Git commit signing wrapper
- `pgpkms-reprepro` — Debian repository (reprepro) integration
- `prepare-to-gpg-clearsign` — Message preparation for GPG clearsign format

### Key environment variables

| Variable | Purpose |
|---|---|
| `PGP_KMS_KEY` | KMS key ID, ARN, or GCP resource name |
| `PGP_KMS_HASH` | Hash algorithm: sha256 (default), sha384, sha512 |
| `GPG_KEY_EXPIRATION` | Key expiration in days |
| `GPG_KEY_FINGERPRINT` | Cached fingerprint to reduce KMS API calls |

AWS uses tags (`PGPName`, `PGPEmail`) and GCP uses labels (`pgp-name`, `pgp-email`) for user ID on exported keys.

### Testing

Tests use `unittest` with `unittest.mock` to mock KMS API responses. No real KMS credentials needed for testing. Test files mirror the provider split: `test_aws_kms.py`, `test_gcp_kms.py`, `test_generic.py`.

### Key design decisions

- RSA key bytes are parsed from DER-encoded `SubjectPublicKeyInfo` using `pyasn1`
- OpenPGP packet construction is done manually (no GPG library dependency)
- Provider detection is by key ID string pattern matching, falling back to AWS for backward compatibility
- The `add_gcp_support` branch adds GCP KMS as a second provider alongside the original AWS-only implementation
