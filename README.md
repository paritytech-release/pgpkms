# pgpkms: Quick Start

This tool lets you use **AWS KMS** and **Google Cloud KMS (GCP KMS)** RSA keys to generate GnuPG / OpenPGP compatible signatures (v4).

## Quick Start

### 1. Install dependencies

Using pipenv:

```bash
pipenv install --dev
```

Or with pip:

```bash
pip install .
```

### 2. Prepare your KMS key

- **AWS:** Create an RSA signing key in AWS KMS.
- **GCP:** Create an RSA key in Google Cloud KMS with "Asymmetric Sign" purpose.

### 3. Set environment variables

- `PGP_KMS_KEY`: The key ID, ARN, alias, or GCP resource name.
- `GOOGLE_APPLICATION_CREDENTIALS`: (GCP only) Path to your service account JSON file.
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`: (AWS only)

### 4. Export a public key

```bash
python3 -m pgpkms export --pgp-kms-key <your-key-id> --gpg-key-expiration 365
```

### 5. Sign a file

```bash
python3 -m pgpkms sign --pgp-kms-key <your-key-id> --input myfile.bin
```

## More

- For advanced usage and full documentation, see [docs/DETAILED_README.md](docs/DETAILED_README.md)
