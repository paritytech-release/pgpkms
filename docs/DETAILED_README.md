# Cloud KMS Provider Support

This library (and command line utility) allows you to use both **AWS KMS** and **Google Cloud KMS (GCP KMS)** RSA keys to generate GnuPG / OpenPGP compatible signatures (v4). The provider is detected automatically based on the key format.

* [AWS KMS Support](#aws-kms-support)
* [Google Cloud KMS Support](#google-cloud-kms-support)
* [Command Line Usage](#command-line-usage)
* [Running Tests](#running-tests)
* [Library Usage](#library-usage)
* [Copyright Notice](NOTICE.md)
* [License](LICENSE.md)

## AWS KMS Support

### Preparing keys in AWS KMS

You can use the AWS console, AWS CLI, CloudFormation, or Terraform to create an RSA "signing" key in AWS KMS.

By default, the _User ID_ associated with the key will be something like `PgpKms-AwsWrapper (...uuid...)` where `uuid` is the random UUID associated with the key in KMS.

To specify a _User ID_ in the format `Name <email@domain>`, add these tags to the AWS key:

* `PGPName`: the `Name` part of the _User ID_.
* `PGPEmail`: the `email@domain` part of the _User ID_.

### Required Environment Variables for AWS

* `PGP_KMS_KEY`: The default ID, ARN or alias of the key to use.
* `GPG_KEY_EXPIRATION`: Public GPG key expiration time, in days, to be used for the key during the `export` command
* `PGP_KMS_HASH`: The hashing algorithm to use (default to "sha256").
* `GPG_KEY_FINGERPRINT`: Set this to reduce the amount of requests to KMS during Git commit signing (optionally, but highly recommended)

AWS credentials and region variables (for the `boto` AWS Python module):

* `AWS_ACCESS_KEY_ID`: AWS Service account key id
* `AWS_SECRET_ACCESS_KEY`: AWS Service account secret key
* `AWS_DEFAULT_REGION`: AWS Region of the key

## Google Cloud KMS Support

### Preparing keys in Google Cloud KMS

Create an RSA key in Google Cloud KMS with the "Asymmetric Sign" purpose and "RSA_SIGN_PKCS1_2048_SHA256" or similar algorithm.

You can add labels to the key to specify the PGP user ID:
* `pgp-name`: the `Name` part of the _User ID_.
* `pgp-email`: the `email@domain` part of the _User ID_.

If these labels are not set, a default user ID will be generated.

### Required Environment Variables for GCP

* `GOOGLE_APPLICATION_CREDENTIALS`: Path to the service account JSON credentials file with access to the KMS key.
* `PGP_KMS_KEY`: The full resource name of the GCP KMS key version, e.g.:
  ```
  projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>/cryptoKeyVersions/<version>
  ```

All command line and library usage is the same as for AWS KMS keys. The provider is detected automatically based on the key format.

Preparing keys in KMS
---------------------

Your mileage might vary (whether you use the AWS console, AWS cli, or tools like
CloudFormation or Terraform) but overall any RSA "signing" key can be used.

By default the _User ID_ associated with the key will be something along the
lines of `PgpKms-AwsWrapper (...uuid...)` where `uuid` is the random UUID
associated with the key in KMS.

In order to properly specify a _User ID_ in the format of `Name <email@domain>`
we can use a couple of _tags_ on the AWS key itself:

* `PGPName`: the `Name` part of the _User ID_.
* `PGPEmail`: the `email@domain` part of the _User ID_.

Command Line Usage
------------------

The `pgpkms` module provides a quick, minimalistic command line able to
_export_ the public key, or _sign_ a file:

#### Usage:

`python3 -m pgpkms <command> [options]`

or just `pgpkms <command> [options]` if the package is installed in a python virtualenv and env is activated.

#### Commands:

* `export`: Export the public key in a PGP-compatible format.
* `sign`: Sing some data and write a detached PGP signature.
* `message`: Wrap a plaintext in a PGP message and sign it.

#### Options:

* `-o <file>` or `--output <file>`
  Use the specified file as output instead of stdout.

* `-i <file>` or `--input <file>`
  Use the specified file as input instead of stdin.

* `-b` or `--binary`
  Do not armour the output (ignored when command is `message`).

* `--sha256` or `--sha384` or `--sha512`
  Use the specified hashing algorithm.

#### Environment Variables:

* `PGP_KMS_KEY`: The default ID, ARN or alias of the key to use.
* `GPG_KEY_EXPIRATION`: Public GPG key expiration time, in days, to be used for the key during the `export` command
* `PGP_KMS_HASH`: The hashing algorithm to use (default tp "sha256").
* `GPG_KEY_FINGERPRINT`: Set this to reduce the amount of requests to KMS during Git commit signing (optionally, but highly recommended)

In addition, AWS variables for the `boto` AWS Python module:

* `AWS_ACCESS_KEY_ID`: AWS Service account key id
* `AWS_SECRET_ACCESS_KEY`: AWS Service account secret key
* `AWS_DEFAULT_REGION`: AWS Region of the key

#### Examples

Export the (unarmoured) public key into the "trusted.gpg" file.

```bash
$ python3 -m pgpkms export --binary --output trusted.gpg
```

#### Signing GIT commits (for RSA only keys)

First, create and activate a Python virtualenv by

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the whole package by `pip3 install .` from the root of the repo, it will make `pgpkms-git` and `pgpkms` scripts quickly accessible.

Prepare GPG:

* use `gpg --import` to import an already prepared KMS-based GPG key

OR (not recommended, since it produces more versions of public keys):

* export the public key to the local gpg: `pgpkms export  | gpg --import`
* obtain the fingerprint of the key: `pgpkms export | gpg --show-key`

Then configure the local git:

```bash
git config --local commit.gpgsign true
git config --local gpg.program pgpkms-git
git config --local user.name <What is in the PGPName tag above>
git config --local user.email <What was in the PGPEmail tag above>
git config --local user.signingKey <GPG Key fingerprint>
```

A normal `git commit` will produce a signed commit.
However, reading git signatures like `git log --show-signature` **won't be supported**, it is needed to change `gpg.program` back to `gpg`, to verify the signatures, because this signing workflow is only designed for securely signing in the pipelines.

#### Using for reprepro

First, create and activate a Python virtualenv by

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the whole package by `pip3 install .` from the root of the repo, it will make `pgpkms-reprepro`, `pgpkms` and `prepare-to-gpg-clearsign` scripts quickly accessible.

Prepare GPG:

* use `gpg --import` to import an already prepared KMS-based GPG key

OR (not recommended, since it produces more versions of public keys):

* export the public key to the local gpg: `pgpkms export  | gpg --import`
* obtain the fingerprint of the key: `pgpkms export | gpg --show-key`

Then configure the reprepro instance. It is needed to leverage the **SignWith** setting in the hook mode, as it described [there](https://salsa.debian.org/debian/reprepro/-/blob/debian/docs/manual.html):

`SignWith: ! /path/to/pgpkms-reprepro`, i.e. an exclamation mark followed by a space and the full or relative path to a hook script to call. Use `which pgpkms-reprepro` to quickly get it. 

Library Usage
-------------

Simply import the package and look for the `KmsPgpKey` class documentation:

```python
import pgpkms

help(pgpkms.KmsPgpKey)
```

This is summarized as follows:

#### `class KmsPgpKey(key_id, kms_client=None)`

The `KmsPgpKey` class wraps an AWS KMS key and is capable of producing
signatures compatible with GnuPG / OpenPGP.

* `key_id`: The ID, ARN or alias of the AWS KMS key.

* `kms_client`: A BotoCore _KMS_ client, if `None` this will be initialized as:
  ```python
  session = botocore.session.get_session()
  kms_client = session.create_client('kms')
  ```

#### `kmsPgpKey.to_pgp(hash='sha256', armoured=True, kms_client=None, expiration = 365)`

Return the public key from AWS KMS wrapped in an OpenPGP v4 key format as a
`bytes` string.

* `hash`: The hashing algorithm used to prepare the self-signature of the public key.
* `armoured`: Whether the returned key should be armoured (text) or not (binary).
* `kms_client`: A BotoCore _KMS_ client _(optional)_.

#### `kmsPgpKey.sign(input, hash='sha256', armoured=True, kms_client=None)`

Sign the specified input using this key, and return the signature in a format
compatible with GnuPG / OpenPGP as a `bytes` string.

* `input`: The data to be signed.
* `hash`: The hashing algorithm used to sign the data.
* `armoured`: Whether the returned signature should be armoured (text) or not (binary).
* `kms_client`: A BotoCore _KMS_ client _(optional)_.

This method returns a `bytes` string containing the GnuPG / OpenPGP formatted
signature.

#### `kmsPgpKey.message(input, output=None, hash='sha256', kms_client=None)`

Sign the specified _TEXT_ input using this key, writing the signed message AND
signature to the output specified.

* `input`: The data to be signed.
* `output`: Where to write the output.
* `hash`: The hashing algorithm used to sign the data.
* `kms_client`: A BotoCore _KMS_ client _(optional)_.

If output was `None`, this method returns a string containing the GnuPG /
OpenPGP formatted message and signature.

### Bugfixes and version changes:

---------------------
Compared with the original **v1.0.7 by Juit Developers:**

- 1.3.1: Fix of GPG clearsign message generation - affects reprepro signing

- 1.3.0: Support for Debian Repository manager reprepro

- 1.2.1: Move expiration date parameter to `to_pgp` method instead of the whole class, to fix the signatures

- 1.2.0: add `GPG_KEY_EXPIRATION` env variable for the GPG public key, GPG keys can expire

- 1.1.1: add `GPG_KEY_FINGERPRINT` env variable for Git commit signing

- 1.1.0: adds GPG commit signing emulation

- 1.0.8: makes the `PGP_KMS_KEY` environmental variable really working, and removes the hardcoded key name from the code. Removes the `-k` option from the list of options as not really used.

- 1.0.7: Origial Python package by Juit Developers - this repo code extracted from this package

Running Tests
-------------

This project uses `pipenv` for dependency management and testing.

To run all tests:

```bash
pipenv install --dev
pipenv run python -m unittest discover tests -v
```

You can also run a specific test file, for example:

```bash
pipenv run python -m unittest tests.test_aws_kms -v
pipenv run python -m unittest tests.test_gcp_kms -v
pipenv run python -m unittest tests.test_generic -v
```

Sign the file "myfile.bin" and emit the armoured signature to stdout.

```bash
$ python3 -m pgpkms sign --input myfile.bin
```
