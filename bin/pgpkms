#!/bin/bash

test -f "/etc/default/pgpkms" && {
  set -a
  source "/etc/default/pgpkms"
  set +a
}

PGP_KMS_ARGV0="${0}" python3 -m "pgpkms" "${@}"
