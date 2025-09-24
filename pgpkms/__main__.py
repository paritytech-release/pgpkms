import os
import sys

from botocore import session as aws
from getopt import getopt, GetoptError
from inspect import cleandoc

from .pgpkms import KmsPgpKey

def __help():
  cmd = os.getenv('PGP_KMS_ARGV0', sys.argv[0])
  cmd = 'python3 -m pgpkms' if cmd == __file__ else cmd

  sys.exit(cleandoc('''\
    Usage: {cmd} <command> [options]

    Commands:
      export     Export the public key in a PGP-compatible format.
      sign       Sing some data and write a detached PGP signature.
      message    Wrap a plaintext in a PGP message and sign it.

    Options:
      -o, --output=<file>    Use the specified file as output instead of stdout.
      -i, --input <file>     Use the specified file as input instead of stdin.
      -b,--binary            Do not armour the output (igored for "message").
      --sha[256|384|512]     Use the specified hashing algorithm.


    Environment Variables (can also be set via command line options):
      PGP_KMS_KEY            The default ID, ARN, alias, or resource name of the key to use.
      PGP_KMS_HASH           The hashing algorithm to use (default to "sha256").
      GPG_KEY_EXPIRATION     Expiration of the key, in days
      GPG_KEY_FINGERPRINT    Set this to make less calls to KMS (long format GPG key fingerprint)

      For AWS KMS:
        AWS_ACCESS_KEY_ID        AWS Service account key id
        AWS_SECRET_ACCESS_KEY    AWS Service account secret key
        AWS_DEFAULT_REGION       AWS Region of the key


      For Google Cloud KMS:
        GOOGLE_APPLICATION_CREDENTIALS  Path to service account key file


    Command Line Options for Environment Variables:
      --pgp-kms-key <key>                     Set PGP_KMS_KEY (key ID, ARN, alias, or resource name)
      --pgp-kms-hash <hash>                   Set PGP_KMS_HASH (hashing algorithm)
      --gpg-key-expiration <days>             Set GPG_KEY_EXPIRATION (expiration in days)
      --gpg-key-fingerprint <fingerprint>     Set GPG_KEY_FINGERPRINT (long format GPG key fingerprint)
      --aws-access-key-id <id>                Set AWS_ACCESS_KEY_ID
      --aws-secret-access-key <secret>        Set AWS_SECRET_ACCESS_KEY
      --aws-default-region <region>           Set AWS_DEFAULT_REGION
      --google-application-credentials <path> Set GOOGLE_APPLICATION_CREDENTIALS


    Examples

      Export the (unarmoured) public key into the "trusted.gpg" file.
        $ {cmd} export --binary --output trusted.gpg

      Sign the file "myfile.bin" and emit the armoured signature to stdout.
        $ {cmd} sign --input myfile.bin

  '''.format(cmd = cmd)) + os.linesep)

# ==============================================================================

def __export(key, hash, input = None, output = None, armoured = True):
  exp_days = int(os.environ.get('GPG_KEY_EXPIRATION', 0))

  key = KmsPgpKey(key)
  pgp_key = key.to_pgp(armoured = armoured, 
                       hash = hash, 
                       expiration = exp_days
                      )

  o = open(output, 'wb') if output else sys.stdout.buffer
  o.write(pgp_key)
  o.close()

  sys.exit(0)

# ==============================================================================

def __sign(key, hash, input = None, output = None, armoured = True):
  key = KmsPgpKey(key)

  i = open(input, 'rb') if input else sys.stdin.buffer

  signature = key.sign(i, armoured = armoured, hash = hash)

  o = open(output, 'wb') if output else sys.stdout.buffer
  o.write(signature)
  o.close()

  sys.exit(0)

# ==============================================================================

def __message(key, hash, input = None, output = None, armoured = True):
  key = KmsPgpKey(key)

  i = open(input, 'r') if input else sys.stdin # text reads!
  o = open(output, 'wb') if output else sys.stdout.buffer # write binary!

  signature = key.message(i, o, hash = hash)

  sys.exit(0)

# ==============================================================================

if __name__ == '__main__':
  if len(sys.argv) < 2:
    __help()

  command = sys.argv[1]

  if not(command in [ 'help', 'export', 'sign', 'message' ]):
    sys.exit('Error: command "%s" unknown' % (command))
  elif command == 'help':
    __help()

  kms_key = os.environ.get('PGP_KMS_KEY')
  hash = os.environ.get('PGP_KMS_HASH', 'sha256')
  input = None
  output = None
  armoured = True


  try:
    (options, rest) = getopt(sys.argv[2:], 'o:i:b', [
      'output=', 'input=', 'binary',
      'sha256', 'sha384', 'sha512',
      'pgp-kms-key=',
      'pgp-kms-hash=',
      'gpg-key-expiration=',
      'gpg-key-fingerprint=',
      'aws-access-key-id=', 'aws-secret-access-key=', 'aws-default-region=',
  'google-application-credentials=',


    ])

    if len(rest) > 0:
      sys.exit('Error: unknown option "%s"' % (rest[0]))

    for key, value in options:
      if key in [ '-b', '--binary' ]:
        armoured = False
      elif key in [ '-i', '--input' ]:
        input = value
      elif key in [ '-o' , '--output' ]:
        output = value
      elif key in [ '--sha256', '--sha384', '--sha512' ]:
        hash = key[2:]
      elif key == '--pgp-kms-key':
        os.environ['PGP_KMS_KEY'] = value
        kms_key = value
      elif key == '--pgp-kms-hash':
        os.environ['PGP_KMS_HASH'] = value
        hash = value
      elif key == '--gpg-key-expiration':
        os.environ['GPG_KEY_EXPIRATION'] = value
      elif key == '--gpg-key-fingerprint':
        os.environ['GPG_KEY_FINGERPRINT'] = value
      elif key == '--aws-access-key-id':
        os.environ['AWS_ACCESS_KEY_ID'] = value
      elif key == '--aws-secret-access-key':
        os.environ['AWS_SECRET_ACCESS_KEY'] = value
      elif key == '--aws-default-region':
        os.environ['AWS_DEFAULT_REGION'] = value
      elif key == '--google-application-credentials':
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = value



  except GetoptError as error:
    sys.exit('Error: %s' % (error))

  if kms_key == None:
    sys.exit('Error: no key ID specified')

  if not(hash in [ 'sha256', 'sha384', 'sha512' ]):
    sys.exit('Error: invalid hashing algorithm "%s"' % (hash))

  {
    'export': __export,
    'sign': __sign,
    'message': __message,
  }[command](
    key = kms_key,
    hash = hash,
    input = input,
    output = output,
    armoured = armoured
  )
