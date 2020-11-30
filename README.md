# shh(1)

shh(1) manages secrets for projects and small teams. Secrets are encrypted and
safe to commit to version control software like git.

Unlike Hashicorp Vault, shh(1) requires no infrastructure. There's no server to
manage and secure -- just a single file.

## Install

```
$ git clone git@github.com/thankful-ai/shh && cd shh
$ make
$ sudo make install
```

After installation, check the man pages for usage information for shh(1).

## Encryption details

shh(1) uses envelope encryption to keep your project secrets secure. `gen-key`
creates 4096-bit RSA keys in your home directory, encrypting the private key
with a mandated 24-char minimum length password, which is long enough to
prevent re-use/memorization and forcing use of a password manager.

Each secret is encrypted with a random AES-256 key using GCM. The AES key is
encrypted using your RSA public key and stored alongside the secret.

## Security bulletins

### v1.8.0

As of v1.8.0, the following security vulnerability is fixed:

- Previously, secrets were vulnerable to a padding oracle attack, as our use of
  AES-CFB did not include any authentication mechanism. Switching to AES-GCM
  prevents this attack. You should regenerate any keys that were stored in .shh
  and shared.

## Future improvements

- Add tests
- v2: Use ssh-agent rather than homegrown server. Remove `shh serve` and `shh
  login`, `-n` non-interactive mode, memguard dependency
