# ki-keyring

Utility for ejecting/injecting sets of obfuscated public keys ("keyring" structures) from/into WizardGraphicalClient binaries.

## Usage

It assumes the game client is located at the default Windows installation path but it can be overridden with `--bin`.

The `eject` subcommand will print the keyring of the game client in JSON format. The `private` field for each key in the keyring will be set to `null` as this information isn't obtainable.
```sh
$ ki-keyring eject
{...}
$ ki-keyring eject --bin path/to/WizardGraphicalClient.exe
{...}
```

The `inject` subcommand will generate new RSA keypairs and inject the public keys into the game client. The `private` field for each key in the keyring will also reflect the new RSA private keys.
```sh
$ ki-keyring inject
{...}
$ ki-keyring inject --bin path/to/WizardGraphicalClient.exe
{...}
```
