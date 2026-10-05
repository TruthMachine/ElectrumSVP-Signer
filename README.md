# ElectrumSVP Signer

ElectrumSVP Signer is an air-gapped Bitcoin SV transaction signing application designed to keep private keys offline.

It is designed to work with ElectrumSVP and compatible wallet software by transferring unsigned and signed transactions between an online computer and the offline signer using animated QR codes.

## Features

- Air-gapped transaction signing
- BIP39 seed generation
- Multisignature transaction support
- Animated QR transaction transfer
- Transaction and destination verification before signing
- LUKS-encrypted storage for protecting signing data
- Encrypted offline wallet storage
- Session locking and storage locking
- Runs without an internet connection

## Supported Platforms

Pre-built releases are currently available for:

- Windows
- macOS
- Linux

The signer is designed to run on a dedicated offline computer or other isolated environment.

## Releases

Official releases and pre-built binaries are published through the GitHub Releases page.

Each release includes SHA-256 checksums and PGP signatures for verifying the downloaded files.

## Security

ElectrumSVP Signer is intended to be used as an offline signing device. Signing data can be stored on a LUKS-encrypted device, providing an additional layer of protection for the signer's wallet data when the storage device is locked.

For maximum security:

1. Install and configure the signer on a computer that will remain offline.
2. Generate the signing seed on the offline signer.
3. Store signing data on a LUKS-encrypted device when appropriate.
4. Transfer unsigned transactions to the signer using QR codes or another offline transfer method.
5. Verify the transaction details on the signer before approving it.
6. Transfer the signed transaction back to the online wallet.
7. Keep the signing device offline except when performing necessary maintenance.

Always verify release signatures and checksums before installing a release.

## Source Code

The source code for ElectrumSVP Signer is provided in this repository.

The repository also contains source code derived from ElectrumSV/Electrum and other upstream components. Existing copyright notices and license terms in individual source files remain applicable.

## Status

ElectrumSVP Signer is under active development.

This is an early release and should be used with appropriate care when handling valuable funds.
