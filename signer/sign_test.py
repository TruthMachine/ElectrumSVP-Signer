import getpass

from bitcoinx import BIP32PrivateKey
from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net
from electrumsv.transaction import Transaction


ACCOUNT_DERIVATION = (44 | 0x80000000,
                      236 | 0x80000000,
                      0 | 0x80000000)


UNSIGNED_TX = {
    "version": 1,
    "hex": (
        "010000000223628c3a0cf7daa895574c1fb929aa3dac4b96f7de6ec0a4b3c5b2cb27395222"
        "000000002401ff210270b04a88b2930c05ec95891119ee39fde0fe2ac33f97d4f8dc74db8c"
        "36fa3960ffffffff23628c3a0cf7daa895574c1fb929aa3dac4b96f7de6ec0a4b3c5b2cb"
        "27395222010000002401ff2102d11fab4dd66860dd7e379fb7005307506cd754715430a59a"
        "fc52ba2a7b8d6bd5ffffffff013a581300000000001976a91431d80cc1ec65ba64508eaac"
        "44d8daeb7e29929ce88acdec30e00"
    ),
    "complete": False,
    "inputs": [
        {
            "script_type": 2,
            "threshold": 1,
            "value": 1267259,
            "signatures": ["ff"],
            "x_pubkeys": [
                {
                    "bip32_xpub": (
                        "xpub6DWsG5zowqPBv8zeJNNuUGeAMKyWd1nvHUVMMqRZCBKDpf1uUWAkCUH6knFzsRr2jpHvz51GfNw9L7WcJ871vaMF5kR9XasjxQDUpMQSYvi"
                    ),
                    "derivation_path": [0, 1],
                }
            ],
        },
        {
            "script_type": 2,
            "threshold": 1,
            "value": 546,
            "signatures": ["ff"],
            "x_pubkeys": [
                {
                    "bip32_xpub": (
                        "xpub6DWsG5zowqPBv8zeJNNuUGeAMKyWd1nvHUVMMqRZCBKDpf1uUWAkCUH6knFzsRr2jpHvz51GfNw9L7WcJ871vaMF5kR9XasjxQDUpMQSYvi"
                    ),
                    "derivation_path": [1, 0],
                }
            ],
        },
    ],
}


def derive_private_key(account_key, derivation_path):
    key = account_key
    for index in derivation_path:
        key = key.child_safe(index)
    return key


def main():
    print("ElectrumSVP Offline Signer POC")
    print("==============================")
    print()

    print("Enter the test BIP39 seed.")
    print("The seed is entered interactively and is not stored.")
    print()

    mnemonic = getpass.getpass("BIP39 seed: ")

    # Convert BIP39 mnemonic to the BIP32 seed.
    bip32_seed = bip39_to_seed(mnemonic, None)

    # Create the BIP32 master private key.
    master_key = BIP32PrivateKey.from_seed(
        bip32_seed,
        Net.COIN,
    )

    # Derive the account used by this test wallet.
    account_key = master_key

    for index in ACCOUNT_DERIVATION:
        account_key = account_key.child_safe(index)

    print()
    print("Account derivation: m/44'/236'/0'")
    print()

    # Derive the two private keys required by the transaction.
    private_key_0 = derive_private_key(
        account_key,
        (0, 1),
    )

    private_key_1 = derive_private_key(
        account_key,
        (1, 0),
    )

    print("Input 0 public key:")
    print(private_key_0.public_key.to_hex())
    print()

    print("Input 1 public key:")
    print(private_key_1.public_key.to_hex())
    print()

    # Load the unsigned transaction.
    tx = Transaction.from_dict(UNSIGNED_TX)

    print("Transaction loaded.")
    print("Initial complete:", tx.is_complete())
    print()

    # ElectrumSVP's XPublicKey objects are already attached to the
    # transaction inputs. Use those exact objects as the keypair map.
    xpub_0 = tx.inputs[0].x_pubkeys[0]
    xpub_1 = tx.inputs[1].x_pubkeys[0]

    keypairs = {
        xpub_0: (private_key_0.to_bytes(), True),
        xpub_1: (private_key_1.to_bytes(), True),
    }

    print("Signing transaction...")
    tx.sign(keypairs)

    print()
    print("Signature results:")
    print("------------------")

    for index, txin in enumerate(tx.inputs):
        print()
        print("Input:", index)
        print("Signature:", txin.signatures[0].hex())

    print()
    print("Complete:", tx.is_complete())

    if tx.is_complete():
        print()
        print("SUCCESS: Transaction was completely signed.")
        print()
        print("Signed transaction:")
        print(tx.serialize())
    else:
        print()
        print("FAILURE: Transaction is still incomplete.")


if __name__ == "__main__":
    main()
