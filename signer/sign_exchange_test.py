import getpass

from bitcoinx import BIP32PrivateKey
from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net
from electrumsv.transaction import Transaction


ACCOUNT_DERIVATION = (
    44 | 0x80000000,
    236 | 0x80000000,
    0 | 0x80000000,
)


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
    print("ElectrumSVP Signer Exchange POC")
    print("================================")
    print()

    print("Enter the test BIP39 seed.")
    print("The seed is entered interactively and is not stored.")
    print()

    mnemonic = getpass.getpass("BIP39 seed: ")

    # ------------------------------------------------------------
    # OFFLINE SIGNER
    # ------------------------------------------------------------

    bip32_seed = bip39_to_seed(mnemonic, None)

    master_key = BIP32PrivateKey.from_seed(
        bip32_seed,
        Net.COIN,
    )

    account_key = master_key

    for index in ACCOUNT_DERIVATION:
        account_key = account_key.child_safe(index)

    print()
    print("Signer account derivation: m/44'/236'/0'")
    print()

    private_key_0 = derive_private_key(
        account_key,
        (0, 1),
    )

    private_key_1 = derive_private_key(
        account_key,
        (1, 0),
    )

    print("Signer derived public keys:")
    print()
    print("Input 0:", private_key_0.public_key.to_hex())
    print("Input 1:", private_key_1.public_key.to_hex())
    print()

    # ------------------------------------------------------------
    # TRANSACTION SIDE
    #
    # This represents the unsigned transaction prepared by
    # ElectrumSVP on the online machine.
    # ------------------------------------------------------------

    tx = Transaction.from_dict(UNSIGNED_TX)

    print("Transaction loaded.")
    print("Initial complete:", tx.is_complete())
    print()

    # ------------------------------------------------------------
    # SIGNING REQUEST
    #
    # In the eventual air-gapped implementation, the transaction
    # side would send the required signing information to the
    # offline signer.
    #
    # For this POC we already have the Transaction object locally.
    # The important point is that the signer returns signatures,
    # not a completed transaction.
    # ------------------------------------------------------------

    print("Creating signing request...")
    print()

    # Use ElectrumSVP's own preimage/signing implementation to
    # produce the signatures. This is the cryptographic operation
    # that will eventually happen on the offline device.
    signature_0_with_sighash = tx._sign_txin(
        tx.inputs[0],
        private_key_0.to_bytes(),
    )

    signature_1_with_sighash = tx._sign_txin(
        tx.inputs[1],
        private_key_1.to_bytes(),
    )

    # update_signatures() expects the raw DER signatures without
    # the final SIGHASH byte.
    signature_0 = signature_0_with_sighash[:-1]
    signature_1 = signature_1_with_sighash[:-1]

    print("OFFLINE SIGNER RESULT")
    print("---------------------")
    print()
    print("Input 0 signature:")
    print(signature_0.hex())
    print()
    print("Input 1 signature:")
    print(signature_1.hex())
    print()

    # ------------------------------------------------------------
    # RETURN TO TRANSACTION SIDE
    # ------------------------------------------------------------

    print("Returning signatures to transaction side...")
    print()

    signatures = [
        signature_0,
        signature_1,
    ]

    tx.update_signatures(signatures)

    print("Transaction complete:", tx.is_complete())
    print()

    if tx.is_complete():
        print("SUCCESS: Signatures were accepted by ElectrumSVP.")
        print()
        print("Signed transaction:")
        print(tx.serialize())
    else:
        print("FAILURE: Transaction is still incomplete.")


if __name__ == "__main__":
    main()
