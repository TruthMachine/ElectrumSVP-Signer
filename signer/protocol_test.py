import getpass
import json

from electrumsv.transaction import Transaction

from signer.signer_protocol import (
    apply_signing_response,
    create_signing_request,
)
from signer.transaction_signer import offline_sign

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



def main():
    print("ElectrumSVP Signer Protocol POC")
    print("================================")
    print()

    print("This test simulates:")
    print()
    print("ONLINE MACHINE")
    print("    -> serialized signing request")
    print("    -> OFFLINE SIGNER")
    print("    -> serialized signature response")
    print("    -> ONLINE MACHINE")
    print()

    print("Enter the test BIP39 seed.")
    print("The seed is entered interactively and is not stored.")
    print()

    mnemonic = getpass.getpass("BIP39 seed: ")

    # --------------------------------------------------------------
    # ONLINE: create serialized signing request
    # --------------------------------------------------------------

    signing_request = create_signing_request(UNSIGNED_TX)

    print()
    print("Signing request created.")
    print("Request size:", len(signing_request), "bytes")
    print()

    # --------------------------------------------------------------
    # OFFLINE: receive request and sign
    # --------------------------------------------------------------

    print("OFFLINE SIGNER")
    print("--------------")
    print()

    signing_response = offline_sign(
        signing_request,
        mnemonic,
    )

    print("Signing response created.")
    print("Response:")
    print(signing_response)
    print()

    # --------------------------------------------------------------
    # ONLINE: receive signatures
    # --------------------------------------------------------------

    print("ONLINE TRANSACTION SIDE")
    print("-----------------------")
    print()

    tx = apply_signing_response(
        signing_request,
        signing_response,
    )

    print("Transaction complete:", tx.is_complete())
    print()

    if tx.is_complete():
        print("SUCCESS: Serialized signer protocol completed.")
        print()
        print("Signed transaction:")
        print(tx.serialize())
    else:
        print("FAILURE: Transaction is still incomplete.")


if __name__ == "__main__":
    main()
