import getpass
import json

from bitcoinx import BIP32PrivateKey

from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net
from electrumsv.transaction import Transaction, tx_output_to_display_text
import hashlib

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


# ----------------------------------------------------------------------
# ONLINE SIDE
# ----------------------------------------------------------------------

def create_signing_request():
    """
    Create the serialized request that would eventually be sent to
    the offline signer by QR, USB, SD card, etc.
    """

    request = {
        "protocol": "electrumsvp-signer",
        "version": 1,
        "derivation": "m/44'/236'/0'",
        "transaction": UNSIGNED_TX,
    }

    return json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
    )


def review_transaction(tx):
    print()
    print("TRANSACTION REVIEW")
    print("-------------------")

    total_input = 0

    for i, txin in enumerate(tx.inputs):
        value = txin.value
        total_input += value

        print(f"Input {i}: {value:,} sats")

    total_output = 0

    for i, txout in enumerate(tx.outputs):
        value = txout.value
        total_output += value

        display_text, _ = tx_output_to_display_text(txout)

        print()
        print(f"Output {i}:")
        print(f"    {value:,} sats")
        print(f"    To: {display_text}")

    fee = total_input - total_output

    print()
    print(f"Total inputs:  {total_input:,} sats")
    print(f"Total outputs: {total_output:,} sats")
    print(f"Fee:           {fee:,} sats")
    print()


def transaction_fingerprint(tx):
    tx_hex = tx.to_hex()
    return hashlib.sha256(bytes.fromhex(tx_hex)).hexdigest()

# ----------------------------------------------------------------------
# OFFLINE SIDE
# ----------------------------------------------------------------------

def offline_sign(signing_request, mnemonic):
    """
    This function represents the isolated offline signer.

    It receives only the serialized signing request and the user's
    seed.

    The signing sequence is:

        1. Validate the request.
        2. Reconstruct the transaction.
        3. Validate all transaction public keys.
        4. Display the transaction.
        5. Ask the user for approval.
        6. Only after approval, generate signatures.
        7. Return the serialized signing response.
    """

    request = json.loads(signing_request)

    if request.get("protocol") != "electrumsvp-signer":
        raise ValueError("Unknown signing protocol")

    if request.get("version") != 1:
        raise ValueError("Unsupported signing protocol version")

    derivation = request.get("derivation")

    if derivation != "m/44'/236'/0'":
        raise ValueError(
            f"Unexpected derivation path: {derivation}"
        )

    transaction_data = request.get("transaction")

    if transaction_data is None:
        raise ValueError("Signing request contains no transaction")

    # Reconstruct a completely independent Transaction object from
    # the serialized request.
    tx = Transaction.from_dict(transaction_data)

    # Convert the BIP39 mnemonic to the BIP32 seed.
    bip32_seed = bip39_to_seed(mnemonic, None)

    # Create the BIP32 master private key.
    master_key = BIP32PrivateKey.from_seed(
        bip32_seed,
        Net.COIN,
    )

    # Derive the requested account.
    account_key = master_key

    for index in ACCOUNT_DERIVATION:
        account_key = account_key.child_safe(index)

    private_keys = []

    # --------------------------------------------------------------
    # Validate ALL transaction keys BEFORE showing the transaction
    # to the user.
    # --------------------------------------------------------------

    for txin in tx.inputs:
        if len(txin.x_pubkeys) != 1:
            raise ValueError(
                "POC currently expects exactly one xpub per input"
            )

        x_pubkey = txin.x_pubkeys[0]

        derivation_path = x_pubkey.derivation_path()

        if derivation_path is None:
            raise ValueError(
                "Input has no BIP32 derivation path"
            )

        derivation_path = tuple(derivation_path)

        private_key = derive_private_key(
            account_key,
            derivation_path,
        )

        actual_pubkey = private_key.public_key.to_hex()
        expected_pubkey = x_pubkey.to_public_key().to_hex()

        if actual_pubkey != expected_pubkey:
            raise ValueError(
                "Derived public key does not match transaction xpub"
            )

        private_keys.append(private_key)

    # --------------------------------------------------------------
    # All key checks passed.
    #
    # Only now show the transaction to the user.
    # --------------------------------------------------------------

    approved_fingerprint = transaction_fingerprint(tx)

    review_transaction(tx)

    print(f"Transaction fingerprint: {approved_fingerprint}")

    confirmation = input(
        "Sign this transaction? [y/N]: "
    ).strip().lower()


    if confirmation != "y":
        print()
        print("Signing cancelled.")
        raise SystemExit(0)

    print()
    print("!!! TEST ATTACK !!!")
    print("Changing the transaction AFTER user approval...")
    
    tx.outputs[0].value = 900000
    
    print("Transaction in memory has now been changed to:")
    print(f"    Output 0: {tx.outputs[0].value:,} sats")
    print()

    # --------------------------------------------------------------
    # ACTUAL SIGNING
    #
    # No cryptographic signature is generated until after explicit
    # user approval.
    # --------------------------------------------------------------

    current_fingerprint = transaction_fingerprint(tx)

    if current_fingerprint != approved_fingerprint:
        raise ValueError(
            "Transaction changed after user approval; refusing to sign"
        )


    signatures = []

    for txin, private_key in zip(tx.inputs, private_keys):
        signature_with_sighash = tx._sign_txin(
            txin,
            private_key.to_bytes(),
        )

        # update_signatures() expects the DER signature without the
        # final SIGHASH byte.
        signature = signature_with_sighash[:-1]

        signatures.append(signature.hex())

    response = {
        "protocol": "electrumsvp-signer",
        "version": 1,
        "signatures": signatures,
    }

    return json.dumps(
        response,
        sort_keys=True,
        separators=(",", ":"),
    )


# ----------------------------------------------------------------------
# ONLINE SIDE
# ----------------------------------------------------------------------

def apply_signing_response(signing_request, signing_response):
    """
    Represents the online ElectrumSVP side receiving the response
    from the offline signer.
    """

    request = json.loads(signing_request)
    response = json.loads(signing_response)

    if response.get("protocol") != request.get("protocol"):
        raise ValueError("Protocol mismatch")

    if response.get("version") != request.get("version"):
        raise ValueError("Protocol version mismatch")

    signatures_hex = response.get("signatures")

    if signatures_hex is None:
        raise ValueError("Signing response contains no signatures")

    transaction_data = request["transaction"]

    tx = Transaction.from_dict(transaction_data)

    signatures = [
        bytes.fromhex(signature)
        for signature in signatures_hex
    ]

    tx.update_signatures(signatures)

    return tx


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

    signing_request = create_signing_request()

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
