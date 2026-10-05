import hashlib
import json

from bitcoinx import BIP32PrivateKey

from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net
from electrumsv.transaction import (
    Transaction,
    XPublicKeyType,
    tx_output_to_display_text,
)


DEFAULT_ACCOUNT_DERIVATION_PATH = "m/44'/0'/0'"


def parse_derivation_path(path_text):
    """
    Parse a BIP32 derivation path such as:

        m/44'/0'/0'

    Returns a tuple of integer BIP32 indexes.
    """

    if not isinstance(path_text, str):
        raise ValueError(
            "Account derivation path must be text."
        )

    path_text = path_text.strip()

    if not path_text:
        raise ValueError(
            "Account derivation path cannot be empty."
        )

    parts = path_text.split("/")

    if parts[0] != "m":
        raise ValueError(
            "Account derivation path must start with m/"
        )

    derivation = []

    for part in parts[1:]:
        if not part:
            raise ValueError(
                "Invalid account derivation path."
            )

        hardened = False

        if part.endswith("'"):
            hardened = True
            part = part[:-1]

        elif part.endswith("h") or part.endswith("H"):
            hardened = True
            part = part[:-1]

        if not part:
            raise ValueError(
                "Invalid account derivation path."
            )

        if not part.isdigit():
            raise ValueError(
                f"Invalid derivation index: {part}"
            )

        index = int(part)

        if index >= 0x80000000:
            raise ValueError(
                f"Derivation index is too large: {index}"
            )

        if hardened:
            index |= 0x80000000

        derivation.append(index)

    return tuple(derivation)


def transaction_fingerprint(tx):
    """
    SHA-256 fingerprint of the serialized transaction.
    """

    tx_hex = tx.to_hex()

    return hashlib.sha256(
        bytes.fromhex(tx_hex)
    ).hexdigest()


def mnemonic_fingerprint(mnemonic):
    """
    Safe diagnostic fingerprint of the exact mnemonic text.

    This does NOT print or return the mnemonic itself.
    """

    return hashlib.sha256(
        mnemonic.encode("utf-8")
    ).hexdigest()


def seed_fingerprint(seed):
    """
    Safe diagnostic fingerprint of the BIP39 seed bytes.
    """

    return hashlib.sha256(seed).hexdigest()


def derive_private_key(base_key, derivation_path):
    """
    Derive a transaction-specific private key from the supplied
    BIP32 base key using the relative BIP32 path stored in the
    transaction XPublicKey.
    """

    key = base_key

    for index in derivation_path:
        key = key.child_safe(index)

    return key


def derive_account_key(mnemonic, account_derivation_path):
    """
    Derive the BIP32 master key and account key from the mnemonic.

    IMPORTANT:

    The master key is the root BIP32 key corresponding to the
    transaction's master xpub.

    The account key is derived separately for diagnostics and
    normal account-path information.

    Transaction XPublicKeys must NOT automatically be assumed
    to be account-level xpubs.
    """

    seed = bip39_to_seed(
        mnemonic,
        None,
    )

    master_key = BIP32PrivateKey.from_seed(
        seed,
        Net.COIN,
    )

    account_indexes = parse_derivation_path(
        account_derivation_path
    )

    account_key = master_key

    for index in account_indexes:
        account_key = account_key.child_safe(index)

    return seed, master_key, account_key


def review_transaction(tx):
    print()
    print("TRANSACTION REVIEW")
    print("-------------------")

    total_input = 0

    for i, txin in enumerate(tx.inputs):
        value = txin.value
        total_input += value

        print(
            f"Input {i}: {value:,} sats"
        )

    total_output = 0

    for i, txout in enumerate(tx.outputs):
        value = txout.value
        total_output += value

        display_text, _ = tx_output_to_display_text(
            txout
        )

        print()
        print(f"Output {i}:")
        print(f"    {value:,} sats")
        print(f"    To: {display_text}")

    fee = total_input - total_output

    print()
    print(
        f"Total inputs:  {total_input:,} sats"
    )
    print(
        f"Total outputs: {total_output:,} sats"
    )
    print(
        f"Fee:           {fee:,} sats"
    )
    print()


def sign_approved_transaction(
    tx,
    mnemonic,
    approved_fingerprint,
    account_derivation_path=DEFAULT_ACCOUNT_DERIVATION_PATH,
):
    """
    Sign an already-approved transaction.

    The signer supports transaction XPublicKeys rooted at either:

        1. The account-level BIP32 key
           account_key + transaction relative path

        2. The BIP32 master key
           master_key + transaction relative path

    The signer determines which one is correct by deriving the
    private key and verifying that its public key exactly matches
    the public key recorded in the transaction.

    This allows the signer to support both regular BIP32 accounts
    and multisig transactions.
    """

    mnemonic = mnemonic.strip()

    if not mnemonic:
        raise ValueError(
            "Mnemonic cannot be empty."
        )

    # ---------------------------------------------------------
    # SAFE MNEMONIC DIAGNOSTICS
    # ---------------------------------------------------------

    print()
    print("SIGNER MNEMONIC DIAGNOSTICS")
    print("---------------------------")

    print(
        f"Mnemonic word count: "
        f"{len(mnemonic.split())}"
    )

    print(
        f"Mnemonic fingerprint: "
        f"{mnemonic_fingerprint(mnemonic)}"
    )

    # ---------------------------------------------------------
    # DERIVE MASTER + ACCOUNT KEYS
    # ---------------------------------------------------------

    bip32_seed, master_key, account_key = derive_account_key(
        mnemonic,
        account_derivation_path,
    )

    print(
        f"BIP39 seed fingerprint: "
        f"{seed_fingerprint(bip32_seed)}"
    )

    # In this bitcoinX version, public_key is a property
    # on BIP32PrivateKey, not a method.
    master_xpub = (
        master_key.public_key.to_extended_key_string()
    )

    account_xpub = (
        account_key.public_key.to_extended_key_string()
    )

    print(
        f"Account derivation path: "
        f"{account_derivation_path}"
    )

    print()

    # ---------------------------------------------------------
    # TRANSACTION XPUB MATCHING
    # ---------------------------------------------------------

    private_keys = []

    for input_index, txin in enumerate(tx.inputs):

        if not txin.x_pubkeys:
            raise ValueError(
                f"Input {input_index} contains no public keys"
            )

        unused_x_pubkeys = txin.unused_x_pubkeys()

        # A complete input does not need another signature.
        if not unused_x_pubkeys:
            private_keys.append(None)
            continue

        matching_private_key = None

        print(
            f"INPUT {input_index} XPUBLICKEYS"
        )
        print(
            "-------------------------------"
        )

        for xpub_index, x_pubkey in enumerate(
            unused_x_pubkeys
        ):

            if x_pubkey.kind() != XPublicKeyType.BIP32:
                print(
                    f"  XPublicKey {xpub_index}: "
                    f"not BIP32, skipping"
                )
                continue

            transaction_xpub = (
                x_pubkey.bip32_extended_key()
            )

            derivation_path = tuple(
                x_pubkey.derivation_path()
            )

            expected_pubkey = (
                x_pubkey.to_public_key().to_hex()
            )

            print(
                f"  XPublicKey {xpub_index}:"
            )

            print(
                f"      transaction xpub: "
                f"{transaction_xpub}"
            )

            print(
                f"      transaction path: "
                f"{derivation_path}"
            )

            print(
                f"      transaction pubkey: "
                f"{expected_pubkey}"
            )

            # -------------------------------------------------
            # TRY ACCOUNT-LEVEL XPUB
            # -------------------------------------------------

            if transaction_xpub == account_xpub:

                print(
                    "      ACCOUNT XPUB MATCH: YES"
                )

                private_key = derive_private_key(
                    account_key,
                    derivation_path,
                )

                actual_pubkey = (
                    private_key.public_key.to_hex()
                )

                print(
                    f"      derived pubkey: "
                    f"{actual_pubkey}"
                )

                if actual_pubkey == expected_pubkey:

                    print(
                        "      ACCOUNT DERIVATION MATCH: YES"
                    )

                    if matching_private_key is not None:
                        raise ValueError(
                            "Multiple unused transaction keys "
                            "match the supplied signing seed "
                            f"for input {input_index}"
                        )

                    matching_private_key = private_key

                    print()
                    continue

                print(
                    "      ACCOUNT DERIVATION MATCH: NO"
                )

            else:
                print(
                    "      ACCOUNT XPUB MATCH: NO"
                )

            # -------------------------------------------------
            # TRY MASTER XPUB
            # -------------------------------------------------

            if transaction_xpub == master_xpub:

                print(
                    "      MASTER XPUB MATCH: YES"
                )

                private_key = derive_private_key(
                    master_key,
                    derivation_path,
                )

                actual_pubkey = (
                    private_key.public_key.to_hex()
                )

                print(
                    f"      derived pubkey: "
                    f"{actual_pubkey}"
                )

                if actual_pubkey == expected_pubkey:

                    print(
                        "      MASTER DERIVATION MATCH: YES"
                    )

                    if matching_private_key is not None:
                        raise ValueError(
                            "Multiple unused transaction keys "
                            "match the supplied signing seed "
                            f"for input {input_index}"
                        )

                    matching_private_key = private_key

                    print()
                    continue

                print(
                    "      MASTER DERIVATION MATCH: NO"
                )

            else:
                print(
                    "      MASTER XPUB MATCH: NO"
                )

            print()

        print()

        if matching_private_key is None:
            raise ValueError(
                "The supplied signing seed does not match "
                "any unused BIP32 signing key for input "
                f"{input_index}"
            )

        private_keys.append(
            matching_private_key
        )

    # ---------------------------------------------------------
    # APPROVAL / TAMPER CHECK
    # ---------------------------------------------------------

    current_fingerprint = transaction_fingerprint(
        tx
    )

    if current_fingerprint != approved_fingerprint:
        raise ValueError(
            "Transaction changed after user approval; "
            "refusing to sign"
        )

    # ---------------------------------------------------------
    # CREATE SIGNATURES
    # ---------------------------------------------------------

    signatures = []

    for input_index, (txin, private_key) in enumerate(
        zip(tx.inputs, private_keys)
    ):

        # Preserve an existing signature for an already
        # complete input.
        if private_key is None:

            existing_signatures = (
                txin.signatures_present()
            )

            if not existing_signatures:
                raise ValueError(
                    f"Input {input_index} is complete but "
                    "contains no existing signatures"
                )

            signatures.append(
                existing_signatures[0][:-1].hex()
            )

            continue

        signature_with_sighash = tx._sign_txin(
            txin,
            private_key.to_bytes(),
        )

        # update_signatures() adds the SIGHASH byte itself.
        signature = signature_with_sighash[:-1]

        signatures.append(
            signature.hex()
        )

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


def offline_sign(
    signing_request,
    mnemonic,
):
    """
    Command-line signing interface.

    The account derivation path is retained in the signing
    request for compatibility and diagnostics.

    Transaction signing itself uses the xpub and relative
    derivation path contained in each transaction XPublicKey.
    """

    request = json.loads(
        signing_request
    )

    if request.get("protocol") != "electrumsvp-signer":
        raise ValueError(
            "Unknown signing protocol"
        )

    if request.get("version") != 1:
        raise ValueError(
            "Unsupported signing protocol version"
        )

    derivation = request.get(
        "derivation",
        DEFAULT_ACCOUNT_DERIVATION_PATH,
    )

    parse_derivation_path(
        derivation
    )

    transaction_data = request.get(
        "transaction"
    )

    if transaction_data is None:
        raise ValueError(
            "Signing request contains no transaction"
        )

    tx = Transaction.from_dict(
        transaction_data
    )

    approved_fingerprint = transaction_fingerprint(
        tx
    )

    review_transaction(
        tx
    )

    print(
        f"Account derivation path: {derivation}"
    )

    print(
        f"Transaction fingerprint: "
        f"{approved_fingerprint}"
    )

    confirmation = input(
        "Sign this transaction? [y/N]: "
    ).strip().lower()

    if confirmation != "y":
        print("Signing cancelled.")
        raise SystemExit(0)

    return sign_approved_transaction(
        tx,
        mnemonic,
        approved_fingerprint,
        derivation,
    )
