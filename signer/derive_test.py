import getpass

from bitcoinx import BIP32PrivateKey
from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net


EXPECTED_KEYS = {
    (0, 1): "0270b04a88b2930c05ec95891119ee39fde0fe2ac33f97d4f8dc74db8c36fa3960",
    (1, 0): "02d11fab4dd66860dd7e379fb7005307506cd754715430a59afc52ba2a7b8d6bd5",
}


def derive_private_key(master_key, derivation_path):
    key = master_key

    for index in derivation_path:
        key = key.child_safe(index)

    return key


def main():
    print("ElectrumSVP Signer POC")
    print("======================")
    print()
    print("Enter the test BIP39 seed.")
    print("The seed is entered interactively and is not stored.")
    print()

    mnemonic = getpass.getpass("BIP39 seed: ")

    bip32_seed = bip39_to_seed(mnemonic, None)

    master_key = BIP32PrivateKey.from_seed(
        bip32_seed,
        Net.COIN
    )

    account_key = master_key

    for index in (
        44 | 0x80000000,
        236 | 0x80000000,
        0 | 0x80000000,
    ):
        account_key = account_key.child_safe(index)


    print()
    print("BIP44 account key created at m/44'/236'/0'.")
    print()

    all_match = True

    for derivation_path, expected_pubkey in EXPECTED_KEYS.items():
        private_key = derive_private_key(
            account_key,
            derivation_path
        )
        actual_pubkey = private_key.public_key.to_hex()

        print(f"Derivation path: {derivation_path}")
        print(f"Public key:      {actual_pubkey}")
        print(f"Expected key:    {expected_pubkey}")

        if actual_pubkey == expected_pubkey:
            print("RESULT:          MATCH")
        else:
            print("RESULT:          *** MISMATCH ***")
            all_match = False

        print()

    if all_match:
        print("SUCCESS: Both transaction keys match.")
        print()
        print("The BIP39 seed reproduces the keys expected by ElectrumSVP.")
    else:
        print("FAILURE: One or more keys did not match.")


if __name__ == "__main__":
    main()
