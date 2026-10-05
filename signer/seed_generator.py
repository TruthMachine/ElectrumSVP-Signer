from electrumsv.keystore import bip39_is_checksum_valid
from electrumsv.mnemonic import generate_bip39_seed


SUPPORTED_WORD_COUNTS = (12, 24)


def generate_recovery_phrase(num_words=24):
    """
    Generate a new BIP39 recovery phrase using ElectrumSVP's
    existing secure BIP39 generator.

    The generated phrase is validated before being returned.
    """

    if num_words not in SUPPORTED_WORD_COUNTS:
        raise ValueError(
            "Recovery phrase must contain 12 or 24 words"
        )

    mnemonic = generate_bip39_seed(num_words)

    if len(mnemonic.split()) != num_words:
        raise ValueError(
            "BIP39 generator returned an unexpected word count"
        )

    is_valid, is_checksum_valid = bip39_is_checksum_valid(mnemonic)

    if not is_valid or not is_checksum_valid:
        raise ValueError(
            "Generated BIP39 recovery phrase failed validation"
        )

    return mnemonic