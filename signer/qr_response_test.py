import json
from pathlib import Path

import qrcode
import zxingcpp
from PIL import Image

from protocol_test import UNSIGNED_TX

from signer.signer_protocol import (
    apply_signing_response,
    create_signing_request,
)

from signer.transaction_signer import offline_sign

def main():
    print("ElectrumSVP Two-Way QR Test")
    print("===========================")
    print()

    # ------------------------------------------------------------
    # Step 1: Create the signing request.
    # ------------------------------------------------------------

    signing_request = create_signing_request(UNSIGNED_TX)

    print(
        f"Signing request: "
        f"{len(signing_request.encode('utf-8'))} bytes"
    )

    # ------------------------------------------------------------
    # Step 2: Offline signer receives the request and signs it.
    # ------------------------------------------------------------

    import getpass

    mnemonic = getpass.getpass(
        "Enter test BIP39 seed: "
    ).strip()

    if not mnemonic:
        print("FAILURE: No seed entered.")
        return

    print()
    print("Signing transaction...")
    print()

    signing_response = offline_sign(
        signing_request,
        mnemonic,
    )

    print()
    print("Signer response created.")
    print(
        f"Response size: "
        f"{len(signing_response.encode('utf-8'))} bytes"
    )
    print()

    # ------------------------------------------------------------
    # Step 3: Encode the signer response as a QR.
    # ------------------------------------------------------------

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=4,
    )

    qr.add_data(signing_response)
    qr.make(fit=True)

    print(f"Response QR version: {qr.version}")
    print(f"Response QR modules: {qr.modules_count} x {qr.modules_count}")
    print()

    image = qr.make_image().convert("RGB")

    output_path = Path("signer/signing_response.png")
    image.save(output_path)

    print(f"Response QR created: {output_path}")
    print()

    # ------------------------------------------------------------
    # Step 4: Decode the response QR.
    # ------------------------------------------------------------

    print("Decoding response QR...")

    results = zxingcpp.read_barcodes(image)

    if not results:
        print("FAILURE: No QR code detected.")
        return

    if len(results) != 1:
        print(
            f"FAILURE: Expected 1 QR code, found {len(results)}."
        )
        return

    decoded_response = results[0].text

    print(
        f"Decoded response: "
        f"{len(decoded_response.encode('utf-8'))} bytes"
    )
    print()

    if decoded_response != signing_response:
        print(
            "FAILURE: Decoded response differs from "
            "original signer response."
        )
        return

    print("Response QR decoded exactly.")
    print()

    # ------------------------------------------------------------
    # Step 5: Apply the response on the online side.
    # ------------------------------------------------------------

    print("Applying signer response...")
    print()

    transaction = apply_signing_response(
        signing_request,
        decoded_response,
    )

    # ------------------------------------------------------------
    # Step 6: Verify the final transaction.
    # ------------------------------------------------------------

    print()
    print(f"Transaction complete: {transaction.is_complete()}")
    print()

    if not transaction.is_complete():
        print("FAILURE: Transaction is still incomplete.")
        return

    print("Final signed transaction:")
    print(transaction.to_hex())
    print()

    expected_hex = (
        "010000000223628c3a0cf7daa895574c1fb929aa3dac4b96f7de6ec0a4b3c5b2cb27395222000000006a4730440220495c2364419abf7d4a0802be773a16742f446185a89d2e3ec948accd48a074e2022020bef564144c867b432484b118353ad4ba6bad6cd294ea7999cdf62dc58fc8e241210270b04a88b2930c05ec95891119ee39fde0fe2ac33f97d4f8dc74db8c36fa3960ffffffff23628c3a0cf7daa895574c1fb929aa3dac4b96f7de6ec0a4b3c5b2cb27395222010000006a473044022022dd0d5294fd58529d051d118f85935a44cf87f6578e2bea71f93ceb8055b42102202f3f6b46c0932b4c308b997dd8d77c6d96b06b50cbbe2ec7a76efa96b3f015f3412102d11fab4dd66860dd7e379fb7005307506cd754715430a59afc52ba2a7b8d6bd5ffffffff013a581300000000001976a91431d80cc1ec65ba64508eaac44d8daeb7e29929ce88acdec30e00"
    )

    if transaction.to_hex() != expected_hex:
        print("FAILURE: Final transaction does not match expected TX.")
        return

    print("SUCCESS: Final transaction exactly matches known-good TX.")
    print()
    print("SUCCESS: Two-way QR signing protocol completed.")


if __name__ == "__main__":
    main()
