import json
from pathlib import Path

import zxingcpp
from PIL import Image

from signer.signer_protocol import create_signing_request
from signer.transaction_signer import offline_sign
from signer.protocol_test import UNSIGNED_TX

def main():
    print("ElectrumSVP QR Signer Test")
    print("==========================")
    print()

    image_path = Path("signer/signing_request.png")

    if not image_path.exists():
        print(f"ERROR: QR image not found: {image_path}")
        return

    print(f"Reading QR image: {image_path}")
    print()

    image = Image.open(image_path)

    results = zxingcpp.read_barcodes(image)

    if not results:
        print("FAILURE: No QR code detected.")
        return

    if len(results) != 1:
        print(f"FAILURE: Expected 1 QR code, found {len(results)}.")
        return

    decoded = results[0].text

    print(f"Decoded payload: {len(decoded.encode('utf-8'))} bytes")
    print()

    # Verify that the decoded data is valid JSON.
    try:
        request = json.loads(decoded)
    except json.JSONDecodeError as e:
        print(f"FAILURE: QR payload is not valid JSON: {e}")
        return

    print("QR payload decoded successfully.")
    print(f"Protocol: {request.get('protocol')}")
    print(f"Version:  {request.get('version')}")
    print(f"Derivation: {request.get('derivation')}")
    print()

    # Compare against the original request.
    expected = create_signing_request(UNSIGNED_TX)

    if decoded != expected:
        print("FAILURE: Decoded QR payload differs from original request.")
        return

    print("QR payload exactly matches original request.")
    print()

    # Get the mnemonic without putting it on the command line.
    import getpass

    mnemonic = getpass.getpass(
        "Enter test BIP39 seed: "
    ).strip()

    if not mnemonic:
        print("FAILURE: No seed entered.")
        return

    print()
    print("Passing decoded QR request to offline signer...")
    print()

    response = offline_sign(decoded, mnemonic)

    print()
    print("SIGNER RESPONSE")
    print("----------------")
    print(response)


if __name__ == "__main__":
    main()
