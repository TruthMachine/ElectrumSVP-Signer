from pathlib import Path

import zxingcpp
from PIL import Image

from signer.protocol_test import UNSIGNED_TX
from signer.signer_protocol import create_signing_request


def main():
    image_path = Path("signer/signing_request.png")

    print("ElectrumSVP Signer QR Decode Test")
    print("================================")
    print()

    expected = create_signing_request(UNSIGNED_TX)

    print(f"Expected payload: {len(expected.encode('utf-8'))} bytes")
    print(f"QR image: {image_path}")
    print()

    image = Image.open(image_path)

    results = zxingcpp.read_barcodes(image)

    if not results:
        print("FAILURE: No QR code detected.")
        return

    print(f"QR codes detected: {len(results)}")
    print()

    result = results[0]

    decoded = result.text

    print(f"Decoded payload: {len(decoded.encode('utf-8'))} bytes")
    print()

    if decoded == expected:
        print("SUCCESS: Decoded payload exactly matches original request.")
    else:
        print("FAILURE: Decoded payload does not match original request.")
        print()
        print("Decoded payload:")
        print(decoded)


if __name__ == "__main__":
    main()
