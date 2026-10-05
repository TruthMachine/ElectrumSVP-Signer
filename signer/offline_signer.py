import json
import tkinter as tk

import qrcode
from PIL import Image, ImageTk

from bitcoinx import BIP32PrivateKey

from electrumsv.bitcoin import base_encode
from electrumsv.keystore import bip39_to_seed
from electrumsv.networks import Net
from electrumsv.qrscanner import scan_barcode
from electrumsv.transaction import Transaction

from signer.signer_protocol import apply_signing_response
from signer.transaction_signer import offline_sign


EXPECTED_XPUB = (
    "xpub661MyMwAqRbcGcjYPWCZNgbbkMgpyCQaGQw6GSqR4BZA2XH5oG1EG9zQc18FVz1RaG7vjKM8xYVm9uuyDezSmcdwRxJTESQRebhCJPbV2tT"
)


def main():
    print("ElectrumSVP Offline Signer")
    print("==========================")
    print()

    print("Waiting for signing request QR...")
    print()

    signing_request = scan_barcode(
        max_duration=60
    )

    if not signing_request:
        raise ValueError(
            "No signing request QR was received"
        )

    print()
    print(
        f"Decoded signing request: "
        f"{len(signing_request.encode('utf-8'))} bytes"
    )

    request = json.loads(signing_request)

    print()
    print("Signing request received:")
    print(f"Protocol:   {request.get('protocol')}")
    print(f"Version:    {request.get('version')}")
    print(f"Derivation: {request.get('derivation')}")
    print()

    mnemonic = input(
        "Enter test BIP39 seed: "
    ).strip()

    if not mnemonic:
        raise ValueError("No seed entered")

    # ------------------------------------------------------------
    # Diagnostic: independently derive the account xpub from the
    # BIP39 mnemonic using m/44'/0'/0'.
    # ------------------------------------------------------------

    bip32_seed = bip39_to_seed(
        mnemonic,
        None,
    )

    master_key = BIP32PrivateKey.from_seed(
        bip32_seed,
        Net.COIN,
    )

    account_key = master_key

    account_derivation = (
        44 | 0x80000000,
        0 | 0x80000000,
        0 | 0x80000000,
    )

    for index in account_derivation:
        account_key = account_key.child_safe(index)

    derived_xpub = (
        account_key.public_key.to_extended_key_string()
    )

    print()
    print("MNEMONIC DERIVATION TEST")
    print("------------------------")
    print("Path:           m/44'/0'/0'")
    print(f"Derived xpub:   {derived_xpub}")
    print(f"Expected xpub:  {EXPECTED_XPUB}")

    if derived_xpub == EXPECTED_XPUB:
        print("RESULT:          MATCH")
    else:
        print("RESULT:          NO MATCH")

    print()

    # ------------------------------------------------------------
    # Continue with the normal signing process.
    # ------------------------------------------------------------

    print("Passing signing request to offline signer...")
    print()

    response = offline_sign(
        signing_request,
        mnemonic,
    )

    print()
    print("SIGNER RESPONSE")
    print("----------------")
    print(response)

    signed_tx = apply_signing_response(
        signing_request,
        response,
    )

    original_tx = Transaction.from_dict(
        json.loads(signing_request)["transaction"]
    )

    original_signature_count = sum(
        1
        for txin in original_tx.inputs
        for signature in txin.signatures
        if signature != b"\xff"
    )

    signed_signature_count = sum(
        1
        for txin in signed_tx.inputs
        for signature in txin.signatures
        if signature != b"\xff"
    )

    if signed_signature_count <= original_signature_count:
        raise ValueError(
            "Signer response did not add a valid signature"
        )

    response = json.dumps(
        signed_tx.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )

    print()
    print("SIGNED TRANSACTION JSON:")
    print(response)
    print()

    response = base_encode(
        response.encode("utf-8"),
        base=43,
    )

    print()

    if signed_tx.is_complete():
        print("Complete signed transaction created.")
    else:
        print("Partially signed transaction created.")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=4,
    )

    qr.add_data(response)
    qr.make(fit=True)

    print()
    print(
        f"Response size: "
        f"{len(response.encode('utf-8'))} bytes"
    )
    print(
        f"QR version: {qr.version}"
    )
    print(
        f"QR modules: "
        f"{qr.modules_count} x {qr.modules_count}"
    )

    image = qr.make_image().convert("RGB")

    output_path = "signer/signing_response.png"
    image.save(output_path)

    print(
        f"Response QR image created: "
        f"{output_path}"
    )
    print(
        "Opening response QR on screen..."
    )

    root = tk.Tk()
    root.title(
        "ElectrumSVP Signer Response"
    )

    display_size = 400

    display_image = image.resize(
        (display_size, display_size),
        Image.Resampling.NEAREST,
    )

    photo = ImageTk.PhotoImage(
        display_image
    )

    label = tk.Label(
        root,
        image=photo,
    )
    label.pack(
        padx=20,
        pady=20,
    )

    info = tk.Label(
        root,
        text=(
            "ElectrumSVP signer response\n"
            f"{len(response.encode('utf-8'))} bytes"
        ),
        font=("Sans", 12),
    )
    info.pack(
        pady=(0, 20)
    )

    root.mainloop()


if __name__ == "__main__":
    main()

