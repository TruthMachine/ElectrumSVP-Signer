import tkinter as tk

import qrcode
from PIL import Image, ImageTk

from signer.protocol_test import UNSIGNED_TX
from signer.signer_protocol import create_signing_request


def main():
    print("ElectrumSVP Signer QR Test")
    print("==========================")
    print()

    signing_request = create_signing_request(UNSIGNED_TX)

    print(f"Request size: {len(signing_request.encode('utf-8'))} bytes")
    print()

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=4,
    )

    qr.add_data(signing_request)
    qr.make(fit=True)

    print(f"QR version: {qr.version}")
    print(f"QR modules: {qr.modules_count} x {qr.modules_count}")
    print()

    image = qr.make_image().convert("RGB")

    output_path = "signer/signing_request.png"
    image.save(output_path)

    print(f"QR image created: {output_path}")
    print()
    print("Opening QR on screen...")
    print("Scan the QR with another camera/device.")
    print("Close the window when finished.")

    root = tk.Tk()
    root.title("ElectrumSVP Signer Request")

    # Scale the QR to a practical display size.
    display_size = 400

    display_image = image.resize(
        (display_size, display_size),
        Image.Resampling.NEAREST,
    )

    photo = ImageTk.PhotoImage(display_image)

    label = tk.Label(root, image=photo)
    label.pack(padx=20, pady=20)

    info = tk.Label(
        root,
        text=(
            f"ElectrumSVP signer request\n"
            f"{len(signing_request.encode('utf-8'))} bytes"
        ),
        font=("Sans", 12),
    )
    info.pack(pady=(0, 20))

    root.mainloop()


if __name__ == "__main__":
    main()
