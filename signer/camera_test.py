from electrumsv.qrscanner import scan_barcode


print("ElectrumSVP Camera QR Test")
print("==========================")
print()
print("Point the camera at signer/signing_request.png")
print("Press the close/stop control when finished.")
print()

result = scan_barcode(max_duration=60)

print()
print("Camera result:")
print(result)
