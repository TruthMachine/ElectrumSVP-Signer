import json

from electrumsv.transaction import Transaction


def create_signing_request(transaction_data):
    """
    Create the serialized signing request sent to the offline signer.
    """
    request = {
        "protocol": "electrumsvp-signer",
        "version": 1,
        "transaction": transaction_data,
    }

    return json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
    )


def apply_signing_response(signing_request, signing_response):
    """
    Apply a serialized signer response to the transaction on the
    online side.
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

