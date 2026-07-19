import base64
import hashlib
import hmac
import json
import os

WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]

def _get_raw_body(event: dict) -> bytes:
    body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body)
    return body.encode("utf-8")

def verify(raw_body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected_signature = signature.removeprefix("sha256=")
    computed_signature = hmac.new(key=WEBHOOK_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_signature, expected_signature)

def handler(event, context):
    body = _get_raw_body(event)
    signature = event["headers"].get("x-hub-signature-256")

    if not verify(body, signature):
        print("signature verification failed")
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"message": "invalid signature"}),
        }

    payload = json.loads(body)
    print(json.dumps(payload))

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "ok"}),
    }