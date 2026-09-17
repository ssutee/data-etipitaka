import hashlib
import re

# Only headers that reflect application behavior are compared. Everything else
# (Date, Server, Django security headers, transfer-encoding, cookies, ...) is
# framework/server framing that differs between the old and new stack without
# being a behavior change, so an allowlist is used rather than a denylist.
BEHAVIOR_HEADERS = {
    "content-type", "allow", "content-disposition",
    "location", "www-authenticate",
}
TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"
)
CSRF_RE = re.compile(r'name="csrfmiddlewaretoken"\s+value="[^"]+"')


def normalize_json_value(value):
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if key in ("created_at", "created"):
                out[key] = "<TIMESTAMP>"
            elif key in ("challenge", "challenge_id"):
                # WebAuthn challenges are random per request
                out[key] = "<CHALLENGE>"
            elif key == "pk":
                # top-level auto-increment ids are not deterministic across runs
                out[key] = "<PK>"
            else:
                out[key] = normalize_json_value(val)
        return out
    if isinstance(value, list):
        return [normalize_json_value(v) for v in value]
    if isinstance(value, str):
        return TIMESTAMP_RE.sub("<TIMESTAMP>", value)
    return value


def _normalize_headers(resp):
    headers = {}
    for key, value in resp.headers.items():
        low = key.lower()
        if low not in BEHAVIOR_HEADERS:
            continue
        if low == "allow":
            # HTTP method ordering in the Allow header is not meaningful
            value = ", ".join(sorted(m.strip() for m in value.split(",")))
        headers[low] = value
    return headers


def normalize_response(resp):
    headers = _normalize_headers(resp)
    content_type = resp.headers.get("Content-Type", "")
    if "application/json" in content_type:
        body = {"json": normalize_json_value(resp.json())}
    elif "text/html" in content_type:
        stripped = CSRF_RE.sub('name="csrfmiddlewaretoken" value="<CSRF>"', resp.text)
        body = {"html_sha256": hashlib.sha256(stripped.encode("utf-8")).hexdigest()}
    else:
        body = {"body_sha256": hashlib.sha256(resp.content).hexdigest()}
    return {"status": resp.status_code, "headers": headers, "body": body}
