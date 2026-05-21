import hashlib
import re

VOLATILE_HEADERS = {
    "date", "server", "set-cookie", "vary", "content-length",
    "connection", "keep-alive", "x-frame-options",
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
            else:
                out[key] = normalize_json_value(val)
        return out
    if isinstance(value, list):
        return [normalize_json_value(v) for v in value]
    if isinstance(value, str):
        return TIMESTAMP_RE.sub("<TIMESTAMP>", value)
    return value


def normalize_response(resp):
    headers = {k.lower(): v for k, v in resp.headers.items()
               if k.lower() not in VOLATILE_HEADERS}
    content_type = resp.headers.get("Content-Type", "")
    if "application/json" in content_type:
        body = {"json": normalize_json_value(resp.json())}
    elif "text/html" in content_type:
        stripped = CSRF_RE.sub('name="csrfmiddlewaretoken" value="<CSRF>"', resp.text)
        body = {"html_sha256": hashlib.sha256(stripped.encode("utf-8")).hexdigest()}
    else:
        body = {"body_sha256": hashlib.sha256(resp.content).hexdigest()}
    return {"status": resp.status_code, "headers": headers, "body": body}
