"""Golden endpoint case table.

Each GoldenCase issues one HTTP request. Tokens are the fixed keys created by
the seed_golden management command. Mutation cases (POST/DELETE) each act on a
dedicated seed row so a single run stays deterministic.
"""
import io
import json

ALICE_TOKEN = "a1ce000000000000000000000000000000000001"
BOB_TOKEN = "b0b0000000000000000000000000000000000002"

UPLOAD_BODY = json.dumps({"seed": "upload_payload", "version": 1})


class GoldenCase(object):
    def __init__(self, case_id, method, path, token=None, data=None,
                 files=None, allow_redirects=False, json_body=None):
        self.id = case_id
        self.method = method
        self.path = path
        self.token = token
        self.data = data
        self.files = files
        self.allow_redirects = allow_redirects
        self.json_body = json_body

    def execute(self, http, base_url):
        headers = {}
        if self.token:
            headers["Authorization"] = "Token " + self.token
        files = None
        if self.files:
            files = {k: (fn, io.BytesIO(content), ct)
                     for k, (fn, content, ct) in self.files.items()}
        return http.request(
            self.method, base_url + self.path,
            headers=headers, data=self.data, files=files, json=self.json_body,
            allow_redirects=self.allow_redirects, timeout=30,
        )


GOLDEN_CASES = [
    # HTML pages (index, login, signup, validate, the CSRF-failure page) are
    # NOT golden cases: a SHA-256 of rendered HTML is too brittle across a
    # Django major-version jump. They are covered by content assertions in
    # test_behavioral.py instead.

    # --- redirects / status-only ---
    GoldenCase("user_data_view_anon", "GET", "/user_data/"),

    # --- auth required, unauthenticated ---
    GoldenCase("sync_data_list_anon", "GET", "/sync_data_list/"),
    GoldenCase("user_data_list_anon", "GET", "/user_data_list/"),

    # --- authenticated reads ---
    GoldenCase("sync_data_list_alice", "GET", "/sync_data_list/", token=ALICE_TOKEN),
    GoldenCase("user_list_alice", "GET", "/user_list/", token=ALICE_TOKEN),
    GoldenCase("sharing_list_alice", "GET", "/sharing_list/", token=ALICE_TOKEN),
    GoldenCase("user_view_bob_by_alice", "GET", "/user/1002/", token=ALICE_TOKEN),
    GoldenCase("user_data_list_alice", "GET", "/user_data_list/", token=ALICE_TOKEN),
    GoldenCase("user_data_list_alice_deleted", "GET", "/user_data_list/?deleted=1", token=ALICE_TOKEN),

    # --- content API (same-stack; old stack lacks these routes) ---
    GoldenCase("content_bookmarks_alice", "GET", "/api/content/bookmarks/", token=ALICE_TOKEN),
    GoldenCase("content_bookmarks_anon", "GET", "/api/content/bookmarks/"),
    GoldenCase("content_summary_alice", "GET", "/api/content/summary/", token=ALICE_TOKEN),

    # --- public canon API (same-stack; old stack lacks these routes; no auth) ---
    GoldenCase("canon_editions", "GET", "/api/canon/editions/"),
    GoldenCase("canon_search", "GET", "/api/canon/search/?edition=thai&query=golden"),
    GoldenCase("canon_passage", "GET", "/api/canon/passage/?edition=thai&volume=1&page=1"),
    GoldenCase("canon_dictionary", "GET", "/api/canon/dictionary/?term=golden&dictionary=pali_thai&match=exact"),
    GoldenCase("canon_search_unknown_edition", "GET", "/api/canon/search/?edition=nope&query=x"),

    # --- OAuth / remote MCP discovery (same-stack; deterministic JSON) ---
    GoldenCase("oauth_as_metadata", "GET", "/.well-known/oauth-authorization-server"),
    GoldenCase("mcp_resource_metadata", "GET", "/.well-known/oauth-protected-resource/mcp"),
    GoldenCase("mcp_unauthenticated", "POST", "/mcp"),

    # --- passkeys (same-stack; old stack lacks these routes) ---
    GoldenCase("apple_app_site_association", "GET", "/.well-known/apple-app-site-association"),
    GoldenCase("assetlinks_unset", "GET", "/.well-known/assetlinks.json"),
    GoldenCase("passkey_login_begin", "POST", "/api/passkeys/login/begin/", json_body={}),
    GoldenCase("desktop_begin", "POST", "/api/passkeys/desktop/begin/", json_body={}),
    GoldenCase("desktop_poll_bad_code", "POST", "/api/passkeys/desktop/poll/",
               json_body={"device_code": "nope"}),
    GoldenCase("passkey_login_finish_bad_challenge", "POST", "/api/passkeys/login/finish/",
               json_body={"challenge_id": "nope", "credential": {}}),
    GoldenCase("passkeys_list_anon", "GET", "/api/passkeys/"),
    GoldenCase("passkeys_list_alice", "GET", "/api/passkeys/", token=ALICE_TOKEN),

    # --- file downloads (body stored as md5 by normalizer) ---
    GoldenCase("download_sync_data_alice", "GET", "/sync_data/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("download_sync_data_404", "GET", "/sync_data/nope.json/", token=ALICE_TOKEN),
    GoldenCase("download_user_data_shared", "GET", "/user/1002/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("download_user_data_denied", "GET", "/user/9999/sync_alice.json/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_get", "GET", "/user_data/3001/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_get_deleted", "GET", "/user_data/3002/", token=ALICE_TOKEN),

    # --- rest-auth login (token key is the fixed seed value -> deterministic) ---
    GoldenCase("rest_login_alice", "POST", "/rest-auth/login/",
               data={"username": "alice", "password": "alicepass123"}),
    GoldenCase("rest_login_bad", "POST", "/rest-auth/login/",
               data={"username": "alice", "password": "wrongpass"}),

    # --- mutations (each on its own dedicated row / target) ---
    GoldenCase("follower_add", "POST", "/follower/1002/", token=ALICE_TOKEN),
    GoldenCase("follower_remove", "DELETE", "/follower/1002/", token=ALICE_TOKEN),
    GoldenCase("user_data_action_delete", "DELETE", "/user_data/3001/", token=ALICE_TOKEN),
    GoldenCase("upload_view_post", "POST", "/upload/", token=ALICE_TOKEN,
               data={"title": "golden"},
               files={"file": ("upload_payload.json",
                               UPLOAD_BODY.encode("utf-8"), "application/json")}),
    GoldenCase("upload_sync_data_post", "POST", "/sync_data/", token=ALICE_TOKEN,
               data={"platform": "ios", "timestamp": "2020-01-05T00:00:00+00:00"},
               files={"file": ("sync_golden.json",
                               UPLOAD_BODY.encode("utf-8"), "application/json")}),
]
