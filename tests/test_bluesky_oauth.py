# SPDX-License-Identifier: GPL-3.0-or-later
"""Bluesky-OAuth gegen einen Attrappen-Server (PAR, DPoP, Nonce, Refresh)."""

import base64
import hashlib
import json
import time
import urllib.parse

import pytest
from helpers import setup_world

from dandelion.auth import atproto
from dandelion.auth.dpop import DpopKey, b64url, b64url_decode, verify
from dandelion.auth.oauth import OAuthError
from dandelion.net.http import Response
from dandelion.platforms.base import PlatformError

PDS = "https://pds.example"
AS = "https://auth.example"
REDIRECT = "http://127.0.0.1:5555/callback"


def split_jwt(token):
    head, body, sig = token.split(".")
    return (json.loads(b64url_decode(head)), json.loads(b64url_decode(body)),
            b64url_decode(sig), (head + "." + body).encode())


def check_proof(token, method, url, *, nonce=None, access_token=None):
    head, claims, sig, signing = split_jwt(token)
    assert head["typ"] == "dpop+jwt" and head["alg"] == "ES256"
    assert verify(head["jwk"], signing, sig)
    assert claims["htm"] == method and claims["htu"] == url.split("?")[0]
    assert abs(claims["iat"] - time.time()) < 60
    if nonce:
        assert claims["nonce"] == nonce
    if access_token:
        assert claims["ath"] == b64url(hashlib.sha256(access_token.encode()).digest())
    else:
        assert "ath" not in claims
    return head["jwk"]


# -- DPoP-Schlüssel ----------------------------------------------------------
def test_signature_roundtrip_and_tamper():
    key = DpopKey.generate()
    sig = key.sign(b"hello")
    assert len(sig) == 64 and verify(key.to_jwk(), b"hello", sig)
    assert not verify(key.to_jwk(), b"hellO", sig)
    assert not verify(DpopKey.generate().to_jwk(), b"hello", sig)


def test_jwk_roundtrip():
    key = DpopKey.generate()
    again = DpopKey.from_jwk(key.to_jwk(private=True))
    assert verify(key.to_jwk(), b"x", again.sign(b"x"))
    assert "d" not in key.to_jwk()
    broken = key.to_jwk(private=True)
    broken["y"] = b64url(b"\x01" * 32)
    with pytest.raises(ValueError):
        DpopKey.from_jwk(broken)


def test_signature_checked_by_independent_implementation():
    ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
    hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")
    utils = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.utils")
    key = DpopKey.generate()
    pub = ec.EllipticCurvePublicNumbers(key.x, key.y, ec.SECP256R1()).public_key()
    sig = key.sign(b"payload")
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                     int.from_bytes(sig[32:], "big"))
    pub.verify(der, b"payload", ec.ECDSA(hashes.SHA256()))
    # und umgekehrt: Signatur der Bibliothek, von uns geprüft
    priv = ec.derive_private_key(key.d, ec.SECP256R1())
    r, s = utils.decode_dss_signature(priv.sign(b"other", ec.ECDSA(hashes.SHA256())))
    assert verify(key.to_jwk(), b"other", r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def test_proof_claims():
    key = DpopKey.generate()
    check_proof(key.proof("post", "https://x.example/a/b?q=1#f", nonce="n1", access_token="tok"),
                "POST", "https://x.example/a/b", nonce="n1", access_token="tok")


# -- Attrappen-Server -------------------------------------------------------
class FakeAuthServer:
    """Verlangt beim ersten Aufruf je Server eine Nonce, prüft DPoP und PKCE."""

    def __init__(self, http, *, did="did:plc:abc", sub=None):
        self.http = http
        self.did = did
        self.sub = sub or did
        self.nonce = "nonce-1"
        self.challenge = None
        self.code_verifier_ok = None
        self.refresh_tokens = {}
        self.jwk = None
        self.counter = 0
        self.fail_refresh = False
        self.calls = []
        http.add("GET", f"{PDS}/.well-known/oauth-protected-resource",
                 {"authorization_servers": [AS]})
        http.add("GET", f"{AS}/.well-known/oauth-authorization-server", {
            "issuer": AS, "authorization_endpoint": f"{AS}/authorize",
            "token_endpoint": f"{AS}/token", "revocation_endpoint": f"{AS}/revoke",
            "pushed_authorization_request_endpoint": f"{AS}/par",
            "scopes_supported": ["atproto", "transition:generic"],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "authorization_response_iss_parameter_supported": True})
        http.add("POST", f"{AS}/par", self.par)
        http.add("POST", f"{AS}/token", self.token)
        http.add("POST", f"{AS}/revoke", lambda req: Response(200, {}, b"{}", req.url))
        http.add("GET", "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
                 {"did": did})
        http.add("GET", f"https://plc.directory/{did}", {"service": [
            {"id": "#atproto_pds", "serviceEndpoint": PDS}]})
        http.add("GET", f"{PDS}/xrpc/app.bsky.actor.getProfile", self.profile)

    def _dpop(self, req):
        proof = req.headers["DPoP"]
        jwk = check_proof(proof, req.method, req.url.split("?")[0],
                          access_token=req.headers.get("Authorization", "").removeprefix("DPoP ")
                          or None)
        if self.jwk is None:
            self.jwk = jwk
        assert jwk == self.jwk, "key changed"
        claims = split_jwt(proof)[1]
        if claims.get("nonce") != self.nonce:
            body = json.dumps({"error": "use_dpop_nonce"}).encode()
            return Response(400, {"dpop-nonce": self.nonce}, body, req.url)
        return None

    def par(self, req):
        self.calls.append("par")
        if (bad := self._dpop(req)):
            return bad
        self.par_form = dict(req.form)
        self.challenge = req.form["code_challenge"]
        assert req.form["code_challenge_method"] == "S256"
        assert req.form["client_id"] == atproto.CLIENT_ID
        assert "atproto" in req.form["scope"].split()
        return Response(201, {"dpop-nonce": self.nonce},
                        json.dumps({"request_uri": "urn:par:1", "expires_in": 60}).encode(),
                        req.url)

    def token(self, req):
        self.calls.append(req.form["grant_type"])
        if (bad := self._dpop(req)):
            return bad
        form = req.form
        if form["grant_type"] == "authorization_code":
            digest = hashlib.sha256(form["code_verifier"].encode()).digest()
            self.code_verifier_ok = b64url(digest) == self.challenge
            assert form["code"] == "code-1" and form["redirect_uri"] == REDIRECT
        else:
            if self.fail_refresh or form["refresh_token"] not in self.refresh_tokens:
                return Response(400, {"dpop-nonce": self.nonce}, json.dumps(
                    {"error": "invalid_grant"}).encode(), req.url)
            del self.refresh_tokens[form["refresh_token"]]      # nur einmal gültig
        self.counter += 1
        refresh = f"refresh-{self.counter}"
        self.refresh_tokens[refresh] = True
        return Response(200, {"dpop-nonce": self.nonce}, json.dumps({
            "access_token": f"access-{self.counter}", "token_type": "DPoP",
            "refresh_token": refresh, "expires_in": 600, "scope": "atproto transition:generic",
            "sub": self.sub}).encode(), req.url)

    def profile(self, req):
        auth = req.headers.get("Authorization", "")
        assert auth.startswith("DPoP access-"), auth
        if (bad := self._dpop(req)):
            return bad
        return Response(200, {}, json.dumps({
            "handle": "lui.bsky.social", "displayName": "Lui", "avatar": "https://a"}).encode(),
            req.url)


def login(http, run, **kw):
    store, secrets, reg, *_ = setup_world(http)
    server = FakeAuthServer(http, **kw)
    bsky = reg.get("bluesky")
    pending = run(bsky.begin_oauth("lui", REDIRECT))
    return server, bsky, secrets, pending


def callback(pending, **kw):
    return {"code": "code-1", "state": pending.state, "iss": AS, **kw}


def test_full_login(http, run):
    server, bsky, secrets, pending = login(http, run)
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(pending.authorize_url()).query)
    assert query == {"client_id": [atproto.CLIENT_ID], "request_uri": ["urn:par:1"]}
    assert pending.authorize_url().startswith(f"{AS}/authorize?")
    assert server.calls == ["par", "par"]                 # erster Versuch: Nonce verlangt
    assert server.par_form["login_hint"] == "lui.bsky.social"
    profile, secret = run(bsky.finish_oauth(pending, callback(pending)))
    assert server.code_verifier_ok
    assert profile.auth_method == "oauth" and profile.remote_id == "did:plc:abc"
    assert profile.display_name == "Lui" and profile.server == PDS
    assert profile.token_expires_at
    assert secret["access_token"] == "access-1" and secret["refresh_token"] == "refresh-1"
    assert secret["dpop_key"]["d"] and secret["issuer"] == AS


@pytest.mark.parametrize("params,reason", [
    ({"state": "other"}, "state"),
    ({"iss": "https://evil.example"}, "iss"),
    ({"error": "access_denied", "error_description": "nope"}, "denied"),
])
def test_callback_is_checked(http, run, params, reason):
    server, bsky, secrets, pending = login(http, run)
    with pytest.raises(OAuthError):
        run(bsky.finish_oauth(pending, callback(pending, **params)))
    assert "authorization_code" not in server.calls


def test_wrong_account_in_token_is_rejected(http, run):
    server, bsky, secrets, pending = login(http, run, sub="did:plc:other")
    with pytest.raises(OAuthError):
        run(bsky.finish_oauth(pending, callback(pending)))


def test_server_without_par_is_rejected(http, run):
    store, secrets, reg, *_ = setup_world(http)
    FakeAuthServer(http)
    http.add("GET", f"{AS}/.well-known/oauth-authorization-server", {
        "issuer": AS, "authorization_endpoint": f"{AS}/authorize",
        "token_endpoint": f"{AS}/token", "scopes_supported": ["atproto"]})
    with pytest.raises(OAuthError):
        run(reg.get("bluesky").begin_oauth("lui", REDIRECT))


def stored_profile(http, run):
    server, bsky, secrets, pending = login(http, run)
    profile, secret = run(bsky.finish_oauth(pending, callback(pending)))
    run(bsky.store_credentials(profile, secret))
    return server, bsky, secrets, profile


def test_xrpc_uses_dpop_with_token_hash_and_nonce(http, run):
    server, bsky, secrets, profile = stored_profile(http, run)
    http.add("POST", f"{PDS}/xrpc/com.atproto.repo.createRecord", lambda req: (
        server._dpop(req) or Response(200, {}, b'{"uri":"at://x/app.bsky.feed.post/1",'
                                               b'"cid":"c"}', req.url)))
    resp = run(bsky._xrpc(profile, "POST", "com.atproto.repo.createRecord", json={"a": 1}))
    assert resp.ok
    sent = http.find("POST", f"{PDS}/xrpc/com.atproto.repo.createRecord")
    assert [r.headers["Authorization"] for r in sent] == ["DPoP access-1"] * 2   # Nonce-Wiederholung
    assert not any("Bearer" in r.headers.get("Authorization", "") for r in sent)


def test_expired_token_is_refreshed_and_rotated(http, run):
    server, bsky, secrets, profile = stored_profile(http, run)
    data = run(secrets.get(profile.uuid, "oauth"))
    data["expires_at"] = time.time() - 5
    run(secrets.set(profile.uuid, "oauth", "l", data))
    http.add("GET", f"{PDS}/xrpc/app.bsky.actor.getProfile", server.profile)
    run(bsky._xrpc(profile, "GET", "app.bsky.actor.getProfile", params={"actor": "x"}))
    stored = run(secrets.get(profile.uuid, "oauth"))
    assert stored["access_token"] == "access-2" and stored["refresh_token"] == "refresh-2"
    assert server.calls.count("refresh_token") >= 1


def test_server_rejecting_token_triggers_one_refresh(http, run):
    server, bsky, secrets, profile = stored_profile(http, run)
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        if req.headers["Authorization"] == "DPoP access-1":
            return Response(401, {"www-authenticate": 'DPoP error="invalid_token"'},
                            b'{"error":"InvalidToken","message":"expired"}', req.url)
        return server._dpop(req) or Response(200, {}, b"{}", req.url)

    http.add("GET", f"{PDS}/xrpc/app.bsky.actor.getProfile", handler)
    assert run(bsky._xrpc(profile, "GET", "app.bsky.actor.getProfile")).ok
    assert run(secrets.get(profile.uuid, "oauth"))["access_token"] == "access-2"


def test_ended_session_asks_for_new_login(http, run):
    server, bsky, secrets, profile = stored_profile(http, run)
    data = run(secrets.get(profile.uuid, "oauth"))
    data["expires_at"] = 0
    run(secrets.set(profile.uuid, "oauth", "l", data))
    server.fail_refresh = True
    with pytest.raises(PlatformError) as e:
        run(bsky._session(profile))
    assert e.value.auth
    updated = run(bsky.refresh_profile(profile))
    assert str(updated.status) == "expired"


def test_concurrent_refresh_uses_token_once(http, run):
    import asyncio
    server, bsky, secrets, profile = stored_profile(http, run)
    data = run(secrets.get(profile.uuid, "oauth"))
    data["expires_at"] = 0
    run(secrets.set(profile.uuid, "oauth", "l", data))

    async def both():
        return await asyncio.gather(bsky._session(profile), bsky._session(profile))

    a, b = run(both())
    assert a["access_token"] == b["access_token"] == "access-2"
    assert server.calls.count("refresh_token") == 2        # Nonce-Wiederholung, ein Token


def test_logout_revokes_and_deletes(http, run):
    server, bsky, secrets, profile = stored_profile(http, run)
    run(bsky.logout(profile))
    assert http.find("POST", f"{AS}/revoke")
    assert run(secrets.get(profile.uuid, "oauth")) is None


def test_base64_helpers():
    assert b64url_decode(b64url(b"\xff\xfe")) == b"\xff\xfe"
    assert base64.urlsafe_b64encode(b"a") == b"YQ=="


def test_published_client_metadata_matches_code():
    from pathlib import Path
    meta = json.loads((Path(__file__).parents[1] / "docs/oauth/client-metadata.json").read_text())
    assert meta["client_id"] == atproto.CLIENT_ID and meta["scope"] == atproto.SCOPE
    assert meta["application_type"] == "native" and meta["dpop_bound_access_tokens"]
    assert meta["token_endpoint_auth_method"] == "none"
    assert urllib.parse.urlsplit(meta["client_uri"]).hostname == "linuxundich.de"
    # Loopback ohne Port; die Anwendung hängt den freien Port an
    assert REDIRECT.replace(":5555", "") in meta["redirect_uris"]
