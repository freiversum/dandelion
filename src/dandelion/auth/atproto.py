# SPDX-License-Identifier: GPL-3.0-or-later
"""OAuth für das AT Protocol (Bluesky): PAR, PKCE, DPoP, Token-Erneuerung.

Dandelion ist ein öffentlicher nativer Client. Die Metadaten liegen unter
`CLIENT_ID`, die Weiterleitung geht an eine Loopback-Adresse
(`http://127.0.0.1:PORT/callback`, der Port wird beim Abgleich ignoriert).
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from dataclasses import dataclass, field
from gettext import gettext as _
from typing import Any

from ..net.http import HttpClient, NetworkError, Request, Response
from .dpop import DpopKey
from .oauth import OAuthError, Pkce, new_state

CLIENT_ID = "https://linuxundich.de/dandelion/oauth/client-metadata.json"
SCOPE = "atproto transition:generic transition:chat.bsky"
# Öffentliche Clients: Sitzung und Refresh-Token halten höchstens zwei Wochen
SESSION_DAYS = 14


@dataclass
class ServerMeta:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    par_endpoint: str
    revocation_endpoint: str | None = None
    iss_in_response: bool = False


@dataclass
class PendingAtproto:
    """Zustand zwischen Browser-Aufruf und Rückkehr."""

    handle: str
    did: str
    pds: str
    meta: ServerMeta
    key: DpopKey
    pkce: Pkce
    state: str
    redirect_uri: str
    request_uri: str
    nonces: dict[str, str] = field(default_factory=dict)

    def authorize_url(self) -> str:
        query = urllib.parse.urlencode({"client_id": CLIENT_ID, "request_uri": self.request_uri})
        return f"{self.meta.authorization_endpoint}?{query}"


def _origin(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


class DpopSession:
    """Sendet Anfragen mit DPoP-Beweis und merkt sich die Nonce je Server."""

    def __init__(self, http: HttpClient, key: DpopKey,
                 nonces: dict[str, str] | None = None) -> None:
        self.http = http
        self.key = key
        self.nonces = nonces if nonces is not None else {}

    async def send(self, req: Request, access_token: str | None = None) -> Response:
        origin = _origin(req.url)
        resp: Response | None = None
        for attempt in (1, 2):
            headers = dict(req.headers)
            headers["DPoP"] = self.key.proof(req.method, req.url, nonce=self.nonces.get(origin),
                                             access_token=access_token)
            if access_token:
                headers["Authorization"] = f"DPoP {access_token}"
            sent = Request(**{**req.__dict__, "headers": headers})
            resp = await self.http.send(sent)
            nonce = resp.headers.get("dpop-nonce")
            if nonce:
                self.nonces[origin] = nonce
            if attempt == 1 and nonce and _needs_nonce(resp):
                continue
            break
        assert resp is not None
        return resp


def _needs_nonce(resp: Response) -> bool:
    if resp.status not in (400, 401):
        return False
    if "use_dpop_nonce" in resp.headers.get("www-authenticate", ""):
        return True
    try:
        return (resp.json() or {}).get("error") == "use_dpop_nonce"
    except (ValueError, AttributeError):
        return False


class AtprotoOAuth:
    def __init__(self, http: HttpClient) -> None:
        self.http = http

    # -- Server finden -------------------------------------------------------
    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            resp = await self.http.send(Request("GET", url, timeout=15))
        except NetworkError as e:
            raise OAuthError(_("The Bluesky server could not be reached.")) from e
        if not resp.ok:
            raise OAuthError(_("The Bluesky server does not support this sign-in."))
        try:
            data = resp.json()
        except ValueError as e:
            raise OAuthError(_("The Bluesky server does not support this sign-in.")) from e
        if not isinstance(data, dict):
            raise OAuthError(_("The Bluesky server does not support this sign-in."))
        return data

    async def discover(self, pds: str) -> ServerMeta:
        resource = await self._get_json(f"{pds}/.well-known/oauth-protected-resource")
        servers = resource.get("authorization_servers") or []
        if len(servers) != 1:
            raise OAuthError(_("The Bluesky server does not support this sign-in."))
        issuer = str(servers[0]).rstrip("/")
        meta = await self._get_json(f"{issuer}/.well-known/oauth-authorization-server")
        if str(meta.get("issuer", "")).rstrip("/") != issuer:
            raise OAuthError(_("The Bluesky server does not support this sign-in."))
        scopes = meta.get("scopes_supported") or ["atproto"]
        if ("atproto" not in scopes or "S256" not in (meta.get("code_challenge_methods_supported")
                                                      or [])
                or not meta.get("pushed_authorization_request_endpoint")
                or "ES256" not in (meta.get("dpop_signing_alg_values_supported") or [])):
            raise OAuthError(_("The Bluesky server does not support this sign-in."))
        return ServerMeta(
            issuer=issuer,
            authorization_endpoint=meta["authorization_endpoint"],
            token_endpoint=meta["token_endpoint"],
            par_endpoint=meta["pushed_authorization_request_endpoint"],
            revocation_endpoint=meta.get("revocation_endpoint"),
            iss_in_response=bool(meta.get("authorization_response_iss_parameter_supported")))

    # -- Anmeldung -----------------------------------------------------------
    async def begin(self, handle: str, did: str, pds: str, redirect_uri: str) -> PendingAtproto:
        meta = await self.discover(pds)
        pending = PendingAtproto(
            handle=handle, did=did, pds=pds, meta=meta, key=DpopKey.generate(),
            pkce=Pkce.create(), state=new_state(), redirect_uri=redirect_uri, request_uri="")
        session = DpopSession(self.http, pending.key, pending.nonces)
        try:
            resp = await session.send(Request(
                "POST", meta.par_endpoint, form={
                    "client_id": CLIENT_ID, "response_type": "code", "scope": SCOPE,
                    "redirect_uri": redirect_uri, "state": pending.state,
                    "code_challenge": pending.pkce.challenge,
                    "code_challenge_method": pending.pkce.method,
                    "login_hint": handle if not handle.startswith("did:") else did}))
        except NetworkError as e:
            raise OAuthError(_("The Bluesky server could not be reached.")) from e
        data = _json(resp)
        if not resp.ok or not data.get("request_uri"):
            raise OAuthError(_("Bluesky did not accept the sign-in request: {reason}").format(
                reason=data.get("error_description") or data.get("error") or resp.status))
        pending.request_uri = data["request_uri"]
        return pending

    async def finish(self, pending: PendingAtproto, params: dict[str, str]) -> dict[str, Any]:
        """Tauscht den Code gegen Tokens. Liefert die Zugangsdaten zum Speichern."""
        if params.get("error"):
            raise OAuthError(_("The server denied the sign-in: {reason}").format(
                reason=params.get("error_description") or params["error"]))
        if params.get("state") != pending.state:
            raise OAuthError(_("The sign-in response did not match. Please try again."))
        iss = params.get("iss")
        if (iss or pending.meta.iss_in_response) and (iss or "").rstrip("/") != pending.meta.issuer:
            raise OAuthError(_("The sign-in response did not match. Please try again."))
        if not params.get("code"):
            raise OAuthError(_("The sign-in response did not match. Please try again."))
        session = DpopSession(self.http, pending.key, pending.nonces)
        tokens = await self._token(session, pending.meta, {
            "grant_type": "authorization_code", "code": params["code"],
            "redirect_uri": pending.redirect_uri, "code_verifier": pending.pkce.verifier,
            "client_id": CLIENT_ID})
        if tokens.get("sub") != pending.did:
            raise OAuthError(_("The sign-in response did not match. Please try again."))
        return self.secret_from(pending.pds, pending.did, pending.meta, pending.key, tokens)

    # -- Tokens --------------------------------------------------------------
    async def _token(self, session: DpopSession, meta: ServerMeta,
                     form: dict[str, str]) -> dict[str, Any]:
        try:
            resp = await session.send(Request("POST", meta.token_endpoint, form=form))
        except NetworkError as e:
            raise OAuthError(_("The Bluesky server could not be reached.")) from e
        data = _json(resp)
        if not resp.ok:
            err = data.get("error", "")
            if err == "invalid_grant":
                raise OAuthSessionEnded(_("The Bluesky sign-in has expired. Please sign in "
                                          "again."))
            raise OAuthError(_("Bluesky did not accept the sign-in: {reason}").format(
                reason=data.get("error_description") or err or resp.status))
        if "atproto" not in str(data.get("scope", "")).split() or not data.get("access_token") \
                or str(data.get("token_type", "")).lower() != "dpop":
            raise OAuthError(_("Bluesky did not accept the sign-in: {reason}").format(
                reason="scope"))
        return data

    @staticmethod
    def secret_from(pds: str, did: str, meta: ServerMeta, key: DpopKey,
                    tokens: dict[str, Any], old: dict[str, Any] | None = None) -> dict[str, Any]:
        now = time.time()
        secret = dict(old or {})
        secret.update({
            "pds": pds, "did": did, "issuer": meta.issuer,
            "token_endpoint": meta.token_endpoint,
            "revocation_endpoint": meta.revocation_endpoint,
            "dpop_key": key.to_jwk(private=True),
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token") or (old or {}).get("refresh_token", ""),
            "expires_at": now + float(tokens.get("expires_in", 900)),
        })
        secret.setdefault("session_started", now)
        return secret

    async def refresh(self, secret: dict[str, Any],
                      nonces: dict[str, str] | None = None) -> dict[str, Any]:
        if not secret.get("refresh_token"):
            raise OAuthSessionEnded(_("The Bluesky sign-in has expired. Please sign in again."))
        key = DpopKey.from_jwk(secret["dpop_key"])
        meta = ServerMeta(issuer=secret["issuer"], authorization_endpoint="",
                          token_endpoint=secret["token_endpoint"], par_endpoint="",
                          revocation_endpoint=secret.get("revocation_endpoint"))
        tokens = await self._token(DpopSession(self.http, key, nonces), meta, {
            "grant_type": "refresh_token", "refresh_token": secret["refresh_token"],
            "client_id": CLIENT_ID})
        if tokens.get("sub") not in (None, secret["did"]):
            raise OAuthError(_("The sign-in response did not match. Please try again."))
        return self.secret_from(secret["pds"], secret["did"], meta, key, tokens, old=secret)

    async def revoke(self, secret: dict[str, Any]) -> None:
        endpoint = secret.get("revocation_endpoint")
        if not endpoint or not secret.get("refresh_token"):
            return
        try:
            await self.http.send(Request("POST", endpoint, form={
                "client_id": CLIENT_ID, "token": secret["refresh_token"],
                "token_type_hint": "refresh_token"}, timeout=10))
        except NetworkError:
            pass


class OAuthSessionEnded(OAuthError):
    """Refresh-Token abgelaufen oder widerrufen: neu anmelden."""


def _json(resp: Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


_locks: dict[str, asyncio.Lock] = {}


def refresh_lock(uuid: str) -> asyncio.Lock:
    """Refresh-Tokens gelten nur einmal: Erneuerungen je Profil nacheinander."""
    return _locks.setdefault(uuid, asyncio.Lock())
