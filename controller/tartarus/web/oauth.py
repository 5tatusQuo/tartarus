from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt

from ..errors import AuthenticationRequired, TartarusError
from ..util import atomic_json, load_json, utc_now

ISSUER = "https://auth.openai.com"
AUTHORIZE_ENDPOINT = f"{ISSUER}/api/accounts/authorize"
TOKEN_ENDPOINT = f"{ISSUER}/api/accounts/oauth/token"
DISCOVERY_ENDPOINT = f"{ISSUER}/.well-known/openid-configuration"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
LONG_RUNNING_TOKEN_MARGIN = timedelta(minutes=30)


@dataclass(frozen=True)
class PendingAuthorization:
    state: str
    nonce: str
    verifier: str
    redirect_uri: str
    client_id: str
    expires_at: datetime


class ChatGPTAuth:
    """Open-source Sign in with ChatGPT flow with protected local credentials."""

    def __init__(self, cache_root: Path):
        self.root = cache_root / "secrets" / "chatgpt"
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.host_path = self.root / "host.json"
        self.credential_path = self.root / "active.json"
        self._pending: PendingAuthorization | None = None
        self._lock = threading.RLock()

    def status(self) -> dict[str, Any]:
        record = self._load_credentials()
        if not record:
            return {"connected": False, "email": None, "expires_at": None, "plan_usage": False}
        return {
            "connected": True,
            "email": record.get("email"),
            "expires_at": record.get("expires_at"),
            "plan_usage": "chatgpt.tokens.use.direct" in record.get("scopes", []),
        }

    def begin(self, redirect_uri: str) -> str:
        if not redirect_uri.startswith("http://127.0.0.1:") or not redirect_uri.endswith(
            "/auth/chatgpt/callback"
        ):
            raise TartarusError("ChatGPT callback must use the configured loopback address")
        with self._lock:
            existing = self._load_credentials()
            client_id = existing.get("client_id") if existing else "dynamic_agent_client"
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(64)
            challenge = _base64url(hashlib.sha256(verifier.encode()).digest())
            self._pending = PendingAuthorization(
                state, nonce, verifier, redirect_uri, client_id, datetime.now(UTC) + timedelta(minutes=10)
            )
            values = {
                "client_id": client_id,
                "ext_agent_host_id": self._host_id(),
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": SCOPES,
                "resource": RESOURCE,
                "state": state,
                "nonce": nonce,
                "code_challenge_method": "S256",
                "code_challenge": challenge,
            }
            if client_id == "dynamic_agent_client":
                values["agent_name_hint"] = "Tartarus"
            elif existing:
                if existing.get("id_token"):
                    values["id_token_hint"] = existing["id_token"]
                if existing.get("email"):
                    values["login_hint"] = existing["email"]
            return AUTHORIZE_ENDPOINT + "?" + urllib.parse.urlencode(values)

    def complete(self, query: dict[str, str]) -> dict[str, Any]:
        with self._lock:
            pending = self._pending
            self._pending = None
            if not pending or datetime.now(UTC) >= pending.expires_at:
                raise TartarusError("ChatGPT authorization attempt expired")
            if not secrets.compare_digest(query.get("state", ""), pending.state):
                raise TartarusError("ChatGPT authorization state did not match")
            if query.get("error"):
                raise TartarusError("ChatGPT authorization was not completed")
            code = query.get("code")
            if not code:
                raise TartarusError("ChatGPT authorization code is missing")
            issued_client = query.get("client_id") or pending.client_id
            if pending.client_id == "dynamic_agent_client" and issued_client == pending.client_id:
                raise TartarusError("ChatGPT client registration was incomplete")
            if pending.client_id != "dynamic_agent_client" and issued_client != pending.client_id:
                raise TartarusError("ChatGPT returned a different registered client")
            token = self._post_form(
                TOKEN_ENDPOINT,
                {
                    "grant_type": "authorization_code",
                    "client_id": issued_client,
                    "code": code,
                    "code_verifier": pending.verifier,
                    "redirect_uri": pending.redirect_uri,
                    "resource": RESOURCE,
                },
            )
            identity = self._validate_id_token(token.get("id_token"), issued_client, pending.nonce)
            scopes = str(token.get("scope", "")).split()
            if "chatgpt.tokens.use.direct" not in scopes:
                raise TartarusError("ChatGPT plan usage permission was not granted")
            now = datetime.now(UTC)
            record = {
                "email": identity.get("email"),
                "subject": identity["sub"],
                "issuer": identity["iss"],
                "client_id": issued_client,
                "ext_agent_host_id": self._host_id(),
                "id_token": token["id_token"],
                "access_token": token["access_token"],
                "refresh_token": token["refresh_token"],
                "token_type": token.get("token_type", "Bearer"),
                "scopes": scopes,
                "saved_at": utc_now(),
                "expires_at": (now + timedelta(seconds=int(token.get("expires_in", 3600)))).isoformat(),
                "earliest_refresh_at": token.get("earliest_refresh_at"),
            }
            self._write_credentials(record)
            return self.status()

    def access_token(self) -> str:
        with self._lock:
            record = self._load_credentials()
            if not record:
                raise AuthenticationRequired("Connect a ChatGPT account before starting AI analysis")
            expires = datetime.fromisoformat(record["expires_at"])
            # Analysis and report requests can stream for many minutes. Refresh before
            # launching them so a token does not expire while a response is in flight.
            if datetime.now(UTC) + LONG_RUNNING_TOKEN_MARGIN >= expires:
                try:
                    record = self._refresh(record)
                except TartarusError as exc:
                    raise AuthenticationRequired(
                        "ChatGPT authorization could not be refreshed. Reconnect ChatGPT."
                    ) from exc
            return str(record["access_token"])

    def disconnect(self) -> bool:
        with self._lock:
            record = self._load_credentials()
            revoked = False
            if record:
                try:
                    discovery = self._get_json(DISCOVERY_ENDPOINT)
                    endpoint = discovery.get("revocation_endpoint")
                    if endpoint:
                        self._post_form(
                            endpoint,
                            {
                                "token": record["refresh_token"],
                                "token_type_hint": "refresh_token",
                                "client_id": record["client_id"],
                            },
                            allow_empty=True,
                        )
                        revoked = True
                except TartarusError:
                    revoked = False
            self.credential_path.unlink(missing_ok=True)
            return revoked

    def _refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        token = self._post_form(
            TOKEN_ENDPOINT,
            {
                "grant_type": "refresh_token",
                "client_id": record["client_id"],
                "refresh_token": record["refresh_token"],
                "resource": RESOURCE,
            },
        )
        now = datetime.now(UTC)
        record.update(
            access_token=token["access_token"],
            refresh_token=token["refresh_token"],
            id_token=token.get("id_token", record.get("id_token")),
            scopes=str(token.get("scope", " ".join(record["scopes"]))).split(),
            saved_at=utc_now(),
            expires_at=(now + timedelta(seconds=int(token.get("expires_in", 3600)))).isoformat(),
            earliest_refresh_at=token.get("earliest_refresh_at"),
        )
        self._write_credentials(record)
        return record

    def _validate_id_token(self, token: Any, client_id: str, nonce: str) -> dict[str, Any]:
        if not isinstance(token, str):
            raise TartarusError("ChatGPT ID token is missing")
        try:
            discovery = self._get_json(DISCOVERY_ENDPOINT)
            key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256", "ES256"],
                audience=client_id,
                issuer=ISSUER,
                options={"require": ["exp", "iss", "sub", "aud", "nonce"]},
            )
        except Exception as exc:
            raise TartarusError("ChatGPT identity token validation failed") from exc
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise TartarusError("ChatGPT identity nonce did not match")
        return claims

    def _host_id(self) -> str:
        if self.host_path.is_file():
            return str(load_json(self.host_path)["ext_agent_host_id"])
        value = {"ext_agent_host_id": f"urn:uuid:{uuid.uuid4()}"}
        atomic_json(self.host_path, value)
        self.host_path.chmod(0o600)
        return value["ext_agent_host_id"]

    def _load_credentials(self) -> dict[str, Any] | None:
        return load_json(self.credential_path) if self.credential_path.is_file() else None

    def _write_credentials(self, value: dict[str, Any]) -> None:
        atomic_json(self.credential_path, value)
        self.credential_path.chmod(0o600)

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                return json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise TartarusError("OpenAI authentication service is unavailable") from exc

    def _post_form(
        self, url: str, values: dict[str, Any], *, allow_empty: bool = False
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=urllib.parse.urlencode(values).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
        except (OSError, urllib.error.URLError) as exc:
            raise TartarusError("OpenAI authentication request failed") from exc
        if allow_empty and not body:
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise TartarusError("OpenAI authentication response was invalid") from exc


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
