from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import AircraftState, Snapshot

API_ROOT = "https://opensky-network.org/api"
TOKEN_URL = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"


class OpenSkyError(RuntimeError):
    """Raised when OpenSky returns an error response."""


@dataclass
class TokenManager:
    client_id: str
    client_secret: str
    refresh_margin_seconds: int = 30
    _token: Optional[str] = None
    _expires_at: float = 0.0

    def get_token(self) -> str:
        if self._token and time.time() < self._expires_at:
            return self._token
        return self._refresh()

    def _refresh(self) -> str:
        payload = urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        ).encode("utf-8")
        request = Request(
            TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError) as exc:
            raise OpenSkyError(f"Unable to obtain OpenSky token: {exc}") from exc

        access_token = body.get("access_token")
        expires_in = int(body.get("expires_in", 1800))
        if not access_token:
            raise OpenSkyError("OpenSky token response did not include access_token.")

        self._token = access_token
        self._expires_at = time.time() + max(0, expires_in - self.refresh_margin_seconds)
        return access_token

    def headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}


class OpenSkyClient:
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: int = 20,
    ) -> None:
        resolved_client_id = client_id or os.getenv("OPENSKY_CLIENT_ID") or os.getenv("CLIENT_ID")
        resolved_client_secret = client_secret or os.getenv("OPENSKY_CLIENT_SECRET") or os.getenv("CLIENT_SECRET")
        self.timeout = timeout
        self._token_manager: Optional[TokenManager] = None
        if resolved_client_id and resolved_client_secret:
            self._token_manager = TokenManager(
                client_id=resolved_client_id,
                client_secret=resolved_client_secret,
            )

    @property
    def is_authenticated(self) -> bool:
        return self._token_manager is not None

    def fetch_states(
        self,
        icao24: Optional[Sequence[str]] = None,
        bbox: Optional[Tuple[float, float, float, float]] = None,
        extended: bool = True,
    ) -> Snapshot:
        params = []
        if icao24:
            for ident in icao24:
                params.append(("icao24", ident.lower()))
        if bbox:
            lamin, lomin, lamax, lomax = bbox
            params.extend(
                [
                    ("lamin", str(lamin)),
                    ("lomin", str(lomin)),
                    ("lamax", str(lamax)),
                    ("lomax", str(lomax)),
                ]
            )
        if extended:
            params.append(("extended", "1"))

        query = urlencode(params)
        url = f"{API_ROOT}/states/all"
        if query:
            url = f"{url}?{query}"

        headers = {}
        if self._token_manager:
            headers.update(self._token_manager.headers())

        request = Request(url, headers=headers, method="GET")

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
                states = [
                    AircraftState.from_api_row(row)
                    for row in payload.get("states") or []
                ]
                return Snapshot(
                    time=int(payload["time"]),
                    states=states,
                    rate_limit_remaining=response.headers.get("X-Rate-Limit-Remaining"),
                )
        except HTTPError as exc:
            if exc.code == 401 and self._token_manager:
                self._token_manager._token = None
                self._token_manager._expires_at = 0.0
                return self.fetch_states(icao24=icao24, bbox=bbox, extended=extended)

            retry_after = exc.headers.get("X-Rate-Limit-Retry-After-Seconds")
            if exc.code == 429 and retry_after:
                raise OpenSkyError(
                    f"OpenSky rate limit exceeded. Retry after {retry_after} seconds."
                ) from exc

            detail = exc.read().decode("utf-8", errors="replace")
            raise OpenSkyError(f"OpenSky HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise OpenSkyError(f"Unable to reach OpenSky: {exc}") from exc

    def recommended_resolution_seconds(self) -> int:
        return 5 if self.is_authenticated else 10
