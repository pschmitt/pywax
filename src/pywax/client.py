# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Local HTTPS API client for Netgear WAX access points.
# API discovery credit: rroller/netgear (https://github.com/rroller/netgear)

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

AUTH_TYPES: dict[str, int] = {
    "wpa2": 32,
    "wpa_wpa2": 48,
    "wpa2_wpa3": 96,
}
AUTH_TYPES_REV: dict[int, str] = {v: k for k, v in AUTH_TYPES.items()}

ENCRYPTION_TYPES: dict[str, int] = {
    "aes": 4,
    "tkip_aes": 6,
}
ENCRYPTION_TYPES_REV: dict[int, str] = {v: k for k, v in ENCRYPTION_TYPES.items()}


class WaxClientError(Exception):
    pass


class WaxClient:
    """Synchronous HTTPS client for the Netgear WAX local management API.

    Auth flow (discovered by rroller/netgear):
      1. GET / → extract lhttpdsid cookie
      2. POST /socketCommunication with credentials → extract security_token
      3. All subsequent calls carry both cookie and security header.

    Usage as a context manager handles login/logout automatically::

        with WaxClient(host, port, username, password) as client:
            facts = client.get_facts()
    """

    def __init__(self, host: str, port: int = 443, username: str = "admin", password: str = "") -> None:
        self._base = f"https://{host}:{port}"
        self._username = username
        self._password = password
        self._cookie: str | None = None
        self._token: str | None = None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

    def __enter__(self) -> WaxClient:
        self.login()
        return self

    def __exit__(self, *_: object) -> None:
        self.logout()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def login(self, retries: int = 5, retry_delay: int = 3) -> None:
        # The device allows only one concurrent admin session. If another
        # client (e.g. the Home Assistant netgear_wax integration) holds an
        # active session the device returns status 100 and no token. Retry
        # with a short delay to wait for that session to expire.
        req = urllib.request.Request(self._base + "/")
        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                for header in resp.headers.get_all("Set-Cookie") or []:
                    if "lhttpdsid=" in header:
                        self._cookie = header.split("lhttpdsid=")[1].split(";")[0]
        except urllib.error.URLError as exc:
            raise WaxClientError(f"Cannot reach device: {exc}") from exc

        if not self._cookie:
            raise WaxClientError("Login step 1 failed: no lhttpdsid cookie")

        payload = json.dumps(
            {
                "system": {
                    "basicSettings": {
                        "adminName": self._username,
                        "adminPasswd": self._password,
                    }
                }
            }
        ).encode()

        result: dict = {}
        for attempt in range(retries):
            result, headers = self._raw_post("/socketCommunication", payload, auth=False)
            status = result.get("status", -1)

            # 401 = bad credentials or IP lockout — retrying won't help.
            if status == 401:
                raise WaxClientError(
                    "Login rejected (status 401): bad credentials or IP "
                    "temporarily locked out after too many failed attempts."
                )

            # Older firmware returns token in response header; newer in body.
            token = headers.get("security")
            if not token:
                token = (result.get("system") or {}).get("security_token")

            if token:
                self._token = token
                return

            # status 100 = concurrent session limit — wait and retry.
            if attempt < retries - 1:
                time.sleep(retry_delay)

        raise WaxClientError(
            f"Login failed after {retries} attempts: device may have reached its "
            f"concurrent session limit (status 100). Last response: {result}"
        )

    def logout(self) -> None:
        try:
            self._raw_post("/logout", json.dumps({self._username: self._username}).encode())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _raw_post(self, path: str, data: bytes, auth: bool = True) -> tuple[dict, object]:
        headers = {"Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = f"lhttpdsid={self._cookie}"
        if auth and self._token:
            headers["security"] = self._token

        req = urllib.request.Request(self._base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                return json.loads(resp.read()), resp.headers
        except urllib.error.HTTPError as exc:
            raise WaxClientError(f"HTTP {exc.code} on {path}") from exc
        except urllib.error.URLError as exc:
            raise WaxClientError(f"Cannot reach device: {exc}") from exc

    def post(self, payload: dict) -> dict:
        result, _ = self._raw_post(
            "/socketCommunication",
            json.dumps(payload).encode(),
        )
        status = result.get("status", -1)
        if status != 0:
            raise WaxClientError(f"API returned status {status}: {result}")
        return result

    # ------------------------------------------------------------------
    # SSID operations
    # ------------------------------------------------------------------

    def get_ssids(self) -> dict:
        """Return the raw ssidGetDetails dict keyed by SSID1, SSID2, ..."""
        result = self.post({"system": {"wlanSettings": {"wlanSettingTable": {"ssidGetDetails": ""}}}})
        return result["system"]["wlanSettings"]["wlanSettingTable"]["ssidGetDetails"]

    def set_ssid(self, ssid_id: str, wlan_configs: dict) -> dict:
        """Apply ssidSetDetails for one SSID across all its bands.

        wlan_configs: { "wlan0": { "vap0": { field: value, ... } }, ... }
        """
        return self.post(
            {"system": {"wlanSettings": {"wlanSettingTable": {"ssidSetDetails": {ssid_id: wlan_configs}}}}}
        )

    def resolve_ssid_id(self, name_or_id: str) -> str:
        """Return the API ssid_id for a given name or ssid_id string.

        If name_or_id looks like an existing ssid_id key (e.g. 'SSID1') it is
        returned directly; otherwise the SSIDs are scanned for a matching
        ssid name.
        """
        ssids = self.get_ssids()
        if name_or_id in ssids:
            return name_or_id
        for sid, val in ssids.items():
            for wlan_val in val.values():
                if not isinstance(wlan_val, dict):
                    continue
                for cfg in wlan_val.values():
                    if isinstance(cfg, dict) and cfg.get("ssid") == name_or_id:
                        return sid
        raise WaxClientError(f"No SSID matching {name_or_id!r} found on device")

    # ------------------------------------------------------------------
    # Basic settings
    # ------------------------------------------------------------------

    def get_ap_name(self) -> str:
        result = self.post({"system": {"basicSettings": {"apName": ""}}})
        return result["system"]["basicSettings"]["apName"]

    def set_ap_name(self, name: str) -> None:
        self.post({"system": {"basicSettings": {"apName": name}}})

    # ------------------------------------------------------------------
    # Device facts
    # ------------------------------------------------------------------

    def get_facts(self) -> dict:
        result = self.post(
            {
                "system": {
                    "monitor": {
                        "productId": "",
                        "totalNumberOfDevices": "",
                        "sysSerialNumber": "",
                        "ethernetMacAddress": "",
                        "sysVersion": "",
                        "stats": {
                            "lan": {"traffic": ""},
                            "wlan0": {"traffic": "", "channelUtil": ""},
                            "wlan1": {"traffic": "", "channelUtil": ""},
                        },
                    },
                    "basicSettings": {"apName": ""},
                }
            }
        )
        mon = result["system"]["monitor"]
        return {
            "ap_name": result["system"]["basicSettings"]["apName"],
            "model": mon["productId"],
            "firmware": mon["sysVersion"],
            "serial": mon["sysSerialNumber"],
            "mac_address": mon["ethernetMacAddress"],
            "client_count": int(mon.get("totalNumberOfDevices", 0)),
        }
