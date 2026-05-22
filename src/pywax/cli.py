# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich_argparse import RichHelpFormatter

from .client import (
    AUTH_TYPES,
    AUTH_TYPES_REV,
    ENCRYPTION_TYPES,
    ENCRYPTION_TYPES_REV,
    WaxClient,
    WaxClientError,
)

console = Console()
console_err = Console(file=sys.stderr)
LOGGER = logging.getLogger(__name__)

CREDENTIALS_FILE = "/etc/wax/credentials"


def _load_credentials_file(path: str = CREDENTIALS_FILE) -> dict[str, str]:
    creds: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                creds[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return creds


_creds = _load_credentials_file()

DEFAULT_HOST = os.environ.get("WAX_HOST", _creds.get("WAX_HOST", ""))
DEFAULT_USER = os.environ.get("WAX_USERNAME", _creds.get("WAX_USERNAME", "admin"))
DEFAULT_PASSWORD = os.environ.get("WAX_PASSWORD", _creds.get("WAX_PASSWORD", ""))

NA = Text("N/A", style="bright_black italic")


def na_or(value: object) -> object:
    return value if value is not None else NA


def bool_text(value: object, true_str: str = "yes", false_str: str = "no") -> Text:
    if value is None:
        return NA
    return Text(true_str, style="green") if value else Text(false_str, style="red")


def make_table(*headers: str) -> Table:
    t = Table(box=None, show_edge=False, pad_edge=False, padding=(0, 2, 0, 0))
    styles = ("cyan", "green", "magenta", "white", "yellow", "blue", "bright_black", "red")
    for i, h in enumerate(headers):
        t.add_column(h, style=styles[i % len(styles)])
    return t


def _settable(cfg: dict) -> dict:
    return {k: v for k, v in cfg.items() if not isinstance(v, list)}


###############################################################################
# info
###############################################################################


def cmd_info(args: argparse.Namespace, client: WaxClient) -> None:
    facts = client.get_facts()

    if args.json:
        console.print_json(json.dumps(facts))
        return

    table = Table(
        box=None,
        show_edge=False,
        pad_edge=False,
        padding=(0, 2, 0, 0),
        show_header=False,
    )
    table.add_column("key", style="bright_black")
    table.add_column("value")
    for key, val in [
        ("AP Name", facts["ap_name"]),
        ("Model", facts["model"]),
        ("Firmware", facts["firmware"]),
        ("Serial", facts["serial"]),
        ("MAC", facts["mac_address"]),
        ("Clients", str(facts["client_count"])),
    ]:
        table.add_row(key, str(val))
    console.print(table)


###############################################################################
# ssid
###############################################################################


def _decode_ssid_entry(ssid_id: str, entry: dict) -> dict:
    """Flatten ssidGetDetails entry to a single summary dict."""
    band = entry.get("band", "?")
    # First VAP of first wlan band is canonical.
    vap: dict = {}
    for wk in ("wlan0", "wlan1"):
        if wk in entry and isinstance(entry[wk], dict):
            vap_map = entry[wk]
            if vap_map:
                vap = next(iter(vap_map.values()))
                break
    return {
        "ssid_id": ssid_id,
        "name": vap.get("ssid", ""),
        "enabled": bool(vap.get("vapProfileStatus", 0)),
        "hidden": bool(vap.get("hideNetworkName", 0)),
        "band": band,
        "auth_type": AUTH_TYPES_REV.get(vap.get("authenticationType"), vap.get("authenticationType")),
        "encryption": ENCRYPTION_TYPES_REV.get(vap.get("encryption"), vap.get("encryption")),
        "vlan_id": vap.get("vlanID"),
        "psk": vap.get("presharedKey"),
    }


def cmd_ssid_list(args: argparse.Namespace, client: WaxClient) -> None:
    raw = client.get_ssids()
    ssids = [_decode_ssid_entry(sid, val) for sid, val in sorted(raw.items())]

    if args.json:
        # strip PSKs unless explicitly requested
        if not getattr(args, "show_psk", False):
            for s in ssids:
                s.pop("psk", None)
        console.print_json(json.dumps(ssids))
        return

    headers = ["id", "name", "enabled", "hidden", "band", "auth", "enc", "vlan"]
    if getattr(args, "show_psk", False):
        headers.append("psk")
    table = make_table(*headers)
    for s in ssids:
        row = [
            s["ssid_id"],
            s["name"],
            bool_text(s["enabled"]),
            bool_text(s["hidden"], "hidden", "visible"),
            s["band"] or NA,
            na_or(s["auth_type"]),
            na_or(s["encryption"]),
            na_or(str(s["vlan_id"]) if s["vlan_id"] is not None else None),
        ]
        if getattr(args, "show_psk", False):
            row.append(na_or(s["psk"]))
        table.add_row(*row)
    console.print(table)


def cmd_ssid_set(args: argparse.Namespace, client: WaxClient) -> None:
    ssid_id = client.resolve_ssid_id(args.ssid)
    raw = client.get_ssids()
    entry = raw[ssid_id]

    # Build per-band set payload, applying only requested changes.
    changed = False
    set_payload: dict = {}
    for wk, vaps in entry.items():
        if not wk.startswith("wlan") or not isinstance(vaps, dict):
            continue
        set_payload[wk] = {}
        for vap_id, cfg in vaps.items():
            desired = _settable(cfg)
            if args.enable is not None:
                new_val = 1 if args.enable else 0
                if desired.get("vapProfileStatus") != new_val:
                    desired["vapProfileStatus"] = new_val
                    changed = True
            if args.hidden is not None:
                new_val = 1 if args.hidden else 0
                if desired.get("hideNetworkName") != new_val:
                    desired["hideNetworkName"] = new_val
                    changed = True
            if args.psk is not None and desired.get("presharedKey") != args.psk:
                desired["presharedKey"] = args.psk
                changed = True
            if args.auth_type is not None:
                new_val = AUTH_TYPES[args.auth_type]
                if desired.get("authenticationType") != new_val:
                    desired["authenticationType"] = new_val
                    changed = True
            if args.encryption is not None:
                new_val = ENCRYPTION_TYPES[args.encryption]
                if desired.get("encryption") != new_val:
                    desired["encryption"] = new_val
                    changed = True
            if args.vlan_id is not None and desired.get("vlanID") != args.vlan_id:
                desired["vlanID"] = args.vlan_id
                changed = True
            set_payload[wk][vap_id] = desired

    if not changed:
        console_err.print("[bright_black]No changes.[/bright_black]")
        return

    client.set_ssid(ssid_id, set_payload)
    console_err.print(f"[green]SSID {ssid_id} updated.[/green]")


###############################################################################
# CLI wiring
###############################################################################


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wax",
        description="Netgear WAX access point CLI",
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument(
        "-H",
        "--host",
        default=DEFAULT_HOST,
        metavar="HOST",
        help=f"AP address (default: {DEFAULT_HOST!r}, $WAX_HOST, {CREDENTIALS_FILE})",
    )
    parser.add_argument(
        "-u",
        "--username",
        default=DEFAULT_USER,
        metavar="USER",
        help="Admin username ($WAX_USERNAME)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=DEFAULT_PASSWORD,
        metavar="PASS",
        help="Admin password ($WAX_PASSWORD)",
    )
    parser.add_argument("-j", "--json", action="store_true", default=False, help="JSON output")
    parser.add_argument("-d", "--debug", action="store_true", default=False, help="Enable debug logging")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info", help="Show device facts (default)", formatter_class=RichHelpFormatter)

    ssid_p = sub.add_parser(
        "ssid",
        aliases=["wifi", "wlan"],
        help="List or configure SSIDs",
        formatter_class=RichHelpFormatter,
    )
    ssid_sub = ssid_p.add_subparsers(dest="ssid_command")

    list_p = ssid_sub.add_parser(
        "list", aliases=["ls"], help="List all SSIDs (default)", formatter_class=RichHelpFormatter
    )
    list_p.add_argument("--psk", action="store_true", dest="show_psk", default=False, help="Show pre-shared keys")

    set_p = ssid_sub.add_parser("set", help="Configure an SSID", formatter_class=RichHelpFormatter)
    set_p.add_argument("ssid", metavar="SSID", help="SSID identifier (e.g. SSID1) or name (e.g. brkn-lan)")

    enable_group = set_p.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", dest="enable", action="store_true", default=None, help="Enable the SSID")
    enable_group.add_argument("--disable", dest="enable", action="store_false", help="Disable the SSID")

    hidden_group = set_p.add_mutually_exclusive_group()
    hidden_group.add_argument("--hide", dest="hidden", action="store_true", default=None, help="Hide SSID from beacons")
    hidden_group.add_argument("--show", dest="hidden", action="store_false", help="Broadcast SSID in beacons")

    set_p.add_argument("--psk", metavar="PSK", default=None, help="WPA pre-shared key")
    set_p.add_argument(
        "--auth-type",
        metavar="TYPE",
        choices=list(AUTH_TYPES),
        default=None,
        help="Authentication type: " + ", ".join(AUTH_TYPES),
    )
    set_p.add_argument(
        "--encryption",
        metavar="TYPE",
        choices=list(ENCRYPTION_TYPES),
        default=None,
        help="Cipher suite: " + ", ".join(ENCRYPTION_TYPES),
    )
    set_p.add_argument("--vlan-id", metavar="N", type=int, default=None, help="802.1Q VLAN ID")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%H:%M:%S",
        )

    if not args.host:
        console_err.print(
            "[red]No host specified.[/red] Use [bold]-H HOST[/bold], "
            f"[bold]$WAX_HOST[/bold], or [bold]{CREDENTIALS_FILE}[/bold]."
        )
        sys.exit(1)

    if not args.password:
        console_err.print("[red]No password specified.[/red] Use [bold]-p PASS[/bold] or [bold]$WAX_PASSWORD[/bold].")
        sys.exit(1)

    try:
        with WaxClient(args.host, username=args.username, password=args.password) as client:
            cmd = args.command
            if cmd in (None, "info"):
                cmd_info(args, client)
            elif cmd in ("ssid", "wifi", "wlan"):
                ssid_cmd = getattr(args, "ssid_command", None)
                if ssid_cmd in (None, "list", "ls"):
                    cmd_ssid_list(args, client)
                elif ssid_cmd == "set":
                    cmd_ssid_set(args, client)
                else:
                    cmd_ssid_list(args, client)
    except WaxClientError as exc:
        console_err.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        console_err.print("\n[bright_black]Interrupted.[/bright_black]")
        sys.exit(130)
