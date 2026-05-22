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

_WIFI_ACTIONS = ("on", "enable", "off", "disable", "toggle", "hide", "show", "psk")


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


def bool_text(value: object, true_str: str = "yes", false_str: str = "no", invert: bool = False) -> Text:
    if value is None:
        return NA
    true_style, false_style = ("red", "green") if invert else ("green", "red")
    return Text(true_str, style=true_style) if value else Text(false_str, style=false_style)


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
# wifi helpers
###############################################################################


def _decode_ssid_entry(ssid_id: str, entry: dict) -> dict:
    """Flatten ssidGetDetails entry into a single summary dict."""
    band = entry.get("band", "?")
    vap: dict = {}
    for wk in ("wlan0", "wlan1"):
        if wk in entry and isinstance(entry[wk], dict) and entry[wk]:
            vap = next(iter(entry[wk].values()))
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


def _apply_changes(client: WaxClient, ssid_id: str, entry: dict, **changes: object) -> bool:
    """Apply a set of field changes across all bands/VAPs. Returns True if anything changed."""
    field_map = {
        "enable": ("vapProfileStatus", lambda v: 1 if v else 0),
        "hidden": ("hideNetworkName", lambda v: 1 if v else 0),
        "psk": ("presharedKey", lambda v: v),
        "auth_type": ("authenticationType", lambda v: AUTH_TYPES[v]),
        "encryption": ("encryption", lambda v: ENCRYPTION_TYPES[v]),
        "vlan_id": ("vlanID", lambda v: v),
    }

    changed = False
    set_payload: dict = {}
    for wk, vaps in entry.items():
        if not wk.startswith("wlan") or not isinstance(vaps, dict):
            continue
        set_payload[wk] = {}
        for vap_id, cfg in vaps.items():
            desired = _settable(cfg)
            for kwarg, (api_field, coerce) in field_map.items():
                if kwarg not in changes:
                    continue
                new_val = coerce(changes[kwarg])
                if desired.get(api_field) != new_val:
                    desired[api_field] = new_val
                    changed = True
            set_payload[wk][vap_id] = desired

    if changed:
        client.set_ssid(ssid_id, set_payload)
    return changed


###############################################################################
# wifi commands
###############################################################################


def cmd_wifi_list(args: argparse.Namespace, client: WaxClient) -> None:
    raw = client.get_ssids()
    ssids = [_decode_ssid_entry(sid, val) for sid, val in sorted(raw.items())]

    if args.json:
        for s in ssids:
            if not args.show_psk:
                s.pop("psk", None)
        console.print_json(json.dumps(ssids))
        return

    headers = ["ID", "NAME", "ENABLED", "HIDDEN", "BAND", "AUTH", "ENC", "VLAN"]
    if args.show_psk:
        headers.append("PSK")
    table = make_table(*headers)
    for s in ssids:
        row: list = [
            s["ssid_id"],
            s["name"],
            bool_text(s["enabled"]),
            bool_text(s["hidden"], "hidden", "visible", invert=True),
            s["band"] or NA,
            na_or(s["auth_type"]),
            na_or(s["encryption"]),
            na_or(str(s["vlan_id"]) if s["vlan_id"] is not None else None),
        ]
        if args.show_psk:
            row.append(na_or(s["psk"]))
        table.add_row(*row)
    console.print(table)


def cmd_wifi_show(ssid_id: str, entry: dict, args: argparse.Namespace) -> None:
    s = _decode_ssid_entry(ssid_id, entry)

    if args.json:
        if not args.show_psk:
            s.pop("psk", None)
        console.print_json(json.dumps(s))
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
    rows = [
        ("ID", s["ssid_id"]),
        ("Name", s["name"]),
        ("Enabled", bool_text(s["enabled"])),
        ("Hidden", bool_text(s["hidden"], "yes", "no", invert=True)),
        ("Band", s["band"] or "?"),
        ("Auth", str(na_or(s["auth_type"]))),
        ("Encryption", str(na_or(s["encryption"]))),
        ("VLAN", str(na_or(str(s["vlan_id"]) if s["vlan_id"] is not None else None))),
    ]
    if args.show_psk:
        rows.append(("PSK", str(na_or(s["psk"]))))
    for key, val in rows:
        table.add_row(key, val if isinstance(val, Text) else str(val))
    console.print(table)


def cmd_wifi(args: argparse.Namespace, client: WaxClient) -> None:
    action = args.wifi_action  # on/off/toggle/hide/show/psk or None
    ssid_arg = args.wifi_ssid  # SSID id/name or None

    # No SSID → list all.
    if not ssid_arg:
        cmd_wifi_list(args, client)
        return

    # Resolve SSID and fetch current state.
    raw = client.get_ssids()
    ssid_id = client.resolve_ssid_id(ssid_arg)
    entry = raw[ssid_id]

    # No action → show info.
    if not action:
        cmd_wifi_show(ssid_id, entry, args)
        return

    # --- mutating actions ---

    if action in ("on", "enable"):
        changed = _apply_changes(client, ssid_id, entry, enable=True)
    elif action in ("off", "disable"):
        changed = _apply_changes(client, ssid_id, entry, enable=False)
    elif action == "toggle":
        current_state = _decode_ssid_entry(ssid_id, entry)["enabled"]
        changed = _apply_changes(client, ssid_id, entry, enable=not current_state)
    elif action == "hide":
        changed = _apply_changes(client, ssid_id, entry, hidden=True)
    elif action == "show":
        changed = _apply_changes(client, ssid_id, entry, hidden=False)
    elif action == "psk":
        passphrase = args.wifi_value
        if not passphrase:
            console_err.print("[red]Error:[/red] psk requires a passphrase argument")
            sys.exit(1)
        changed = _apply_changes(client, ssid_id, entry, psk=passphrase)
    else:
        console_err.print(f"[red]Unknown action:[/red] {action!r}")
        sys.exit(1)

    if changed:
        console_err.print(f"[green]{ssid_id}[/green] updated.")
    else:
        console_err.print(f"[bright_black]{ssid_id}: no change.[/bright_black]")


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
    parser.add_argument("--psk", action="store_true", dest="show_psk", default=False, help="Show pre-shared keys")
    parser.add_argument("-d", "--debug", action="store_true", default=False, help="Enable debug logging")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info", help="Show device facts (default)", formatter_class=RichHelpFormatter)

    wifi_p = sub.add_parser(
        "wifi",
        aliases=["w", "wlan", "ssid"],
        help="List or manage WiFi networks",
        formatter_class=RichHelpFormatter,
        epilog=(
            "Examples:\n"
            "  wax wifi                       list all SSIDs\n"
            "  wax wifi SSID1                 show SSID1 details\n"
            "  wax wifi brkn-lan on           enable by name\n"
            "  wax wifi SSID2 toggle          flip enabled state\n"
            "  wax wifi SSID2 hide            hide from beacons\n"
            "  wax wifi SSID2 psk s3cr3t      set passphrase\n"
        ),
    )
    wifi_p.add_argument("wifi_ssid", nargs="?", metavar="SSID", help="SSID identifier (e.g. SSID1) or name")
    wifi_p.add_argument(
        "wifi_action",
        nargs="?",
        metavar="ACTION",
        choices=_WIFI_ACTIONS,
        help="on|off|toggle|hide|show|psk",
    )
    wifi_p.add_argument("wifi_value", nargs="?", metavar="VALUE", help="Passphrase (for psk action)")

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
            elif cmd in ("wifi", "w", "wlan", "ssid"):
                cmd_wifi(args, client)
    except WaxClientError as exc:
        console_err.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        console_err.print("\n[bright_black]Interrupted.[/bright_black]")
        sys.exit(130)
