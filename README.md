# pywax

Python library and CLI for managing Netgear WAX access points via their local HTTPS management API.

## Installation

```sh
pip install pywax
```

Or run without installing:

```sh
uv run --with pywax python3 -m pywax --help
```

## Configuration

Credentials are read from environment variables or `/etc/wax/credentials`:

```sh
# /etc/wax/credentials
WAX_HOST=10.5.0.3
WAX_USERNAME=admin
WAX_PASSWORD=your-password
```

Environment variables (`WAX_HOST`, `WAX_USERNAME`, `WAX_PASSWORD`) take precedence over the file.

## CLI usage

```sh
wax info                          # device facts

wax wifi                          # list all SSIDs
wax wifi --psk                    # include pre-shared keys
wax wifi SSID1                    # show details for SSID1
wax wifi brkn-lan                 # look up by SSID name

wax wifi SSID1 on                 # enable
wax wifi SSID1 off                # disable
wax wifi SSID1 toggle             # flip enabled state
wax wifi SSID1 hide               # hide from beacons
wax wifi SSID1 show               # unhide
wax wifi SSID1 psk s3cr3t         # set passphrase
```

`wifi` can be abbreviated as `w`, `wlan`, or `ssid`.

## Library usage

```python
from pywax import WaxClient

with WaxClient("10.5.0.3", password="secret") as client:
    facts = client.get_facts()
    ssids = client.get_ssids()
    client.set_ssid("SSID1", {...})
```

## Auth type reference

| `auth_type`  | Description                          |
|--------------|--------------------------------------|
| `wpa2`       | WPA2-PSK only                        |
| `wpa_wpa2`   | WPA + WPA2 mixed                     |
| `wpa2_wpa3`  | WPA2-PSK + WPA3-SAE (transition)     |

## Credits

API discovery based on the excellent work by **rroller** in the
[netgear Home Assistant integration](https://github.com/rroller/netgear).

## License

GPL-3.0-or-later
