# pywax

Python library and CLI for managing Netgear WAX access points via their local HTTPS management API.

## Installation

```sh
pip install "pywax @ git+https://github.com/pschmitt/pywax"
```

Or run without installing via `uvx`:

```sh
uvx --from "pywax @ git+https://github.com/pschmitt/pywax" wax --help
```

## Configuration

Credentials can be provided via environment variables or `/etc/wax/credentials`:

```sh
# /etc/wax/credentials
WAX_HOST=10.5.0.3
WAX_USERNAME=admin
WAX_PASSWORD=your-password
```

## CLI usage

```sh
wax info                          # device facts
wax ssid                          # list all SSIDs
wax ssid --psk                    # include pre-shared keys
wax ssid set SSID1 --enable       # enable an SSID
wax ssid set brkn-lan --hide      # hide SSID from beacons
wax ssid set SSID1 --psk new-psk  # change passphrase
wax ssid set SSID1 --auth-type wpa2_wpa3 --encryption aes
```

## Library usage

```python
from pywax import WaxClient

with WaxClient("10.5.0.3", password="secret") as client:
    facts = client.get_facts()
    ssids = client.get_ssids()
```

## Credits

API discovery based on the excellent work by **rroller** in the
[netgear Home Assistant integration](https://github.com/rroller/netgear).

## License

GPL-3.0-or-later
