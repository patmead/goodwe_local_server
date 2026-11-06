
# Local Server for GoodWe device data in Home Assistant

This custom integration allows Home Assistant (HA) to receive data directly from GoodWe equipment,
replacing the proprietary cloud-based SEMS Portal.

It works by emulating GoodWe's data collection server to accept locally pushed data from GoodWe devices. Only metric/data packets are supported, with all other packets (such as time sync or remote firmware updates) being dropped by default. Packets may optionally be relayed to GoodWe's servers to retain remote monitoring/control if desired.

It has been tested with the following hardware:
 - GoodWe DT-Series GW8KAU-DT 3-phase solar inverter
 - GoodWe HomeKit HK3000 3-phase energy meter


## Installation
 - Add this directory to HA's `config/custom_components/`
 - Enable the integration in HA Settings → Devices & Services → GoodWe Local Server
 - Ensure local TCP traffic to HA on port `20001` is not blocked by any firewall
 - Add a static DNS entry on your local network (e.g. in your router or Pi-Hole settings) directing `tcp.goodwe-power.com` to HA's IP address
 - Devices & sensors will appear in HA automatically when data packets are received

## Extending
Compatibility may be extended to devices other than the ones listed above by adding an appropriate packet type, model number, and sensor data mapping to `sensor.py`.

To assist with this, unrecognised packets are logged to HA's `config/home-assistant.log` for further reverse-engineering.

## References
Many thanks to Scott Leggett for the excellent documentation on GoodWe's data protocol in [Reverse-engineering an encrypted IoT protocol](https://smlx.dev/posts/goodwe-sems-protocol-teardown/)
