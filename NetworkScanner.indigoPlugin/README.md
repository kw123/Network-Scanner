# Network Scanner – Indigo Plugin

Discovers all devices on the local LAN and creates one Indigo device per unique MAC address found. The device's on/off state reflects whether the physical device is currently reachable on the network.

---

## Requirements

No third-party packages required.

| Tool | Purpose |
|------|---------|
| `/usr/sbin/tcpdump` | Passive traffic sniffing — captures ARP, mDNS (port 5353) and DHCP (ports 67/68). Flags: `-i` interface, `-n` no name resolution, `-e` ethernet header, `-l` line-buffered |
| `/usr/sbin/arp` | Reads ARP cache after sweep — flags: `-a` all entries, `-i` limit to interface |
| `/sbin/ifconfig` | Determine local subnet — parses `inet` line for IP and netmask (hex or dotted decimal) |
| `Python socket` | ICMP ping (`SOCK_DGRAM` / `IPPROTO_ICMP`) and TCP-connect probe (`SOCK_STREAM`) — no subprocess, no root required |
| `MAC2Vendor.py` | Bundled OUI vendor lookup — auto-downloads IEEE tables on first run, caches locally, refreshes every 10 days |

---

## Discovery Methods

1. **Passive traffic sniffing** — `tcpdump` listens for ARP, mDNS (port 5353) and DHCP (ports 67/68). Any matching packet from a device updates its last-seen timestamp. Catches devices that suppress ARP (iOS privacy mode, VMs, IoT). Each MAC is throttled to one Indigo update per 30 s. Requires sudo password in plugin config if tcpdump does not already have the BPF entitlement.

2. **Active ARP sweep** — sends parallel ICMP pings (pure Python socket, no subprocess) to every host on the subnet, then reads the kernel ARP cache with `arp -a`. Only devices that **responded to ping or TCP probe** have their `last_seen` updated. Stale ARP cache entries are recorded for discovery only — they never falsely extend a device's online status.

3. **Periodic reachability probe** — runs every scan-interval seconds:
   - **ICMP ping** via Python `SOCK_DGRAM / IPPROTO_ICMP` socket (no subprocess, no root)
   - **TCP connect fallback** — if ping fails or is blocked, tries ports 80 → 443 → 22 → 8080 via Python `SOCK_STREAM` socket. `ConnectionRefusedError` (TCP RST) counts as alive.
   - The last responding TCP port is remembered per device in `known_devices.json` and tried first next time.
   - After 5 consecutive all-port failures the TCP probe is suspended for that device (auto-resets when ping next succeeds).
   - Per-device option **Ping only** skips the TCP fallback entirely (useful for routers, cameras, printers).

---

## Plugin Configuration

*Plugins → Network Scanner → Configure…*

| Setting | Description | Default |
|---------|-------------|---------|
| Network Interface | Interface to sniff (e.g. `en0`, `eth0`). Leave blank to auto-detect. | `en0` |
| sudo Password | macOS login password so tcpdump can open the BPF socket via `echo <pw> \| sudo -S`. Leave blank if tcpdump already has the entitlement. | — |
| Scan Interval (s) | How often to probe known devices. Options: 30 / 60 / 90 / 120 | `60` |
| Enable ARP Sweep | Active subnet sweep each scan cycle | on |
| Enable Passive Traffic Sniffing | Listen for ARP / mDNS / DHCP traffic between sweeps | on |
| Offline Threshold (s) | Unreachable for this long → marked offline. Options: 30–420 | `180` |
| Ignore offline changes at startup (s) | Suppress all offline decisions for N seconds after plugin start, giving sniffing time to re-confirm devices. Options: 20 / 40 / 60 / 80 | `60` |
| Auto-Create Devices | Create an Indigo device for each new MAC address discovered | on |
| Device Folder Name | Indigo folder for `Net_*` devices (created automatically). Leave blank for root. | `Network Devices` |

### Logging Options

| Setting | Description |
|---------|-------------|
| Log New Device Created | Log when a new Indigo device is auto-created for a MAC |
| Log Online / Offline Changes | Log online ↔ offline state transitions |
| Online / Offline Log Destination | `plugin.log` only — or — `plugin.log` + Indigo event log |
| Log IP Address Changes | Log when a device's IP address changes |
| Log Every Device Seen | Verbose per-packet log (can be noisy) |
| Log ARP Sweep Activity | Log sweep start / finish with device counts |
| Log Ignored MACs Skipped | Log each time an ignored MAC is seen and skipped |
| Log Ping / Probe Results | Log every ICMP ping and TCP probe result to `plugin.log` (can be noisy during sweeps) |

---

## Device Edit

*Double-click any `Net_*` device*

### Ping / Probe Usage

Controls how the periodic reachability probe affects the online/offline state of this device. The probe is ICMP ping first, then TCP connect fallback (unless **Ping only** is selected).

| Option | Behaviour | When to use |
|--------|-----------|-------------|
| **Online + Offline** | Probe sets both online and offline state | Verbose tracking; device responds reliably |
| **Online only** | Probe can mark online, not offline | Get devices back to "on" fast after they reappear (e.g. phone returning home) |
| **Offline only** | Probe can mark offline, not online | Make devices go offline fast when they disappear |
| **Confirm offline** *(default)* | Probe only fires when sniff/ARP timeout is exceeded; logged to plugin.log when probe keeps device online | Quiet devices — prevents premature offline |
| **Ping only** | ICMP ping only — no TCP fallback | Routers, cameras, printers where TCP probing is undesirable |
| **Not at all** | Probe ignored; sniff/ARP timeout alone decides offline | Device reliably detected by passive sniffing alone |

### Offline Trigger Logic

How probe failure and sniff/ARP timeout combine to decide offline.

| Option | Behaviour |
|--------|-----------|
| **AND** *(default)* | Timeout expired **AND** probe failed — fewest false alarms |
| **OR** | Timeout expired **OR** probe failed — faster offline detection |

### Other Device Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Missed Pings Before Offline | Consecutive probe failures needed before offline (1–5). Higher = fewer false alarms on transient packet loss. | `1` |
| Offline Threshold (s) | Per-device override. `0` = use plugin-wide default. | `0` |
| Comment | Free-text note stored in the `comment` device state | — |
| Suppress IP Change Logging | Silence IP-change log entries for this device only | off |
| Log Every Seen Event to File | Write a `plugin.log` entry each time this device is seen | off |

---

## Device States

| State | Type | Description |
|-------|------|-------------|
| `onOffState` | Boolean | `True` = online / reachable, `False` = offline |
| `ipAddress` | String | Last seen IP address |
| `macAddress` | String | MAC address |
| `localName` | String | mDNS / Bonjour hostname from `arp -a` (e.g. `iPhone.local`); populated during ARP sweep; empty if device has not announced a name |
| `vendorName` | String | Manufacturer name from bundled OUI table |
| `lastOnOffChange` | String | Timestamp of last online ↔ offline transition |
| `created` | String | Timestamp when the Indigo device was first created |
| `openPorts` | String | Comma-separated open TCP ports from last port scan |
| `comment` | String | Free-text note set in device edit |

### Device Naming & Sorting

- **Name**: `Net_AA:BB:CC:DD:EE:FF` (or `Net_AA:BB:CC:DD:EE:FF  VendorName` once vendor is known)
- **Address column**: MAC address (visible in Indigo device list)
- **Notes column**: IP with last octet zero-padded — e.g. `192.168.1.005` — so that alphabetical sort on Notes gives correct numeric IP order

---

## Plugin Menu

*Plugins → Network Scanner*

| Menu Item | Description |
|-----------|-------------|
| List All Discovered Devices | Prints all known MACs with IP, local name, vendor, on/off state and last-seen to plugin.log |
| Force Immediate Rescan | Triggers an ARP sweep + ping check immediately |
| Scan Open Ports on All Online Devices… | Port-scans every currently online device; stores results in the `openPorts` device state |
| Set a State of Device… | Manually overwrite any state on any `Net_*` device |
| Print Seen-Interval Statistics… | Histogram of how often each device is seen; sort by IP / device name / last seen |
| Reset Seen-Interval Statistics | Clears histogram counters for all devices |
| Manage Ignored MAC Addresses… | Exclude / re-include specific MACs from scanning |
| Help… | Prints full help text to plugin.log |

---

## Seen-Interval Statistics

Tracks the time between consecutive sightings of each device, bucketed into:

`≤10s` · `≤30s` · `≤60s` · `≤90s` · `≤120s` · `≤180s` · `≤240s` · `≤300s` · `>300s`

Use **Print Seen-Interval Statistics…** to view (sorted by IP address, device name or last seen); **Reset Seen-Interval Statistics** to clear all counters.

---

## Ignored MACs

*Plugins → Network Scanner → Manage Ignored MAC Addresses…*

- **Top list** — all discovered devices: select one, then click **▼ Ignore Selected Device**
- **Bottom list** — currently ignored devices: select one, then click **▲ Un-ignore Selected Device**
- Click **OK** to save

Ignored MACs are neither created nor updated by the scanner.

---

## Local Name Resolution

The `localName` device state is populated from the first field of `arp -a` output. On macOS, this field is filled in by the OS from its mDNS/Bonjour cache (`mdnsResponder`). Devices that advertise themselves via Bonjour (Apple devices, Sonos speakers, many routers, smart home devices) will show names like `iPhone.local`, `MacBook-Pro.local`, or `router.local`. Devices that do not announce a Bonjour name show `?` in the arp output and will have an empty `localName` state.

The name is **only updated when a real name is found** — a sweep that returns `?` for a device will not erase a previously discovered name.

---

## Scanned TCP Ports

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol — plain-text |
| 22 | SSH | Secure Shell — encrypted remote access / SFTP |
| 23 | Telnet | Insecure plain-text remote access |
| 25 | SMTP | Mail server — outgoing mail relay |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Web server — unencrypted |
| 110 | POP3 | Mail retrieval |
| 143 | IMAP | Mail retrieval |
| 443 | HTTPS | Web server — TLS encrypted |
| 445 | SMB | Windows / Samba file sharing |
| 548 | AFP | Apple Filing Protocol — macOS file sharing |
| 554 | RTSP | Real-Time Streaming — cameras / media |
| 587 | SMTP-sub | Mail submission — encrypted outgoing mail |
| 631 | IPP | Internet Printing Protocol |
| 993 | IMAPS | IMAP over SSL |
| 995 | POP3S | POP3 over SSL |
| 1883 | MQTT | IoT messaging broker (unencrypted) |
| 3306 | MySQL | MySQL / MariaDB database |
| 3389 | RDP | Windows Remote Desktop Protocol |
| 5000 | UPnP/Dev | UPnP control point or development server |
| 5900 | VNC | VNC screen sharing / remote desktop |
| 8080 | HTTP-alt | Alternate HTTP — proxy or dev server |
| 8443 | HTTPS-alt | Alternate HTTPS |
| 9100 | Printer | Raw printing — HP JetDirect / direct TCP print |
| 32400 | Plex | Plex Media Server |

---

## Startup Behaviour

- On startup, all managed Indigo devices run a deferred port scan (15-second delay to allow the first ARP sweep to confirm devices are online).
- Offline changes are suppressed for the configured grace period so that ARP sniffing and the first sweep have time to re-confirm all devices before any device is flipped offline.
- The `known_devices.json` state file is loaded at startup so previously discovered devices are immediately available without waiting for a sweep.

---

## State Persistence

The plugin saves all discovered device data (IP, last-seen timestamp, vendor, local name, ping-fail streak, seen-interval statistics) to:

```
<Indigo install>/Preferences/Plugins/com.karlwachs.networkscanner/known_devices.json
```

This file is saved after every scan cycle and on shutdown (including SIGTERM). On a clean shutdown the save is lock-safe; on SIGTERM a lockless fast-save is used to avoid deadlock.

---

*Author: Karl Wachs — Version 2026.0.5*
