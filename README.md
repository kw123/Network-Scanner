# Network Scanner – Indigo Plugin

Discovers all devices on the local LAN and creates one Indigo device per unique MAC address found. The device's on/off state reflects whether the physical device is currently reachable on the network.

Beyond basic LAN scanning the plugin provides:

- **Internet ping devices** — monitor external hosts (Google, Yahoo, custom hostname…) by ICMP ping on a fixed interval. One-click creation via *Add Internet Ping Devices…*
- **Internet Address device** — tracks the public (WAN) IP of this machine; alerts when the IP changes. Created via *Add Internet Address Device…*
- **Home or Away aggregate** — watches up to 6 Network Devices; ON when at least one is home, OFF when all are away. Use it to trigger automations when someone arrives or leaves.
- **Online / Offline aggregate** — watches up to 3 External Devices; ON when at least one is reachable, OFF when all fail. Instant internet up/down indicator.
- **On-demand ping** — ping any IP or DNS hostname from the plugin menu; result written to the `networkScanner_pingDevice` variable.

---

## Requirements

No third-party packages required.

| Tool | Purpose |
|------|---------|
| `/usr/sbin/tcpdump` | Passive traffic sniffing — captures ARP, mDNS (port 5353) and DHCP (ports 67/68) |
| `/usr/sbin/arp` | Reads ARP cache after sweep |
| `/sbin/ifconfig` | Determines local subnet (IP and netmask) |
| `Python socket` | ICMP ping (`SOCK_DGRAM / IPPROTO_ICMP`) and TCP-connect probe (`SOCK_STREAM`) — no subprocess, no root required |
| `MAC2Vendor.py` | Bundled OUI vendor lookup — auto-downloads IEEE tables on first run, caches locally |

> **macOS password required for tcpdump.**  
> `tcpdump` needs elevated privileges to open the BPF network socket for passive sniffing.  
> Enter your macOS login password in *Plugins → Network Scanner → Configure… → sudo Password*.  
> Leave blank only if tcpdump already has the BPF entitlement granted via `sudo chmod` or a system policy.

---

## Discovery Methods

1. **Passive traffic sniffing** — `tcpdump` listens for ARP, mDNS (port 5353) and DHCP (ports 67/68). Any matching packet updates the device's last-seen timestamp. Catches devices that suppress ARP (iOS privacy mode, VMs, IoT). Each MAC throttled to one Indigo update per 30 s. Requires sudo password if tcpdump does not already have the BPF entitlement.

2. **Active ARP sweep** — sends parallel ICMP pings to every host on the subnet, then reads the kernel ARP cache with `arp -a`. Only devices that actually respond to ping or TCP probe have their last-seen updated. Stale cache entries do not count as online.

3. **Periodic reachability probe** — runs every scan-interval:
   - ICMP ping via Python socket (no subprocess, no root)
   - TCP connect fallback on ports 80 → 443 → 22 → 8080 if ICMP is blocked. `ConnectionRefusedError` counts as alive.
   - Winning TCP port remembered per device and tried first next time.
   - After 5 consecutive all-port failures the TCP probe is suspended (auto-resets when ping succeeds).
   - Per-device **Ping only** option skips TCP fallback entirely.

---

## Plugin Configuration

*Plugins → Network Scanner → Configure…*

| Setting | Description | Default |
|---------|-------------|---------|
| Network Interface | Interface to sniff (e.g. `en0`, `eth0`). Leave blank to auto-detect. | auto |
| sudo Password | macOS login password so tcpdump can open the BPF socket. Leave blank if tcpdump already has the entitlement. | — |
| Scan Interval (s) | How often to probe known devices. Options: 30 / 60 / 90 / 120 | `60` |
| Enable ARP Sweep | Active subnet sweep each scan cycle | on |
| Enable Passive Traffic Sniffing | Listen for ARP / mDNS / DHCP traffic between sweeps | on |
| Offline Threshold (s) | Unreachable for this long → marked offline. Options: 30–420 s | `180` |
| Ignore offline changes at startup (s) | Suppress offline decisions for N seconds after start, giving sniffing time to re-confirm devices. Options: 20 / 40 / 60 / 80 | `60` |
| Auto-Create Devices | Create an Indigo device for each new MAC address discovered | on |
| Device Folder Name | Indigo folder for `Net_*` devices (auto-created). Leave blank for root. | `Network Devices` |
| Variable Folder Name | Indigo variable folder for plugin-managed variables. Auto-created. Leave blank for root. | — |
| Prefix Name | Prefix for auto-named devices (e.g. `Net_` → `Net_AA:BB:CC:DD:EE:FF`) | `Net_` |

### Quick-Setup Buttons

| Button | Description |
|--------|-------------|
| **Turn Off All Per-Device Logging** | Sets *Log Every Seen Event to File* to `false` on every managed Network Device in one click. |

### Logging Options

| Setting | Description |
|---------|-------------|
| Log New Device Created | Log when a new Indigo device is auto-created for a MAC |
| Log Online / Offline Changes | Log online ↔ offline state transitions |
| Online / Offline Log Destination | `plugin.log` only — or — `plugin.log` + Indigo event log |
| Log IP Address Changes | Log when a device's IP address changes |
| Log Every Device Seen | Verbose per-packet log (noisy) |
| Log ARP Sweep Activity | Log sweep start / finish |
| Log Ignored MACs Skipped | Log each time an ignored MAC is seen |
| Log Ping / Probe Results | Log every ICMP ping and TCP probe result (noisy during sweeps) |
| Log Tcpdump ARP Replies | Log every ARP reply captured by tcpdump including throttled ones (very noisy) |
| Log ARP Sweep Entries | Log every entry parsed from `arp -a` during each sweep |

---

## Device Types

### Network Device  (`Net_*`)

One device per discovered MAC address. Auto-created when **Auto-Create Devices** is on.

- **Address column**: MAC address
- **Notes column**: IP with last octet zero-padded (e.g. `192.168.1.005`) for correct alphabetical sort by IP
- Name starts as `Net_AA:BB:CC:DD:EE:FF`, then automatically renamed to include vendor / local name once known

### External Device

A manually configured host (IP address or DNS name) pinged on a fixed interval. No MAC tracking — useful for monitoring internet connectivity. Create via *New Device → External Device* or use **Add Internet Ping Devices…** in the plugin menu.

### Network Devices — Home or Away

Aggregate device that watches up to **6 Network Devices** and tracks presence.

- **ON** — at least one watched device is online ("someone home")
- **OFF** — all watched devices are offline ("everyone away")
- `ParticipantsHome` — count of currently online participants
- `participants` — comma-separated Indigo device IDs of all configured slots
- **Notes** column — written once on first save as `id,id,id - mac,mac,mac`; never overwritten so you can edit it freely

Use the `ParticipantsHome` state in Indigo conditions to check if *at least N* people are home.

### External Devices — Online / Offline

Aggregate device that watches up to **3 External Devices** and tracks internet connectivity.

- **ON** — at least one watched External Device is reachable
- **OFF** — all watched External Devices are offline (internet appears down)
- `ParticipantsOnline` — count of currently reachable participants
- `participants` — comma-separated Indigo device IDs of all configured slots
- **Address column** — set once at creation: watched hostnames with `www.` and TLD stripped, separated by `·` (e.g. `google · yahoo · welt`). Never overwritten.
- **Notes column** — written once on first save as `id,id,id - host,host,host`; never overwritten

### Internet Address

Monitors the public (WAN) IP address of this machine. Fetches from well-known IP-echo services on a configurable interval and stores the result in the `publicIp` state (shown as the device display state in the Indigo device list).

- **Display state**: `publicIp` — current public IP address
- **ON** — last fetch succeeded
- **OFF** — all services unreachable (internet appears down)
- **Notes column** — mirrors `publicIp` for easy reading

**Services tried in order** (first to respond wins):

| Priority | Service |
|----------|---------|
| 1 | `api.ipify.org` |
| 2 | `checkip.amazonaws.com` |
| 3 | `icanhazip.com` |

Each service has a 10-second timeout. The next service is tried only if the previous one fails or times out.

Create via *Plugins → Network Scanner → Add Internet Address Device…* (safe to click multiple times — skips if device already exists).

---

## Device Edit — Network Device

*Double-click any `Net_*` device*

### Ping / Probe Usage

| Option | Behaviour | When to use |
|--------|-----------|-------------|
| **Online + Offline** | Probe sets both online and offline | Verbose tracking; device responds reliably |
| **Online only** | Probe can mark online, not offline | Fast recovery when device reappears (e.g. phone returning home) |
| **Offline only** | Probe can mark offline, not online | Fast offline when device disappears |
| **Confirm offline** *(default)* | Probe only fires after ARP/sniff timeout is exceeded | Quiet devices — prevents premature offline |
| **Ping only** | ICMP only, no TCP fallback | Routers, cameras, printers |
| **Not at all** | Probe ignored; timeout alone decides offline | Passive detection is sufficient |

### Offline Trigger Logic

| Option | Behaviour |
|--------|-----------|
| **AND** *(default)* | Timeout expired **AND** probe failed — fewest false alarms |
| **OR** | Timeout expired **OR** probe failed — faster offline detection |

### Other Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Missed Pings Before Offline | Consecutive probe failures before offline is triggered (1–5) | `1` |
| Offline Threshold (s) | Per-device override; `0` = use plugin-wide default | `0` |
| Set IP Address | Manually override the IP address for this device. Stored in `ipNumber` state and `known_devices.json`. Will be overwritten on the next scan if the device is seen with a different IP. | — |
| Is AP or Router | Mark this device as a proxy-ARP AP or router. IP changes from the passive sniff thread are ignored; only the ARP sweep can update its IP. Set automatically when 3 or more IP changes are detected within 10 minutes. Can be cleared here to re-enable auto-detection. | off |
| Comment | Free-text note stored in the `comment` state | — |
| Suppress IP Change Logging | Silence IP-change log entries for this device | off |
| Log Every Seen Event to File | Write a `plugin.log` entry each time this device is seen | off |

---

## Device States — Network Device

| State | Type | Description |
|-------|------|-------------|
| `onOffState` | Boolean | `True` = online, `False` = offline |
| `ipNumber` | String | Last seen IP address |
| `MACNumber` | String | MAC address |
| `localName` | String | mDNS / Bonjour hostname from `arp -a` (e.g. `iPhone.local`) |
| `hardwareVendor` | String | Manufacturer from bundled OUI table |
| `lastOnOffChange` | String | Timestamp of last online ↔ offline transition |
| `created` | String | Timestamp when the Indigo device was first created |
| `openPorts` | String | Comma-separated open TCP ports from last port scan |
| `comment` | String | Free-text note set in device edit |
| `isApOrRouter` | Boolean | `True` when the device is a proxy-ARP AP or router. Set automatically after 3+ IP changes within 10 minutes, or manually in device edit. When `True`, IP updates from passive sniffing are suppressed — only the ARP sweep can change the IP. |
| `pingMode` | String | Ping/probe mode synced from device settings (e.g. `both`, `confirm`, `none`) |
| `lastOnMessage` | String | Timestamp of the most recent online confirmation (`YYYY-MM-DD HH:MM`). Updated at most once per minute while the device is online. |
| `setOnBy` | String | What mechanism last set the device **online**: `sweep (arp)` · `traffic observed (tcpdump)` · `ping(ICMP)` · `tcp:<port>` |
| `setOffBy` | String | What mechanism last set the device **offline**: `timeout` · `probe` |
| `fingscanDeviceInfo` | String | Fing scan info imported via migration tool |

---

## Device States — External Device

| State | Type | Description |
|-------|------|-------------|
| `onOffState` | Boolean | `True` = reachable, `False` = offline |
| `host` | String | Configured hostname or IP |
| `ipNumber` | String | Resolved IP address |
| `pingMs` | String | Last ping round-trip time (e.g. `12 ms`) or `timeout` |
| `lastOnOffChange` | String | Timestamp of last online ↔ offline transition |
| `comment` | String | Free-text note |

---

## Device States — Aggregate Devices

Applies to both **Network Devices — Home or Away** and **External Devices — Online / Offline**.

| State | Type | Description |
|-------|------|-------------|
| `onOffState` | Boolean | `True` = at least one participant is online/home |
| `ParticipantsHome` / `ParticipantsOnline` | Integer | Count of currently online/home participants |
| `participants` | String | Comma-separated Indigo device IDs of all configured slots |
| `lastOnOffChange` | String | Timestamp of last on/off transition |
| `comment` | String | Free-text note |

---

## Device States — Internet Address

| State | Type | Description |
|-------|------|-------------|
| `onOffState` | Boolean | `True` = last fetch succeeded, `False` = all services unreachable |
| `publicIp` | String | Current public (WAN) IP address — also shown as the device display state |
| `previousIp` | String | IP address before the most recent change |
| `lastChanged` | String | Timestamp when `publicIp` last changed |
| `lastSuccessfulUpdate` | String | Timestamp of the most recent successful fetch (`YYYY-MM-DD HH:MM:SS`) |
| `lastFailedUpdate` | String | Timestamp of the most recent failed fetch (`YYYY-MM-DD HH:MM:SS`) |
| `comment` | String | Free-text note |

---

## New Device Notification

Each time a new MAC address is auto-created as an Indigo device, the variable `networkScanner_newdevice` is updated to `{deviceId}  {timestamp}`.

**How to use:** Create an Indigo Trigger on *Variable Changed → networkScanner_newdevice*, then add a **Run Script** action:

```python
info           = indigo.variables["networkScanner_newdevice"].value
ipDevVarNumber = int(info.split(" ")[0])
dev            = indigo.devices[ipDevVarNumber]
st             = dev.states   # shortcut

theSubject  = "new device on network " + dev.name
theBody     = "new device on network: " + dev.name        + "\n"
theBody    += "ipNumber: "              + st["ipNumber"] + "\n"
theBody    += "MACNumber: "             + st["MACNumber"]+ "\n"
theBody    += "hardwareVendor: "        + st["hardwareVendor"]+ "\n"
theBody    += "indigoID: "              + str(dev.id)     + "\n"

indigo.server.log(theBody)
indigo.server.sendEmailTo("your email address", subject=theSubject, body=theBody)
```

---

## Plugin Variables

| Variable | Value | Description |
|----------|-------|-------------|
| `networkScanner_newdevice` | `{deviceId}  {timestamp}` | Updated on every new Network Device auto-creation. Created at startup if it doesn't exist. Placed in the configured **Variable Folder**. |
| `networkScanner_pingDevice` | `{ip} {ms}ms on/off` | Updated after every manual ping (menu item, action, or Add Internet Ping Devices). Format: `142.250.80.46 22ms on`. If the host is offline the value is e.g. `142.250.80.46 1850ms off`. Created at startup if it doesn't exist. |

---

## Plugin Menu

*Plugins → Network Scanner*

| Menu Item | Description |
|-----------|-------------|
| Force Immediate Rescan | Triggers an ARP sweep + ping check immediately |
| **Ping a Device (IP or DNS)…** | Enter any IP address or DNS name, click **PING**. Result is logged and written to `networkScanner_pingDevice` as `{ip} {ms}ms on/off`. |
| **Add Internet Ping Devices…** | Select from Google, Yahoo, Microsoft, CNN, AT&T, Siemens, or enter a **custom hostname** (e.g. `www.welt.de`). Creates External Device entries for each selected host — device name is `Ping-{host}` with `www.` stripped (e.g. `Ping-welt.de`). Safe to run multiple times — skips any host that already exists. Also auto-creates a **Ping-NetworkScanner Internet** aggregate device (watches up to 3 devices) as an instant internet up/down indicator — Address column shows the watched names without `www.` and TLD (e.g. `google · yahoo · welt`). Pings each selected host immediately after creation and logs the results. |
| **Add Internet Address Device…** | Creates one **Internet Address** device that periodically fetches the public (WAN) IP of this machine. Services tried in order: `api.ipify.org` → `checkip.amazonaws.com` → `icanhazip.com`. Safe to click multiple times — skips if device already exists. |
| Scan Open Ports on All Online Devices… | Port-scans all online devices; stores results in `openPorts` state |
| Set a State of Device… | Manually overwrite any state on any `Net_*` device |
| Print All Discovered Devices | Prints all known MACs with IP, local name, vendor, on/off and last-seen to plugin.log |
| Print Devices with IP Address Changes | Lists devices whose IP address has changed since the plugin started |
| Print devices that have frequent on and off… | Lists devices with very short on/off intervals (possible instability) |
| Print Seen-Interval Statistics… | Histogram of how often each device is seen; sort by IP / name / last seen |
| Reset Seen-Interval Statistics | Clears histogram counters for all devices |
| Manage Ignored MAC Addresses… | Exclude / re-include specific MACs from scanning |
| Help… | Prints full help text to plugin.log |

---

## Actions

*Available in Indigo Action Groups*

| Action | Description |
|--------|-------------|
| **Ping Address** | Ping any IP address or DNS hostname. The result is written to `plugin.log` and to the variable `networkScanner_pingDevice` as `{ip} {ms}ms on/off`. |

---

## Seen-Interval Statistics

Tracks the time between consecutive sightings of each device, bucketed into:

`≤10s` · `≤30s` · `≤60s` · `≤90s` · `≤120s` · `≤180s` · `≤240s` · `≤300s` · `>300s`

---

## Ignored MACs

*Plugins → Network Scanner → Manage Ignored MAC Addresses…*

- **Top list** — all discovered devices: select one → click **▼ Ignore Selected Device**
- **Bottom list** — currently ignored: select one → click **▲ Un-ignore Selected Device**
- Click **OK** to save

Ignored MACs are neither created nor updated by the scanner.

---

## Local Name Resolution

`localName` is populated from the first field of `arp -a` output — filled by macOS from its mDNS/Bonjour cache. Devices that don't advertise a Bonjour name show `?` in arp output and have an empty `localName`. The name is **only updated when a real name is found** — a `?` result never erases a previously discovered name.

---

## Scanned TCP Ports

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 554 | RTSP (cameras/media) |
| 22 | SSH | 587 | SMTP submission |
| 23 | Telnet | 631 | IPP (printing) |
| 25 | SMTP | 993 | IMAPS |
| 53 | DNS | 995 | POP3S |
| 80 | HTTP | 1883 | MQTT |
| 110 | POP3 | 3306 | MySQL |
| 143 | IMAP | 3389 | RDP |
| 443 | HTTPS | 5000 | UPnP / dev server |
| 445 | SMB | 5900 | VNC |
| 548 | AFP | 8080 | HTTP-alt |
| — | — | 8443 | HTTPS-alt |
| — | — | 9100 | Raw printing |
| — | — | 32400 | Plex |

---

## Startup Behaviour

- Plugin-managed Indigo variables are created if they don't exist yet.
- Offline changes are suppressed for the configured grace period so sniffing and the first sweep can re-confirm all devices.
- `known_devices.json` is loaded at startup — previously discovered devices are immediately available.
- Each managed device gets a deferred port scan 15 s after startup.

---

## State Persistence

All discovered device data (IP, last-seen, vendor, local name, ping-fail streak, statistics, IP change history) is saved to:

```
<Indigo install>/Preferences/Plugins/com.karlwachs.networkscanner/known_devices.json
```

Saved after every scan cycle and on shutdown (including SIGTERM).

### IP Change History

Each time a device's IP address changes, a record is appended to its `ip_history` list (capped at 20 entries):

| Field | Description |
|-------|-------------|
| `ts` | Timestamp of the change |
| `old_ip` | Previous IP address |
| `new_ip` | New IP address |
| `source` | `scan` — changed by ARP sweep / sniff; `manual` — set via device edit |

Visible in *List All Discovered Devices* and *Print IP-Changed Devices* menu items, where each line shows `[scan]` or `[manual]`.

---

*Author: Karl Wachs — Version 2026.5.28 (2026-04-20)*
