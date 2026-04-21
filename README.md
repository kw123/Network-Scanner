# Network Scanner – Indigo Plugin

- **Discovers all devices** on the local LAN and creates one Indigo device per unique MAC address found.
The device's on/off state reflects whether the physical device is currently reachable on the network.

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

2. **Active ARP sweep** — sends parallel ICMP pings to every host on the subnet, then reads the kernel ARP cache with `arp -a`. Only devices that actually respond to ping or TCP probe have their last-seen updated. Stale cache entries do not count as online. After processing, the plugin runs `sudo arp -d -a` to flush the ARP cache so stale entries from powered-off devices do not persist into the next cycle (requires sudo password). The `arp -a` output also captures the network interface (`en0` = Wi-Fi, `en1` = Ethernet) for each device → stored in `networkInterface`.

3. **Periodic reachability probe** — runs every scan-interval:
   - ICMP ping via Python socket (no subprocess, no root) — records round-trip time (`pingMs`) and IP TTL.
   - TTL is used to derive a fallback OS hint when no better source is available: 128 → Windows · 64 → Linux / macOS / iOS · 255 → Router / network gear.
   - TCP connect fallback on ports 80 → 443 → 22 → 8080 if ICMP is blocked. `ConnectionRefusedError` counts as alive.
   - Winning TCP port remembered per device and tried first next time.
   - After 5 consecutive all-port failures the TCP probe is suspended (auto-resets when ping succeeds).
   - Per-device **Ping only** option skips TCP fallback entirely.
   - **Sweep-freshness skip:** if the ARP sweep confirmed the device within the last `scan-interval − 10 s`, the per-device probe is skipped — the sweep result is used directly, reducing redundant probing.
   - **False-positive guard:** when a device that is currently offline gets a positive ICMP response, a TCP probe is run as confirmation before the device is brought back online. Routers/gateways proxy ICMP for their ARP-cached neighbours but do not proxy TCP, so a TCP reply (connect or RST) proves the device's own stack is running. For `pingOnly` devices or those where TCP has never worked, a second ICMP ping is used instead (1-second gap).

4. **DHCP enrichment** — the separate DHCP sniffer (`tcpdump -vv` on ports 67/68) extracts:
   - **Option 12** (hostname) → `dhcpHostname`. Populated only when a device sends a DHCP request — typically on first connect or lease renewal (can take hours for already-connected devices).
   - **Option 55** (parameter request list) → `dhcpOsFingerprint`. The sequence of option numbers acts as an OS fingerprint: Windows `{249,252}` · Apple macOS/iOS `[_, 121, ...]` · Linux `{28,2}` · Android `{33,26}`. Same timing constraint as dhcpHostname.

5. **mDNS / Bonjour enrichment** — `dns-sd` browses all advertised service types every 5 minutes and resolves TXT records:
   - `md=` field → `mdnsModel` (e.g. `HomePod mini`, `BRAVIA XR`)
   - `am=` field → `appleModel` (Apple internal model code, e.g. `AudioAccessory1,1`)
   - `osxvers=` field → `osVersion` (macOS/iOS kernel version)
   - Advertised service types → `mdnsServices` and → `deviceType` (derived via priority-ordered service map: `_airplay._tcp` = Smart Speaker / AV · `_ipp._tcp` = Printer · etc.)
   - Only devices that **actively advertise mDNS services** populate these states. Generic routers, many Android devices, and most Windows PCs do not.

6. **NetBIOS** — `nmblookup -A` runs every 10 minutes on all online devices. Windows computer name → `netbiosName`. Requires NetBIOS/SMB port 137 to be responding (may be disabled on modern Windows).

> **Note on enrichment state population:** `dhcpHostname`, `dhcpOsFingerprint` are only captured on DHCP events (device reconnect / lease renewal). `mdnsModel`, `appleModel`, `osVersion`, `deviceType` require the device to advertise mDNS services. `netbiosName` requires Windows or Samba with NetBIOS enabled. These states may remain empty for devices that are already connected with valid leases, or devices that simply do not support the relevant protocol.

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
| **▶ Activate Tracking Now** | Validate the MAC(s)/IP(s) in *Track Specific Device* and begin detailed tracing immediately — no Save needed. |
| **■ Stop Tracking** | Clear the tracked device list immediately. |
| **Turn Off All Per-Device Logging** | Sets *Log Every Seen Event to File* to `false` on every managed Network Device in one click. |

### Logging Options

| Setting | Description |
|---------|-------------|
| Log New Device Created | Log when a new Indigo device is auto-created for a MAC |
| Log Online / Offline Changes | Log online ↔ offline state transitions. Each message includes the source, e.g. *"Device X is now ONLINE  via sweep (arp)"* or *"is now OFFLINE  [timeout]"* |
| Online / Offline Log Destination | `plugin.log` only — or — `plugin.log` + Indigo event log |
| Log IP Address Changes | Log when a device's IP address changes |
| Log Every Device Seen | Verbose per-packet log (noisy) |
| Log ARP Sweep Activity | Log sweep start / finish, and the ARP cache flush |
| Log Ignored MACs Skipped | Log each time an ignored MAC is seen |
| Log Ping / Probe Results | Log every ICMP ping and TCP probe result (noisy during sweeps) |
| Log Tcpdump ARP Replies | Log every ARP reply captured by tcpdump including throttled ones (very noisy) |
| Log ARP Sweep Entries | Log every entry parsed from `arp -a` during each sweep |

### Per-Device Diagnostic Trace

**Track Specific Device (MAC or IP)** — enter one or more comma-separated MAC addresses (`aa:bb:cc:dd:ee:ff`) or IP addresses (`192.168.1.5`) in the debug section of the configuration dialog.

Use the **▶ Activate Tracking Now** button to start tracing immediately — no need to save the dialog. Use **■ Stop Tracking** to cancel. Tracking is always cleared automatically when the plugin restarts so it can never silently stay on.

While active, every event touching a listed device is written to `plugin.log` at DEBUG level with a `[TRACE <target>]` prefix:

| Tag | What is logged |
|-----|----------------|
| `raw-tcpdump` | Complete raw tcpdump output line (before any parsing or throttle) |
| `sniff-ARP-reply` | ARP reply parsed from tcpdump |
| `sniff-frame` | Non-ARP frame from which src MAC + IP were extracted |
| `arp-a` | Entry parsed from `arp -a` during the sweep, with `replied` flag |
| `_register_device` | Every call that updates `_known` and pushes to Indigo, with `source`, `changed_ip`, `skip_push` |
| `ping-recheck` | Offline-to-online confirmation result (ICMP+TCP guard) |
| `_state_update` | Every Indigo state write — `online_changed`, `source`, `ip_changed` |

> **Validation:** the Activate button accepts only exact MAC format (`xx:xx:xx:xx:xx:xx`) or valid IPv4. Invalid entries are rejected with a descriptive error shown in the dialog.

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

The probe runs **in addition to** passive detection (ARP sweep + tcpdump). Passive detection always marks the device online immediately when traffic is seen; the probe adds a second layer of active confirmation.

**Who wins — a failed ping vs a recent passive sighting?**

| Offline Trigger Logic | Result |
|---|---|
| **AND** *(default)* | **Passive wins** — a recent ARP/tcpdump sighting keeps `timed_out = false`, so a failed ping cannot take the device offline on its own |
| **OR** | **Ping wins** — streak alone triggers offline even if ARP/tcpdump saw the device moments ago |

Ping **success** always wins regardless of mode — device goes online immediately.

| Option | Behaviour | When to use |
|--------|-----------|-------------|
| **Online + Offline** | Probe is additional to passive detection. Success → online immediately; failure → offline only when threshold + streak conditions are met (AND/OR). ICMP first, TCP fallback if ICMP blocked. | Reliable devices that respond to both ping and TCP |
| **Online only** | Probe can only mark online, never offline. Passive timeout still handles going offline. | Fast recovery detection — phone coming home |
| **Offline only** | Probe can only mark offline, never online. Passive still handles going online. | Fast offline detection |
| **Confirm offline** *(default)* | Probe only fires after ARP/sniff timeout is exceeded; silent devices with infrequent traffic | Most LAN devices |
| **Ping only** | ICMP only (no TCP fallback), adaptive 60 s / 15 s interval — see below | Routers, cameras, printers, manually-added devices |
| **Not at all** | Probe ignored; offline decided purely by ARP/sniff timeout | Passive detection is sufficient |

#### Ping only — adaptive timing

**Ping only** uses a dedicated probe schedule independent of the global scan interval:

| Device state | Probe interval | Transition rule |
|---|---|---|
| **Online** | every **60 s** | Goes **offline** only after the *Offline Threshold* expires — a single missed ping is never enough |
| **Offline** | every **15 s** | Goes **online** immediately on the **first** successful ping |

This makes it suitable for devices that suppress ARP and mDNS (routers, cameras, printers) as well as devices added manually with a custom MAC where no passive traffic is expected. The *Offline Trigger Logic* and *Missed Pings Before Offline* settings are not used in this mode — the threshold alone controls the on→off transition.

#### Ping only — quick retry on failure

When *Offline Trigger Logic* is set to **OR** and the first ping fails while the device is online, the plugin immediately sends **2 additional ICMP pings 3 s apart** before accepting the failure — mirroring `ping -c 3 -i 3`. A single dropped packet is confirmed or dismissed within ~6 s rather than waiting for the next 15 s poll cycle.

| Offline Trigger Logic | First ping fails | Action |
|---|---|---|
| **AND** *(default)* | No retry — threshold must also expire before offline is possible; one failure is already safe | Wait for next 15 s poll |
| **OR** | 2 retries × 3 s apart (~6 s) | Offline only if all 3 fail |

> **Note:** The 15 s / 60 s probe intervals and 2 × 3 s retry parameters are defined as named constants at the top of `plugin.py` (`_PING_ONLY_INTERVAL_ONLINE`, `_PING_ONLY_INTERVAL_OFFLINE`, `_PING_RETRY_COUNT`, `_PING_RETRY_INTERVAL`) and can be adjusted there without touching any other logic. The intervals are minimum values — the actual probe fires on the next scan-loop wake-up after the interval has elapsed.

### Offline Trigger Logic

| Option | Behaviour |
|--------|-----------|
| **AND** *(default)* | Timeout expired **AND** probe failed — fewest false alarms |
| **OR** | Timeout expired **OR** probe failed — faster offline detection |

### Other Settings

| Setting | Description | Default |
|---------|-------------|---------|
| Missed Pings Before Offline | Consecutive probe failures before offline is triggered (1–5). Not used in *Ping only* mode. | `1` |
| Offline Threshold (s) | Per-device override; `0` = use plugin-wide default. In *Ping only* mode this is the sole condition that triggers offline. | `0` |
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
| `dhcpHostname` | String | Device hostname from DHCP option 12 — populated on DHCP request/renewal (e.g. `Karl-iPhone`). |
| `dhcpOsFingerprint` | String | OS guess from DHCP option 55 parameter request list: `Windows` · `Apple (macOS/iOS)` · `Linux` · `Android`. Populated on DHCP events only. |
| `mdnsServices` | String | Comma-separated mDNS service types advertised by this device (e.g. `_airplay._tcp, _raop._tcp`). Populated by passive PTR parsing and periodic `dns-sd` browse. |
| `mdnsModel` | String | Device model string from mDNS TXT `md=` field (e.g. `HomePod mini`, `BRAVIA XR`). |
| `deviceType` | String | Device category derived from advertised mDNS services (e.g. `Smart Speaker / AV` · `Printer` · `NAS / Server`). Only set for devices that advertise mDNS. |
| `appleModel` | String | Apple internal model code from mDNS TXT `am=` field (e.g. `AudioAccessory1,1`, `iPhone14,5`). Apple devices only. |
| `osVersion` | String | macOS / iOS kernel version from mDNS TXT `osxvers=` field. Apple devices only. |
| `osHint` | String | Best-guess OS: `Windows` · `Linux/macOS/iOS` · `Android` · `Cisco/Network`. Derived from DHCP vendor class (option 60), DHCP option 55 fingerprint, or IP TTL as last resort. |
| `netbiosName` | String | Windows computer name from NetBIOS Name Service (`nmblookup -A`). Windows / Samba devices only. |
| `networkInterface` | String | Network interface the device was last seen on, from `arp -a` output (e.g. `en0` = Wi-Fi, `en1` = Ethernet). |
| `pingMs` | String | Last ICMP round-trip time in ms (e.g. `12 ms`). Updated each probe cycle. |
| `changeToOn` | String | Timestamp (`YYYY-MM-DD HH:MM:SS`) of the most recent offline → online transition. |
| `changeToOff` | String | Timestamp (`YYYY-MM-DD HH:MM:SS`) of the most recent online → offline transition. |
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
| **Add Internet Ping Devices…** | Select from Google, Yahoo, Microsoft, CNN, AT&T, Siemens, or enter a **custom hostname** (e.g. `www.welt.de`). Creates External Device entries for each selected host — device name is `Ping-{host}` with `www.` stripped. Safe to run multiple times — skips any host that already exists. Also auto-creates a **Ping-NetworkScanner Internet** aggregate device as an internet up/down indicator. This dialog also contains an **Add Internet Address device** button — see *Internet Address* device type below. |
| Scan Open Ports on All Online Devices… | Port-scans all online devices; stores results in `openPorts` state |
| Set a State of Device… | Manually overwrite any state on any plugin device |
| **Print tools…** | Combined reporting dialog with the following buttons: |
| ↳ All discovered devices | Prints all known MACs with IP, local name, vendor, on/off and last-seen to plugin.log |
| ↳ Devices grouped by OS / ports / type | Groups networkDevices by `osHint`, `osVersion`, `dhcpOsFingerprint`, `deviceType`, `networkInterface`, and open port. Only populated buckets are shown. |
| ↳ Devices with IP address changes | Lists devices whose IP address has changed since the plugin started |
| ↳ Devices with empty states | Lists all enrichment state names that are empty across **every** networkDevice — quick check of which data sources have not yet populated any devices. |
| ↳ Instability report | Lists devices with very short on/off intervals (configurable cutoff: 1–8 minutes) |
| ↳ Seen-interval statistics | Histogram of how often each device is seen; sort by IP / name / last seen |
| ↳ Reset seen-interval counters | Clears histogram counters for all devices |
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
- `known_devices.json` is loaded at startup — previously discovered devices are immediately available.
- Each managed device gets a deferred port scan 15 s after startup.
- A **startup grace period** (`self.in_grace_period`) is active from plugin start until the configured *Ignore offline changes at startup* duration expires. While the flag is `True`:
  - Offline state changes are suppressed — sniffing and the first sweep have time to re-confirm devices before anything is marked offline.
  - Ping-only candidate detection is skipped — no "no ARP entry" candidates are evaluated and no synthetic MAC devices are created until after the grace period, preventing false positives when ARP/tcpdump has not yet had time to populate `_known`.
  - The `passive-info` debug log is silenced — bulk state updates from the first sweep do not flood the log.
- The flag is set to `False` by `runConcurrentThread` (the single authoritative location) and is read directly everywhere else — no inline time calculations at the call sites.

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

---

## Fingscan Migration

Two menu items are available under *Plugins → Network Scanner* for migrating from the Fingscan plugin:

| Menu Item | Description |
|-----------|-------------|
| **Import Names from Fingscan** | Reads all Fingscan `IP-Device` entries, matches them to NetworkScanner devices by MAC address, and writes the Fingscan device name into the `fingscanDeviceInfo` state. Logs each matched pair. |
| **Overwrite Device Names with Fingscan Names** | Uses the imported `fingscanDeviceInfo` values to rename each NetworkScanner device to `{fingscan-name}-NET_`. Only renames devices where `fingscanDeviceInfo` is non-empty. |
| **Compare Fingscan ↔ NetworkScanner** | Prints a side-by-side report showing: devices in Fingscan only, devices in NetworkScanner only, and devices in both with a conflicting online/offline state. |

---

*Author: Karl Wachs*
