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

- **`/usr/sbin/tcpdump`** — Passive traffic sniffing, captures ARP, mDNS (port 5353) and DHCP (ports 67/68)
- **`/usr/sbin/arp`** — Reads ARP cache after sweep
- **`/sbin/ifconfig`** — Determines local subnet (IP and netmask)
- **`Python socket`** — ICMP ping (`SOCK_DGRAM / IPPROTO_ICMP`) and TCP-connect probe (`SOCK_STREAM`) — no subprocess, no root required
- **`MAC2Vendor.py`** — Bundled OUI vendor lookup, auto-downloads IEEE tables on first run, caches locally

> **macOS password required for tcpdump.**
> `tcpdump` needs elevated privileges to open the BPF network socket for passive sniffing.
> Enter your macOS login password in *Plugins → Network Scanner → Configure… → sudo Password*.
> Leave blank only if tcpdump already has the BPF entitlement granted via `sudo chmod` or a system policy.

---

## Discovery Methods

1. **Passive traffic sniffing** — `tcpdump` listens for ARP, mDNS (port 5353) and DHCP (ports 67/68). Any matching packet updates the device's last-seen timestamp. Catches devices that suppress ARP (iOS privacy mode, VMs, IoT). Each MAC throttled to one Indigo update per 30 s. Requires sudo password if tcpdump does not already have the BPF entitlement.

2. **Active ARP sweep** — sends parallel ICMP pings to every host on the subnet, then reads the kernel ARP cache with `arp -a`. Only devices that actually respond to ping or TCP probe have their last-seen updated. Stale cache entries do not count as online. After processing, the plugin runs `sudo arp -d -a` to flush the ARP cache so stale entries from powered-off devices do not persist into the next cycle (requires sudo password). The `arp -a` output also captures the network interface (`en0` = Wi-Fi, `en1` = Ethernet) for each device, stored in `networkInterface`.

3. **Periodic reachability probe** — runs every scan-interval:
   - ICMP ping via Python socket (no subprocess, no root) — records round-trip time (`pingMs`) and IP TTL.
   - TTL is used to derive a fallback OS hint when no better source is available: 128 → Windows · 64 → Linux / macOS / iOS · 255 → Router / network gear.
   - TCP connect fallback on ports 80 → 443 → 22 → 8080 if ICMP is blocked. `ConnectionRefusedError` counts as alive.
   - Winning TCP port remembered per device and tried first next time.
   - After 5 consecutive all-port failures the TCP probe is suspended (auto-resets when ping succeeds).
   - Per-device **Ping only** option skips TCP fallback entirely.
   - **Sweep-freshness skip:** if the ARP sweep confirmed a non-pingOnly device within the last `scan-interval − 10 s`, the per-device probe is skipped — the sweep result is used directly, reducing redundant probing. pingOnly devices have their own adaptive timer (see below) and are handled separately: if the ARP sweep pinged the same IP within the last 10 s, the dedicated pingOnly probe is skipped for that cycle and the timer is advanced, preventing a double-ping.
   - **False-positive guard (confirm mode):** when a device that is currently offline gets a positive ICMP response, a TCP probe is run as confirmation before the device is brought back online. Routers proxy ICMP for recently-disconnected clients but never proxy TCP, so a TCP reply proves the device's own stack is alive. If TCP has worked before for this device (`curlPort` is set) but is failing now, the device stays offline — no second-ICMP fallback (which proxy-ARP can fake). Second ICMP is used only for devices where TCP has genuinely never worked (pure IoT with no open ports).
   - **False-positive guard (pingOnly mode):** the ARP sweep may reset `last_seen` via proxy-ARP replies even when the device is offline, preventing the offline threshold from expiring. `pingOnly` devices use a separate `ping_only_last_ping_ok` timestamp that is updated only by the dedicated ICMP probe — never by the ARP sweep. The offline threshold is measured against this timestamp, making it immune to proxy-ARP sweep noise.

4. **DHCP enrichment** — the separate DHCP sniffer (`tcpdump -vv` on ports 67/68) extracts:
   - **Option 12** (hostname) → `dhcpHostname`. Populated only when a device sends a DHCP request — typically on first connect or lease renewal (can take hours for already-connected devices).
   - **Option 55** (parameter request list) → `dhcpOsFingerprint`. The sequence of option numbers acts as an OS fingerprint: Windows `{249,252}` · Apple macOS/iOS `[_, 121, ...]` · Linux `{28,2}` · Android `{33,26}`. Same timing constraint as dhcpHostname.

5. **mDNS / Bonjour enrichment** — `dns-sd` browses all advertised service types every 5 minutes and resolves TXT records:
   - `md=` field → `mdnsModel` (e.g. `HomePod mini`, `BRAVIA XR`)
   - `am=` field → `appleModel` (Apple internal model code, e.g. `AudioAccessory1,1`)
   - `osxvers=` field → `osVersion` (macOS/iOS kernel version)
   - Advertised service types → `mdnsServices` and → `deviceType` (derived via priority-ordered service map: `_airplay._tcp` = Smart Speaker / AV · `_ipp._tcp` = Printer · etc.)
   - Only devices that **actively advertise mDNS services** populate these states. Generic routers, many Android devices, and most Windows PCs do not.

> **Note on enrichment state population:** `dhcpHostname`, `dhcpOsFingerprint` are only captured on DHCP events (device reconnect / lease renewal). `mdnsModel`, `appleModel`, `osVersion`, `deviceType` require the device to advertise mDNS services. These states may remain empty for devices that are already connected with valid leases, or devices that simply do not support the relevant protocol.

---

## Plugin Configuration

*Plugins → Network Scanner → Configure…*

- **Network Interface** — Interface to sniff (e.g. `en0`, `eth0`). Leave blank to auto-detect. *(default: auto)*
- **sudo Password** — macOS login password so tcpdump can open the BPF socket. Leave blank if tcpdump already has the entitlement.
- **Scan Interval (s)** — How often to probe known devices. Options: 30 / 60 / 90 / 120. *(default: 60)*
- **Enable ARP Sweep** — Active subnet sweep each scan cycle. *(default: on)*
- **Enable Passive Traffic Sniffing** — Listen for ARP / mDNS / DHCP traffic between sweeps. *(default: on)*
- **Enable Active mDNS Query** — Send an mDNS PTR query at the start of each ARP sweep to prompt all mDNS-capable devices to announce themselves. Useful for devices hidden behind proxy-ARP APs. *(default: off)*
- **Offline Threshold (s)** — Unreachable for this long → marked offline. Options: 30–600 s. *(default: 180)*
- **Auto-Create Devices** — Create an Indigo device for each new MAC address discovered. *(default: on)*
- **Create Synthetic Devices for Ping-Only Hosts** — If an IP responds to ping but never appears in ARP (e.g. different VLAN), create a device with a synthetic MAC `00:00:00:00:00:XX`. Leave off unless you need cross-VLAN monitoring — some routers answer ping for every subnet IP, flooding the plugin with ghost devices. *(default: off)*
- **Flip Address / Notes Columns** — Swap the Address and Notes columns for all plugin devices simultaneously. OFF (default): Address = MAC / host, Notes = IP. ON: Address = IP, Notes = MAC / host. Takes effect immediately on Save — all devices are updated at once. *(default: off)*
- **Device Folder Name** — Indigo folder for `Net_*` devices (auto-created). Leave blank for root. *(default: Network Devices)*
- **Variable Folder Name** — Indigo variable folder for plugin-managed variables. Auto-created. Leave blank for root.
- **Prefix Name** — Prefix for auto-named devices (e.g. `Net_` → `Net_AA:BB:CC:DD:EE:FF`). *(default: Net_)*

### Quick-Setup Buttons

- **▶ Activate Tracking Now** — Validate the MAC(s)/IP(s) in *Track Specific Device* and begin detailed tracing immediately — no Save needed.
- **■ Stop Tracking** — Clear the tracked device list immediately.
- **Turn Off All Per-Device Logging** — Sets *Log Every Seen Event to File* to `false` on every managed Network Device in one click.

### Logging Options

- **Log New Device Created** — Log when a new Indigo device is auto-created for a MAC.
- **Log Online / Offline Changes** — Log online ↔ offline state transitions to `plugin.log`. Each message includes the source, e.g. *"Device X is now ONLINE  via sweep (arp)"* or *"is now OFFLINE  [timeout]"*.
- **Log IP Address Changes** — Log when a device's IP address changes.
- **Log Every Device Seen** — Verbose per-packet log (noisy).
- **Log ARP Sweep Activity** — Log sweep start / finish, and the ARP cache flush.
- **Log Ignored MACs Skipped** — Log each time an ignored MAC is seen.
- **Log Ping / Probe Results** — Log every ICMP ping and TCP probe result (noisy during sweeps).
- **Log Tcpdump ARP Replies** — Log every ARP reply captured by tcpdump including throttled ones (very noisy).
- **Log ARP Sweep Entries** — Log every entry parsed from `arp -a` during each sweep.

### Per-Device Diagnostic Trace

**Track Specific Device (MAC or IP)** — enter one or more comma-separated MAC addresses (`aa:bb:cc:dd:ee:ff`) or IP addresses (`192.168.1.5`) in the debug section of the configuration dialog.

Use the **▶ Activate Tracking Now** button to start tracing immediately — no need to save the dialog. Use **■ Stop Tracking** to cancel. Tracking is always cleared automatically when the plugin restarts so it can never silently stay on.

While active, every event touching a listed device is written to `plugin.log` at DEBUG level with a `[TRACE <target>]` prefix:

- **`raw-tcpdump`** — Complete raw tcpdump output line (before any parsing or throttle)
- **`sniff-ARP-reply`** — ARP reply parsed from tcpdump
- **`sniff-frame`** — Non-ARP frame from which src MAC + IP were extracted
- **`arp-a`** — Entry parsed from `arp -a` during the sweep, with `replied` flag
- **`_register_device`** — Every call that updates `_known` and pushes to Indigo, with `source`, `changed_ip`, `skip_push`
- **`ping-recheck`** — Offline-to-online confirmation result (ICMP+TCP guard)
- **`_state_update`** — Every Indigo state write — `online_changed`, `source`, `ip_changed`

> **Validation:** the Activate button accepts only exact MAC format (`xx:xx:xx:xx:xx:xx`) or valid IPv4. Invalid entries are rejected with a descriptive error shown in the dialog.

---

## Device Types

### Network Device  (`Net_*`)

One device per discovered MAC address. Auto-created when **Auto-Create Devices** is on.

- **Address column**: MAC address (or padded IP when *Flip Address / Notes* is ON)
- **Notes column**: IP with last octet zero-padded (e.g. `192.168.1.005`) for correct alphabetical sort by IP (or MAC when *Flip* is ON)
- Name starts as `Net_AA:BB:CC:DD:EE:FF`, then automatically renamed to include vendor / local name once known

### External Device

A manually configured host (IP address or DNS name) pinged on a fixed interval. No MAC tracking — useful for monitoring internet connectivity. Create via *New Device → External Device* or use **Add Internet Ping Devices…** in the plugin menu.

- **Address column**: configured hostname / IP (or resolved IP when *Flip Address / Notes* is ON)
- **Notes column**: resolved IP address (or hostname when *Flip* is ON), updated live on each ping

### Network Devices — Home or Away

Aggregate device that watches up to **6 Network Devices** and tracks presence.

- **ON** — at least one watched device is online ("someone home")
- **OFF** — all watched devices are offline ("everyone away")
- `ParticipantsHome` — count of currently online participants
- `participants` — comma-separated Indigo device IDs of all configured slots
- **Address column** — MAC addresses of all participants (space-separated), updated live. When *Flip Address / Notes* is ON: compact IP summary — if all participants share the same /24 subnet the common prefix is shown once (e.g. `192.168.1. 112 22 44`); otherwise full IPs are shown.
- **Notes column** — current IP addresses in compact form (e.g. `192.168.1. - 12 15 25`), updated live (or MACs when *Flip* is ON)

**Delay before OFF** — optional grace period (0 / 10 / 20 / 30 / 60 / 90 / 120 / 180 s) before the device flips to OFF when all participants go offline. If any participant comes back online during the delay the OFF transition is cancelled and the device stays ON. Useful to absorb brief WiFi drops or proxy-ARP timing artefacts that would otherwise trigger Away automations prematurely. Default is 0 (immediate).

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

- **Display state**: `publicIp` — shown as `on   203.0.113.42` or `off   203.0.113.42` so status and IP are visible at a glance. The state *value* (for triggers and scripts) is always the bare IP address only.
- **ON** — last fetch succeeded
- **OFF** — all services unreachable (internet appears down)
- **Address column** — current public IP address, updated on each successful fetch
- **Notes column** — mirrors the current public IP for easy reading

**Services tried in order** (first to respond wins): `api.ipify.org` → `checkip.amazonaws.com` → `icanhazip.com`. Each has a 10-second timeout.

Create via *Plugins → Network Scanner → Add Internet Address Device…* (safe to click multiple times — skips if device already exists).

---

## Device Edit — Network Device

*Double-click any `Net_*` device*

### Ping / Probe Usage

The probe runs **in addition to** passive detection (ARP sweep + tcpdump). Passive detection always marks the device online immediately when traffic is seen; the probe adds a second layer of active confirmation.

**Who wins — a failed ping vs a recent passive sighting?**

- **AND** *(default)* — Passive wins. A recent ARP/tcpdump sighting keeps `timed_out = false`, so a failed ping cannot take the device offline on its own.
- **OR** — Ping wins. Streak alone triggers offline even if ARP/tcpdump saw the device moments ago.

Ping **success** always wins regardless of mode — device goes online immediately.

**Probe mode options:**

- **Online + Offline** — Probe is additional to passive detection. Success → online immediately; failure → offline only when threshold + streak conditions are met (AND/OR). ICMP first, TCP fallback if ICMP blocked. *Use for: reliable devices that respond to both ping and TCP.*
- **Online only** — Probe can only mark online, never offline. Passive timeout still handles going offline. *Use for: fast recovery detection — phone coming home.*
- **Offline only** — Probe can only mark offline, never online. Passive still handles going online. *Use for: fast offline detection.*
- **Confirm offline** *(default)* — Probe only fires after ARP/sniff timeout is exceeded; silent devices with infrequent traffic. *Use for: most LAN devices.*
- **Ping only** — ICMP only (no TCP fallback), adaptive 60 s / 15 s interval — see below. *Use for: routers, cameras, printers, manually-added devices.*
- **Not at all** — Probe ignored; offline decided purely by ARP/sniff timeout. *Use for: passive detection is sufficient.*

#### Ping only — adaptive timing

**Ping only** uses a dedicated probe schedule that runs independently of the global scan interval (the scan loop checks pingOnly devices every 15 s so the adaptive timer fires on time regardless of the sweep period):

- **Online** — probe every 60 s (or the *Online Ping Interval* if set). Goes offline only after the *Offline Threshold* expires — a single missed ping is never enough.
- **Offline** — probe every 15 s (or the *Offline Check Interval* if set). Goes online immediately on the first successful ping.

The offline threshold is measured against `ping_only_last_ping_ok` — a timestamp that is updated only when the dedicated probe itself succeeds. The ARP sweep may receive proxy-ARP replies for offline devices and would otherwise reset `last_seen`, preventing the threshold from ever expiring. `ping_only_last_ping_ok` is unaffected by sweep results.

This makes it suitable for devices that suppress ARP and mDNS (routers, cameras, printers) as well as devices added manually with a custom MAC where no passive traffic is expected. The *Offline Trigger Logic* and *Missed Pings Before Offline* settings are not used in this mode — the threshold alone controls the on→off transition.

> **Tip:** Set *Online Ping Interval* to 30–50 % of the *Offline Threshold* so the device is confirmed online at least twice before it can time out. For example, with a 3-minute threshold, set the interval to 60–90 s.

#### Ping only — quick retry on failure

When *Offline Trigger Logic* is set to **OR** and the first ping fails while the device is online, the plugin immediately sends **2 additional ICMP pings 3 s apart** before accepting the failure — mirroring `ping -c 3 -i 3`. A single dropped packet is confirmed or dismissed within ~6 s rather than waiting for the next 15 s poll cycle.

- **AND** *(default)* — No retry. Threshold must also expire before offline is possible; one failure is already safe. Waits for next 15 s poll.
- **OR** — 2 retries × 3 s apart (~6 s total). Offline only if all 3 fail.

> **Note:** The 15 s / 60 s probe intervals and 2 × 3 s retry parameters are defined as named constants at the top of `plugin.py` (`_PING_ONLY_INTERVAL_ONLINE`, `_PING_ONLY_INTERVAL_OFFLINE`, `_PING_RETRY_COUNT`, `_PING_RETRY_INTERVAL`) and can be adjusted there without touching any other logic.

### Offline Trigger Logic

- **AND** *(default)* — Timeout expired AND probe failed — fewest false alarms.
- **OR** — Timeout expired OR probe failed — faster offline detection.

### Other Settings

- **Missed Pings Before Offline** — Consecutive probe failures before offline is triggered (1–5). Not used in *Ping only* mode. *(default: 1)*
- **Offline Check Interval** — How often to probe this device while it is offline to detect recovery. Only active when ping is enabled (any mode except *Not at all*). `0` = use the global Scan Interval. Smaller values catch recovery faster at the cost of more pings. Not used in *Ping only* mode (which has its own 15 s adaptive timer). *(default: 0)*
- **Online Ping Interval** — How often to ping this device while it is online. `0` = default (60 s for *Ping only*; global Scan Interval for other modes). Increase to reduce traffic for stable devices; decrease for faster re-confirmation. Recommended: set to 30–50 % of the *Offline Threshold* so the device is confirmed at least twice before timing out. Applies to all active ping modes. *(default: 0)*
- **Offline Threshold (s)** — Per-device override; `0` = use plugin-wide default. In *Ping only* mode this is the sole condition that triggers offline. *(default: 0)*
- **Set IP Address** — Manually override the IP address for this device. Stored in `ipNumber` state and `known_devices.json`. Will be overwritten on the next scan if the device is seen with a different IP.
- **Is AP or Router** — Mark this device as a proxy-ARP AP or router. IP changes from the passive sniff thread are ignored; only the ARP sweep can update its IP. Set automatically when 3 or more IP changes are detected within 10 minutes. Can be cleared here to re-enable auto-detection. *(default: off)*
- **Comment** — Free-text note stored in the `comment` state.
- **Suppress IP Change Logging** — Silence IP-change log entries for this device. *(default: off)*
- **Log Every Seen Event to File** — Write a `plugin.log` entry each time this device is seen. *(default: off)*

---

## Device States — Network Device

- **`onOffState`** (Boolean) — `True` = online, `False` = offline
- **`ipNumber`** (String) — Last seen IP address
- **`previousIps`** (String) — Last 10 IP addresses used by this device with dates, e.g. `192.168.1.100  (2026-04-20)  |  192.168.1.101  (2026-04-19)`. Updated each time the IP changes.
- **`MACNumber`** (String) — MAC address
- **`mdnsName`** (String) — Hostname from mDNS / Bonjour SRV records (e.g. `iPhone-Karl.local`). Populated by the passive sniff thread and mDNS browse.
- **`arpHostname`** (String) — Hostname from `arp -a` output — the first field when macOS resolves a Bonjour name for the IP (e.g. `iphone.localdomain`). Updated each ARP sweep. Only set when a real name (not `?`) is found.
- **`hardwareVendor`** (String) — Manufacturer from bundled OUI table
- **`dhcpHostname`** (String) — Device hostname from DHCP option 12, populated on DHCP request/renewal (e.g. `Karl-iPhone`).
- **`dhcpOsFingerprint`** (String) — OS guess from DHCP option 55 parameter request list: `Windows` · `Apple (macOS/iOS)` · `Linux` · `Android`. Populated on DHCP events only.
- **`mdnsServices`** (String) — Comma-separated mDNS service types advertised by this device (e.g. `_airplay._tcp, _raop._tcp`). Cumulative — services are added but never removed.
- **`mdnsModel`** (String) — Device model string from mDNS TXT `md=` field (e.g. `HomePod mini`, `BRAVIA XR`).
- **`deviceType`** (String) — Device category derived from advertised mDNS services (e.g. `Smart Speaker / AV` · `Printer` · `NAS / Server`). Only set for devices that advertise mDNS.
- **`appleModel`** (String) — Apple internal model code from mDNS TXT `am=` field (e.g. `AudioAccessory1,1`, `iPhone14,5`). Apple devices only.
- **`osVersion`** (String) — macOS / iOS kernel version from mDNS TXT `osxvers=` field. Apple devices only.
- **`osHint`** (String) — Best-guess OS: `Windows` · `Linux/macOS/iOS` · `Android` · `Cisco/Network`. Derived from DHCP vendor class (option 60), DHCP option 55 fingerprint, or IP TTL as last resort.
- **`networkInterface`** (String) — Network interface the device was last seen on, from `arp -a` output (e.g. `en0` = Wi-Fi, `en1` = Ethernet).
- **`pingMs`** (String) — Last ICMP round-trip time in ms (e.g. `12 ms`). Updated only when RTT changes by more than 40% and more than 20 ms.
- **`changeToOn`** (String) — Timestamp (`YYYY-MM-DD HH:MM:SS`) of the most recent offline → online transition.
- **`changeToOff`** (String) — Timestamp (`YYYY-MM-DD HH:MM:SS`) of the most recent online → offline transition.
- **`lastOnOffChange`** (String) — Timestamp of last online ↔ offline transition.
- **`created`** (String) — Timestamp when the Indigo device was first created.
- **`openPorts`** (String) — Comma-separated open TCP ports from last port scan.
- **`comment`** (String) — Free-text note set in device edit.
- **`isApOrRouter`** (Boolean) — `True` when the device is a proxy-ARP AP or router. Set automatically after 3+ IP changes within 10 minutes, or manually in device edit. When `True`, IP updates from passive sniffing are suppressed — only the ARP sweep can change the IP.
- **`pingMode`** (String) — Ping/probe mode synced from device settings (e.g. `both`, `confirm`, `none`).
- **`lastOnMessage`** (String) — Timestamp of the most recent online confirmation (`YYYY-MM-DD HH:MM`). Updated at most once per minute while the device is online.
- **`setOnBy`** (String) — What mechanism last set the device online: `sweep (arp)` · `traffic observed (tcpdump)` · `ping(ICMP)` · `tcp:<port>`.
- **`setOffBy`** (String) — What mechanism last set the device offline: `timeout` · `probe`.
- **`fingscanDeviceInfo`** (String) — Fing scan info imported via migration tool.

---

## Device States — External Device

- **`onOffState`** (Boolean) — `True` = reachable, `False` = offline
- **`host`** (String) — Configured hostname or IP
- **`ipNumber`** (String) — Resolved IP address
- **`pingMs`** (String) — Last ping round-trip time (e.g. `12 ms`) or `timeout`
- **`lastOnOffChange`** (String) — Timestamp of last online ↔ offline transition
- **`comment`** (String) — Free-text note

---

## Device States — Aggregate Devices

Applies to both **Network Devices — Home or Away** and **External Devices — Online / Offline**.

- **`onOffState`** (Boolean) — `True` = at least one participant is online/home
- **`ParticipantsHome`** / **`ParticipantsOnline`** (Integer) — Count of currently online/home participants
- **`participants`** (String) — Comma-separated Indigo device IDs of all configured slots
- **`lastOnOffChange`** (String) — Timestamp of last on/off transition
- **`comment`** (String) — Free-text note

---

## Device States — Internet Address

- **`onOffState`** (Boolean) — `True` = last fetch succeeded, `False` = all services unreachable
- **`publicIp`** (String) — Current public (WAN) IP address. State *value* = bare IP; displayed in the Indigo device list as `on   203.0.113.42` / `off   203.0.113.42`.
- **`previousIp`** (String) — IP address before the most recent change
- **`lastChanged`** (String) — Timestamp when `publicIp` last changed
- **`lastSuccessfulUpdate`** (String) — Timestamp of the most recent successful fetch (`YYYY-MM-DD HH:MM:SS`)
- **`lastFailedUpdate`** (String) — Timestamp of the most recent failed fetch (`YYYY-MM-DD HH:MM:SS`)
- **`comment`** (String) — Free-text note

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

- **`networkScanner_newdevice`** — Updated on every new Network Device auto-creation. Value: `{deviceId}  {timestamp}`. Created at startup if it doesn't exist. Placed in the configured Variable Folder.
- **`networkScanner_pingDevice`** — Updated after every manual ping (menu item, action, or Add Internet Ping Devices). Value: `{ip} {ms}ms on/off` (e.g. `142.250.80.46 22ms on`). Created at startup if it doesn't exist.

---

## Plugin Menu

*Plugins → Network Scanner*

- **Force Immediate Rescan** — Triggers an ARP sweep + ping check immediately.
- **Ping a Device (IP or DNS)…** — Enter any IP address or DNS name, click PING. Result is logged and written to `networkScanner_pingDevice` as `{ip} {ms}ms on/off`.
- **Add Internet Ping Devices…** — Select from Google, Yahoo, Microsoft, CNN, Siemens, SAP, Indigodomo, or enter a custom hostname. Creates External Device entries for each selected host — device name is `Ping-{host}`. Safe to run multiple times — skips any host that already exists. Also contains an **Add Internet Address device** button.
- **Perform Broad Port Scan on All Online Devices…** — TCP connect scan of all 25 known ports on every online device. Menu-triggered run is verbose: every device shown with all ports found; newly discovered ports marked `++++ new ++++`. Also runs automatically once per night after 02:00 in quiet mode — only devices with newly discovered ports are printed, plus `no new ports found` if nothing changed.
- **Set a State of Device…** — Manually overwrite any state on any plugin device.
- **Print tools…** — Combined reporting dialog:
  - *All discovered devices* — Prints all known MACs with IP, local name, vendor, on/off and last-seen to plugin.log.
  - *Devices grouped by OS / ports / type* — Groups networkDevices by `osHint`, `osVersion`, `dhcpOsFingerprint`, `deviceType`, `networkInterface`, and open port. Only populated buckets are shown.
  - *Devices with IP address changes* — Lists devices whose IP address has changed since the plugin started.
  - *Devices with empty states* — Lists all enrichment state names that are empty across every networkDevice.
  - *Instability report* — Lists devices with very short on/off intervals (configurable cutoff: 1–8 minutes).
  - *Seen-interval statistics* — Histogram of how often each device is seen; sort by IP / name / last seen.
  - *Reset seen-interval counters* — Clears histogram counters for all devices.
- **Manage Ignored MAC Addresses…** — Exclude / re-include specific MACs from scanning.
- **Track Device / Logging Tools…** — Per-device debug trace by MAC or IP. Logs every tcpdump line, ARP hit, ping probe and state change for listed devices. Also contains a button to turn off all per-device logging at once.
- **Help…** — Prints a short plugin summary (device types, all menu items) followed by the full README to plugin.log.
- **Fingscan Migration Tools…** — See *Fingscan Migration* section below.

---

## Actions

*Available in Indigo Action Groups*

- **Ping Address** — Ping any IP address or DNS hostname. The result is written to `plugin.log` and to the variable `networkScanner_pingDevice` as `{ip} {ms}ms on/off`.

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

Two separate states capture device hostnames from different sources:

- **`mdnsName`** — from mDNS / Bonjour SRV records (passive sniff thread or `dns-sd` browse). Example: `iPhone-Karl.local`. More reliable; only updated when a DNS-SD packet is seen.
- **`arpHostname`** — from the first field of `arp -a` output, which macOS fills from its Bonjour cache. Example: `iphone-karl.localdomain`. Updated every ARP sweep, but only when a real name (not `?`) is found.

Both states are write-once-per-source — a `?` result from `arp -a` never erases a previously discovered `arpHostname`. Devices that don't advertise Bonjour names have both states empty.

---

## Scanned TCP Ports

21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP),
443 (HTTPS), 445 (SMB), 548 (AFP), 554 (RTSP), 587 (SMTP submission), 631 (IPP/printing),
993 (IMAPS), 995 (POP3S), 1883 (MQTT), 3306 (MySQL), 3389 (RDP), 5000 (UPnP/dev server),
5900 (VNC), 8080 (HTTP-alt), 8443 (HTTPS-alt), 9100 (Raw printing), 32400 (Plex)

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

- **`ts`** — Timestamp of the change
- **`old_ip`** — Previous IP address
- **`new_ip`** — New IP address
- **`source`** — `scan` (changed by ARP sweep / sniff) or `manual` (set via device edit)

Visible in *List All Discovered Devices* and *Print IP-Changed Devices* menu items, where each line shows `[scan]` or `[manual]`.

---

## Fingscan Migration

Four tools under *Plugins → Network Scanner → Fingscan Migration Tools…*:

- **(0) Compare** — Prints a side-by-side report: devices in Fingscan only, devices in NetworkScanner only, and devices in both with a conflicting online/offline state.
- **(1) Import Names** — Matches Fingscan `IP-Device` entries to NetworkScanner devices by MAC and writes the Fingscan name into the `fingscanDeviceInfo` state of each matched device.
- **(2) Overwrite Names** — Uses the imported `fingscanDeviceInfo` values to rename each NetworkScanner device to `{fingscan-name}-{prefix}` (e.g. `Karl iPhone-Net`). Only renames devices where `fingscanDeviceInfo` is non-empty.
- **(3) Copy New — COPY NEW button** — Finds Fingscan devices whose MAC has no match in NetworkScanner and creates a new `networkDevice` for each one:
  - `pingMode = "pingOnly"`, device starts **disabled** — enable each one manually to begin monitoring
  - Name format: `{fingscan-name}-{prefix}-ping-only` (e.g. `Karl iPhone-Net-ping-only`)
  - MAC, IP, and vendor are seeded from Fingscan
  - **Skipped automatically** (shown in log): devices with no IP, IP `0.0.0.0`, or a non-private (public/internet) IP address — add those as External Devices instead. Private ranges accepted: `10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`

---

*Author: Karl Wachs*
