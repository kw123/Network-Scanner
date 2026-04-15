INSTALLATION
  No third-party packages required.
  All discovery uses macOS built-in tools:
    • /usr/sbin/tcpdump  — passive ARP sniffing
    • /sbin/ping         — subnet sweep and reachability checks
    • /usr/sbin/arp      — reads ARP cache after ping sweep

  Vendor name lookup (bundled — no install):
    MAC2Vendor.py  — downloads IEEE OUI tables on first run, caches locally,
                     auto-refreshes every 10 days

CONFIGURATION  (Plugins → Network Scanner → Configure…)
  Network Interface                 : interface to scan, default en0 (WiFi)
  Scan Interval (seconds)           : how often to ping known devices (menu: 30/60/90/120 s)
  Enable ARP Sweep                  : active subnet sweep on each scan interval
  Enable Passive Sniffing           : listen for ARP traffic between sweeps
  Offline Threshold (seconds)       : how long unreachable before marked offline
                                      (menu: 30–420 s, default 180 s); can be
                                      overridden per device in device edit
  Ignore offline changes at startup : suppress all offline decisions for N seconds
                                      after plugin start, giving ARP time to
                                      re-confirm devices  (menu: 20/40/60/80 s)
  Auto-Create Devices               : automatically create an Indigo device for
                                      each new MAC address discovered
  Device Folder Name                : Indigo folder for Net_* devices, default
                                      "Network Devices" (created automatically)

  Logging section:
    Log New Device Created          : log when an Indigo device is auto-created
    Log Online / Offline Changes    : log state transitions
    Online / Offline Log Destination: plugin.log only  –or–  plugin.log + Indigo log
    Log IP Address Changes          : log when a device changes IP
    Log Every Device Seen           : verbose per-packet log (can be noisy)
    Log ARP Sweep Activity          : log sweep start / finish
    Log Ignored MACs Skipped        : log each time an ignored MAC is seen

PLUGIN MENU  (Plugins → Network Scanner)
  List All Discovered Devices       : prints all known MACs to the Indigo log
                                      with name, IP, on/off state, vendor, last seen
  Force Immediate Rescan            : triggers an ARP sweep + ping check now
  Scan Open Ports on All Online Devices
                                    : runs a port scan on every currently online
                                      device and stores results in openPorts state
  Set a State of Device…            : dialog to manually overwrite any device state
  Print Seen-Interval Statistics…   : histogram of how frequently each device is
                                      seen; sort by IP / name / last seen
  Reset Seen-Interval Statistics    : clears the histogram counters for all devices
  Manage Ignored MAC Addresses…     : dialog to exclude / re-include specific MACs

DEVICE EDIT  (double-click any Net_* device)
  Ping Usage                        : how periodic pings affect online/offline state
    • Online + Offline              : ping sets both directions
    • Online only                   : ping can only mark online
    • Offline only                  : ping can only mark offline
    • Confirm offline (default)     : ping only fires when ARP timeout is exceeded;
                                      logged to plugin.log when ping keeps device online
    • Not at all                    : ping results ignored; ARP timeout alone decides
  Offline Trigger Logic             : AND (timeout AND ping fail, default) or
                                      OR (timeout OR ping fail, faster detection)
  Missed Pings Before Offline       : consecutive failures needed (1–5)
  Offline Threshold (seconds)       : per-device override (0 = use plugin default)
  Comment                           : free-text note, stored in device state "comment"
  Suppress IP Change Logging        : silence IP-change log for this device
  Log Every Seen Event to File      : write a debug entry each time this device is seen

DEVICE STATES
  onOffState        : True = online, False = offline
  ipAddress         : last seen IP address
  macAddress        : MAC address
  vendorName        : manufacturer name (from bundled OUI lookup)
  lastOnOffChange   : timestamp of last online ↔ offline transition
  created           : timestamp when Indigo device was first created
  openPorts         : comma-separated list of open TCP ports (from last port scan)
  comment           : free-text note set in device edit

DEVICE NAMING & SORTING
  Each device is named  Net_AA:BB:CC:DD:EE:FF
  Address column : MAC address  (visible in Indigo device list)
  Notes column   : IP with last octet zero-padded (192.168.1.005) so that
                   alphabetical sort on Notes gives correct IP order

IGNORED MACs  (Plugins → Manage Ignored MAC Addresses…)
  • Top list shows all discovered devices — click one, then click
    "▼ Ignore Selected Device" to exclude it
  • Bottom list shows currently ignored devices — click one, then click
    "▲ Un-ignore Selected Device" to re-enable it
  • Click OK to save
  Ignored MACs are neither created nor updated.

OFFLINE LOGIC
  Default mode is "Confirm offline":
    A device is marked offline only after the ARP offline threshold is
    exceeded AND a confirm-ping also fails.  This avoids false alarms from
    brief network blips or ARP cache staleness.
  When a confirm-ping keeps a device online, a notice is written to
  plugin.log showing how long the device was silent and the threshold used.
  The OFFLINE log message includes the last-seen timestamp and how many
  seconds ago it was.

SEEN-INTERVAL STATISTICS
  The plugin tracks how often each device is seen, bucketed into intervals:
    ≤10 s / ≤30 s / ≤60 s / ≤90 s / ≤120 s / ≤180 s / ≤240 s /
    ≤300 s / >300 s
  Print via Plugins menu → Print Seen-Interval Statistics…
  Reset via Plugins menu → Reset Seen-Interval Statistics

STARTUP BEHAVIOUR
  • On startup all managed devices run a deferred port scan (15 s delay).
  • Offline changes are suppressed for the configured grace period so that
    ARP sniffing and the first sweep have time to re-confirm all devices
    before any device is flipped offline.

