#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------
# PLUGIN_HELP  — printed by Plugins → Network Scanner → Help
# Also assigned to __doc__ so it appears in pydoc / introspection.
# ---------------------------------------------------------------------------
PLUGIN_HELP = """\
================================================================================
Network Scanner – Indigo Plugin
================================================================================
Discovers all devices on the local LAN and creates one Indigo device per unique
MAC address found.  The device's on/off state reflects whether the physical
device is currently reachable on the network.

REQUIREMENTS  (macOS built-ins — nothing to install)
  /usr/sbin/tcpdump   — passive traffic sniffing (ARP + mDNS + DHCP)
  /usr/sbin/arp       — reads ARP cache after sweep
  MAC2Vendor.py       — bundled OUI vendor lookup (auto-downloads + caches)
  Python socket       — ICMP ping and TCP-port probes; no subprocess, no root needed

--------------------------------------------------------------------------------
DISCOVERY METHODS
  1. Passive traffic sniffing — tcpdump listens for ARP, mDNS (port 5353) and
                                DHCP (ports 67/68).  Any matching packet from a
                                device updates its last-seen timestamp.
                                Catches devices that suppress ARP (iOS privacy
                                mode, VMs, IoT).  Each MAC throttled to one
                                update per 30 s to avoid Indigo API flooding.
                                Requires sudo password in plugin config if
                                tcpdump does not already have the BPF entitlement.
  2. Active ARP sweep         — parallel ICMP ping sweep of the entire subnet,
                                then reads ARP cache.  Only devices that respond
                                to ping (or TCP probe) update last-seen; stale
                                ARP cache entries do not count as "online".
  3. Periodic reachability    — each scan cycle probes every known device:
                                  a. ICMP ping via Python socket (no subprocess)
                                  b. If ping fails (or is blocked): TCP connect
                                     on ports 80 → 443 → 22 → 8080 via Python
                                     socket.  Connection refused counts as alive.
                                  c. Per-device option to skip TCP fallback and
                                     use ICMP-only for online/offline decisions.
                                The winning TCP port is remembered per device so
                                subsequent probes go straight to that port first.
                                After 5 consecutive all-port failures the TCP
                                probe is suspended for that device (auto-resets
                                when ping next succeeds).

--------------------------------------------------------------------------------
PLUGIN CONFIGURATION  (Plugins → Network Scanner → Configure…)
  Network Interface                 interface to sniff, default en0 (WiFi)
  sudo Password                     macOS login password so tcpdump can open the
                                    raw BPF socket via  echo <pw> | sudo -S.
                                    Leave blank if tcpdump already has the
                                    entitlement (common after granting access once).
  Scan Interval (s)                 how often to probe known devices [30/60/90/120]
  Enable ARP Sweep                  active subnet sweep each scan cycle
  Enable Passive Traffic Sniffing   listen for ARP/mDNS/DHCP between sweeps
  Offline Threshold (s)             unreachable for this long → marked offline
                                    [30/60/90/120/180/240/300/360/420, default 180]
                                    can be overridden per device in device edit
  Ignore offline changes at startup suppress offline decisions for N seconds after
                                    plugin start so sniffing can re-confirm devices
                                    [20/40/60/80, default 60]
  Auto-Create Devices               create an Indigo device for each new MAC found
  Device Folder Name                Indigo folder for Net_* devices (auto-created)
                                    default "Network Devices", blank = root

  ── Logging ──
  Log New Device Created            log when a new Indigo device is auto-created
  Log Online / Offline Changes      log online ↔ offline state transitions
  Online / Offline Log Destination  plugin.log only  –or–  plugin.log + Indigo log
  Log IP Address Changes            log when a device's IP changes
  Log Every Device Seen             verbose per-packet log (can be noisy)
  Log ARP Sweep Activity            log sweep start / finish
  Log Ignored MACs Skipped          log each time an ignored MAC is seen
  Log Ping / Probe Results          log every ICMP ping and TCP probe result
                                    (can be noisy during sweeps)

--------------------------------------------------------------------------------
DEVICE EDIT  (double-click any Net_* device)
  Ping / Probe Usage
    Controls how the periodic reachability probe affects online/offline state.
    The probe is: ICMP ping → TCP connect fallback (unless "ICMP Only" is set).

    Online + Offline (both)         probe sets both online and offline state
                                    → use for verbose tracking of a device
    Online only                     probe can mark online, not offline
                                    → use to get devices back online fast after they
                                      reappear (e.g. phone leaving/returning home)
    Offline only                    probe can mark offline, not online
                                    → use to make devices go offline fast when they disappear
    Confirm offline  [default]      probe only fires when sniff/ARP timeout exceeded;
                                    logged to plugin.log when probe keeps device online
                                    → use for quiet devices that must not go offline too fast
    Not at all                      probe ignored; sniff/ARP timeout alone decides offline
                                    → use when passive detection alone is sufficient
  ICMP Ping Only (no TCP fallback)  skip the TCP socket probe for this device;
                                    online/offline decided by ICMP ping alone
                                    → use for routers, cameras, printers where
                                      TCP probing is undesirable
  Offline Trigger Logic
    AND  [default]                  timeout expired AND probe failed (fewest false alarms)
    OR                              timeout expired OR  probe failed (faster detection)
  Missed Pings Before Offline       consecutive probe failures before offline [1–5, default 1]
  Offline Threshold (s)             per-device override; 0 = use plugin-wide default
  Comment                           free-text note, stored in device state "comment"
  Suppress IP Change Logging        silence IP-change log for this device only
  Log Every Seen Event to File      write plugin.log entry each time this device is seen

--------------------------------------------------------------------------------
DEVICE STATES
  onOffState          True = online / reachable,  False = offline
  ipAddress           last seen IP address
  macAddress          MAC address
  vendorName          manufacturer name (from bundled OUI table)
  lastOnOffChange     timestamp of last online ↔ offline transition
  created             timestamp when the Indigo device was first created
  openPorts           comma-separated open TCP ports from last port scan
  comment             free-text note set in device edit
  localName           mDNS / Bonjour hostname from arp -a  (e.g. "iPhone.local");
                      populated during ARP sweep; empty if device has no announced name

DEVICE NAMING & SORTING
  Name    : Net_AA:BB:CC:DD:EE:FF  (or  Net_AA:BB:CC:DD:EE:FF  VendorName)
  Address : MAC address (shown in Indigo device list Address column)
  Notes   : IP with last octet zero-padded  e.g. 192.168.1.005
            → correct alphabetical sort by IP in the Notes column

--------------------------------------------------------------------------------
PLUGIN MENU  (Plugins → Network Scanner)
  List All Discovered Devices       prints all known MACs with IP, state, vendor,
                                    last-seen to plugin.log
  Force Immediate Rescan            triggers ARP sweep + ping check immediately
  Scan Open Ports on All Online     port-scans every currently online device;
  Devices…                          stores results in the openPorts device state
  Set a State of Device…            manually overwrite any state on any Net_* device
  Print Seen-Interval Statistics…   histogram of how often each device is seen;
                                    sort by IP / device name / last seen
  Reset Seen-Interval Statistics    clears histogram counters for all devices
  Manage Ignored MAC Addresses…     exclude / re-include specific MACs from scanning
  Help                              print this help text to plugin.log

--------------------------------------------------------------------------------
SEEN-INTERVAL STATISTICS
  Tracks time between consecutive sightings of each device, bucketed as:
    ≤10s  ≤30s  ≤60s  ≤90s  ≤120s  ≤180s  ≤240s  ≤300s  >300s
  Use Print Seen-Interval Statistics… to view; Reset to clear counters.

--------------------------------------------------------------------------------
IGNORED MACs  (Plugins → Manage Ignored MAC Addresses…)
  Top list    : all discovered devices  — select one → ▼ Ignore
  Bottom list : currently ignored       — select one → ▲ Un-ignore
  Click OK to save.  Ignored MACs are neither created nor updated.

--------------------------------------------------------------------------------
SCANNED TCP PORTS
  21 FTP · 22 SSH · 23 Telnet · 25 SMTP · 53 DNS · 80 HTTP · 110 POP3
  143 IMAP · 443 HTTPS · 445 SMB · 548 AFP · 554 RTSP · 587 SMTP-sub
  631 IPP · 993 IMAPS · 995 POP3S · 1883 MQTT · 3306 MySQL · 3389 RDP
  5000 UPnP · 5900 VNC · 8080 HTTP-alt · 8443 HTTPS-alt · 9100 Printer
  32400 Plex

--------------------------------------------------------------------------------
Author  : Karl Wachs
Version : 2026.1.0
================================================================================
"""

__doc__ = PLUGIN_HELP

import indigo          # type: ignore  (provided by Indigo at runtime)
import threading
import subprocess
import select
import socket
import struct
import signal
import time
import re
import datetime
import json
import os
import logging

import MAC2Vendor  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PLUGIN_ID      = "com.karlwachs.networkscanner"
DEVICE_TYPE_ID = "networkDevice"
STDDTSTRING    = "%Y-%m-%d %H:%M:%S"
_CURL_PORTS_DEFAULT = (80, 443, 22, 8080)

# Bump this whenever Devices.xml gains or changes states/props.
# deviceStartComm() calls stateListOrDisplayStateIdChanged() only when this
# value differs from what is stored in the device's pluginProps — avoids an
# expensive Indigo API round-trip on every normal restart.
SCHEMA_VERSION = "2025.0.6"
# ---------------------------------------------------------------------------
# Plugin config defaults
# Indigo ignores defaultValue= in PluginConfig.xml for prefs already saved,
# so we apply these ourselves in __init__ for any key that is missing.
# ---------------------------------------------------------------------------
kDefaultPluginPrefs = {
	"networkInterface":  "en0",
	"scanInterval":      "60",
	"arpSweepEnabled":   True,
	"sniffEnabled":      True,
	"offlineThreshold":    "180",
	"startupGracePeriod":  "60",
	"autoCreateDevices":   True,
	"deviceFolder":      "Network Devices",
	"prefixName":		 "NET_",
	"sudoPassword":      "",
	# per-device defaults (applied when creating new devices)
	"pingMode":          "confirm",
	# logging categories  (key = "debug" + area-name)
	"debugNewDevice":      True,
	"debugStateChange":      True,
	"stateChangeLogLevel":   "20",
	"debugIpChange":       True,
	"debugSeen":           False,
	"debugSweep":          False,
	"debugIgnored":        False,
	"debugPing":           False,
}

# ---------------------------------------------------------------------------
# Build the log-areas dict from kDefaultPluginPrefs keys starting with "debug".
# Maps area-name → default bool, e.g. "NewDevice" → True
# Mirrors homematic's _debugAreas pattern.
# ---------------------------------------------------------------------------
_logAreas = {}
for _kk in kDefaultPluginPrefs:
	if _kk.startswith("debug"):
		_logAreas[_kk[5:]] = kDefaultPluginPrefs[_kk]   # e.g. "debugNewDevice" → "NewDevice": True

# ---------------------------------------------------------------------------
# Bins for the "time between seen events" histogram.
# Last entry is the catch-all "larger than 300 s" bucket (stored as the
# integer 301 internally so it sorts correctly; printed as "300+").
# ---------------------------------------------------------------------------
_SEEN_BINS  = [10, 30, 60, 90, 120, 180, 240, 300, 301]   # 301 == "300+" bucket
_SEEN_LABEL = {b: (f"≤{b}s" if b != 301 else ">300s") for b in _SEEN_BINS}

# ---------------------------------------------------------------------------
# Well-known TCP ports probed by the port-scan menu action.
# Format:  port → (short-name, human description)
# ---------------------------------------------------------------------------
_SCAN_PORTS = {
	21:    ("FTP",        "File Transfer Protocol — plain-text file transfer"),
	22:    ("SSH",        "Secure Shell — encrypted remote access / SFTP"),
	23:    ("Telnet",     "Telnet — insecure plain-text remote access"),
	25:    ("SMTP",       "Mail server — outgoing mail relay"),
	53:    ("DNS",        "Domain Name System — name resolution"),
	80:    ("HTTP",       "Web server — unencrypted"),
	110:   ("POP3",       "Mail retrieval — Post Office Protocol"),
	143:   ("IMAP",       "Mail retrieval — IMAP"),
	443:   ("HTTPS",      "Web server — TLS encrypted"),
	445:   ("SMB",        "Windows / Samba file sharing"),
	548:   ("AFP",        "Apple Filing Protocol — macOS file sharing"),
	554:   ("RTSP",       "Real-Time Streaming Protocol — cameras / media"),
	587:   ("SMTP-sub",   "Mail submission — encrypted outgoing mail"),
	631:   ("IPP",        "Internet Printing Protocol — network printer"),
	993:   ("IMAPS",      "IMAP over SSL"),
	995:   ("POP3S",      "POP3 over SSL"),
	1883:  ("MQTT",       "IoT messaging broker (unencrypted)"),
	3306:  ("MySQL",      "MySQL / MariaDB database"),
	3389:  ("RDP",        "Windows Remote Desktop Protocol"),
	5000:  ("UPnP/Dev",   "UPnP control point or development server"),
	5900:  ("VNC",        "VNC screen sharing / remote desktop"),
	8080:  ("HTTP-alt",   "Alternate HTTP — proxy or dev server"),
	8443:  ("HTTPS-alt",  "Alternate HTTPS"),
	9100:  ("Printer",    "Raw printing — HP JetDirect / direct TCP print"),
	32400: ("Plex",       "Plex Media Server"),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_for_notes(ip: str) -> str:
	"""Return IP with last octet zero-padded to 3 digits for sortable Notes column.
	e.g. 192.168.1.5 → 192.168.1.005,  192.168.1.54 → 192.168.1.054
	"""
	try:
		parts = ip.split(".")
		parts[-1] = parts[-1].zfill(3)
		return ".".join(parts)
	except Exception:
		return ip

def _now_str():
	return datetime.datetime.now().strftime(STDDTSTRING)

def _date_string_to_Object(dd):
	return datetime.datetime.strptime(dd, STDDTSTRING)

def _date_diff_in_Seconds(dt1, dt2):
	# Calculate the time difference between dt2 and dt1; dt2 > dt1
	timedelta = _date_string_to_Object(dt2) - _date_string_to_Object(dt1)
	# Return the total time difference in seconds
	return timedelta.days * 24 * 3600 + timedelta.seconds

def _strip_local_suffix(name: str) -> str:
	"""Remove common local-network domain suffixes from a Bonjour/mDNS hostname.
	e.g. 'iPhone.local' → 'iPhone',  'MacBook-Pro.localdomain' → 'MacBook-Pro'
	Suffixes stripped: .local  .localdomain  .lan  .home  .internal
	"""
	for suffix in (".localdomain", ".local", ".lan", ".home", ".internal"):
		if name.lower().endswith(suffix):
			return name[:-len(suffix)]
	return name


def _mac_to_device_name(mac: str, vendor: str = "", local_name: str = "", prefixName: str = "Net_") -> str:
	"""Build the auto-generated device name.

	Priority for the display label appended after the MAC:
	  1. local_name  (mDNS/Bonjour hostname from arp -a, suffix stripped)
	                 e.g. 'iPhone.local' → 'Net_AA:BB:CC:DD:EE:FF  iPhone'
	  2. vendor      (OUI manufacturer name)
	                 e.g.                 → 'Net_AA:BB:CC:DD:EE:FF  Apple Inc'
	  3. neither     → 'Net_AA:BB:CC:DD:EE:FF'
	"""
	base = prefixName + mac.upper()
	# Prefer the local network name — strip domain suffix and sanitise
	if local_name:
		display = _strip_local_suffix(local_name.strip())
		safe    = re.sub(r"[^A-Za-z0-9 _\-]", "", display).strip()[:24]
		if safe:
			return f"{base}  {safe}"
	# Fall back to vendor name
	if vendor and vendor.strip().lower() not in ("", "unknown"):
		safe = re.sub(r"[^A-Za-z0-9 _\-]", "", vendor).strip()[:20]
		if safe:
			return f"{base}  {safe}"
	return base



def _icmp_checksum(data: bytes) -> int:
	"""Standard one's-complement checksum used in ICMP headers (RFC 792)."""
	if len(data) % 2:
		data += b'\x00'
	s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
	s = (s >> 16) + (s & 0xFFFF)
	s += s >> 16
	return ~s & 0xFFFF


def _ping(ip: str, timeout: float = 1.0) -> bool:
	"""Return True if host replies to an ICMP echo request.

	Uses SOCK_DGRAM + IPPROTO_ICMP — no subprocess, no root required on macOS.
	The kernel fills in the IP header; we supply only the ICMP payload.

	Error mapping:
	  recv() returns data  → echo reply received → True
	  socket.timeout       → no reply within timeout → False
	  OSError              → unreachable / no route / permission denied → False
	"""
	icmp_id  = os.getpid() & 0xFFFF
	header   = struct.pack('!BBHHH', 8, 0, 0, icmp_id, 1)   # type=8 echo, code=0, cksum placeholder
	payload  = b'NS'
	checksum = _icmp_checksum(header + payload)
	packet   = struct.pack('!BBHHH', 8, 0, checksum, icmp_id, 1) + payload

	s = None
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
		s.settimeout(timeout)
		s.sendto(packet, (ip, 0))
		s.recv(1024)
		return True
	except Exception:
		return False
	finally:
		if s:
			try: s.close()
			except Exception: pass



def _curl_check(ip: str, preferred_port: int = None, timeout: float = 0.5) -> int | None:
	"""TCP-connect probe: try common ports and return the first responding port, or None.

	Uses a raw Python socket — no subprocess overhead.
	preferred_port is tried first (last port that worked for this device).

	Result logic:
	  connect() succeeds          → port open,   device alive  → return port
	  ConnectionRefusedError      → port closed, device alive  → return port
	  socket.timeout / OSError    → no response on this port   → try next
	"""
	ports = ((preferred_port,) + tuple(p for p in _CURL_PORTS_DEFAULT if p != preferred_port)
	         if preferred_port else _CURL_PORTS_DEFAULT)
	for port in ports:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.settimeout(timeout)
			s.connect((ip, port))
			return port                      # connected — device is alive
		except ConnectionRefusedError:
			return port                      # port closed but device answered the SYN
		except (socket.timeout, OSError):
			pass                             # no response on this port — try next
		finally:
			try:
				s.close()
			except Exception:
				pass
	return None


def _arp_ping(ip: str, iface: str, timeout: int = 2) -> bool:
	"""Check reachability: ping first; if ping fails fall back to curl TCP probe."""
	return _ping(ip, timeout) or (_curl_check(ip) is not None)


def _local_subnet(iface: str):
	"""Return (network_str, cidr) e.g. ('192.168.1.0', 24) by parsing ifconfig output.

	ifconfig output for an active interface looks like:
	  en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	          inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	We look for the 'inet' line and parse the IP and subnet mask.
	macOS reports the mask as a hex string (0xffffff00); older systems and Linux
	use dotted-decimal (255.255.255.0).  Both forms are handled.
	CIDR prefix length is derived by counting the 1-bits in the 32-bit mask.
	Returns None on any failure (interface down, not found, parse error).
	"""
	try:
		# Query the interface configuration — stderr suppressed (interface may be down)
		out = subprocess.check_output(["/sbin/ifconfig", iface], text=True, stderr=subprocess.DEVNULL)

		# Match: inet <ip>  netmask <hex-or-dotted>
		m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", out)
		if not m:
			return None
		ip_str, mask_str = m.group(1), m.group(2)

		# Convert mask to a 32-bit integer regardless of format
		if mask_str.startswith("0x"):
			mask_int = int(mask_str, 16)                                  # hex → int
		else:
			parts    = [int(p) for p in mask_str.split(".")]
			mask_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

		cidr    = bin(mask_int).count("1")                                # count set bits for prefix length
		ip_int  = struct.unpack("!I", socket.inet_aton(ip_str))[0]       # IP string → 32-bit network-order int
		net_int = ip_int & mask_int                                       # mask off host bits → network address
		net_str = socket.inet_ntoa(struct.pack("!I", net_int))           # 32-bit int → dotted-decimal string
		return net_str, cidr
	except Exception:
		return None


# ---------------------------------------------------------------------------
# Plugin Class
# ---------------------------------------------------------------------------

class Plugin(indigo.PluginBase):

	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super().__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

		# Apply defaults for any key missing from saved prefs
		# (Indigo ignores PluginConfig.xml defaultValue= for existing installs)
		for k, v in kDefaultPluginPrefs.items():
			if k not in self.pluginPrefs:
				self.pluginPrefs[k] = v

		self.getInstallFolderPath		= indigo.server.getInstallFolderPath()+"/"

		# --- setup prefs dir and state file --------------------
		self.indigoPreferencesPluginDir = self.getInstallFolderPath+"Preferences/Plugins/"+self.pluginId+"/"
		if not os.path.exists(self.indigoPreferencesPluginDir):
			os.mkdir(self.indigoPreferencesPluginDir)
		self.stateFile     = self.indigoPreferencesPluginDir+"known_devices.json"

		# ── Logging setup ────────────────────
		# plugin_file_handler / indigo_log_handler are provided by Indigo's PluginBase.
		# We attach a LevelFormatter so every level gets a proper timestamp.
		if not os.path.exists(indigo.server.getLogsFolderPath(pluginId=pluginId)):
			os.mkdir(indigo.server.getLogsFolderPath(pluginId=pluginId))
		self.PluginLogFile = indigo.server.getLogsFolderPath(pluginId=pluginId) + "/plugin.log"

		formats = {
			logging.DEBUG:    "%(asctime)s  %(msg)s",
			logging.INFO:     "%(asctime)s  %(msg)s",
			logging.WARNING:  "%(asctime)s  %(msg)s",
			logging.ERROR:    "%(asctime)s.%(msecs)03d\t%(levelname)-12s\t%(name)s.%(funcName)-25s %(msg)s",
			logging.CRITICAL: "%(asctime)s.%(msecs)03d\t%(levelname)-12s\t%(name)s.%(funcName)-25s %(msg)s",
		}
		date_fmt = {
			logging.DEBUG:    "%Y-%m-%d %H:%M:%S",
			logging.INFO:     "%Y-%m-%d %H:%M:%S",
			logging.WARNING:  "%Y-%m-%d %H:%M:%S",
			logging.ERROR:    "%Y-%m-%d %H:%M:%S",
			logging.CRITICAL: "%Y-%m-%d %H:%M:%S",
		}
		formatter = LevelFormatter(fmt="%(msg)s", datefmt="%Y-%m-%d %H:%M:%S",
		                           level_fmts=formats, level_date=date_fmt)
		self.plugin_file_handler.setFormatter(formatter)
		self.indiLOG = logging.getLogger("Plugin")
		self.indiLOG.setLevel(logging.DEBUG)
		self.indigo_log_handler.setLevel(logging.INFO)

		# Build active log-areas list from prefs (no log output yet)
		self.setLogFromPrefs(self.pluginPrefs, writeToLog=False)

		# MAC → {ip, last_seen (epoch), online (bool), indigo_device_id}
		self._known: dict      = {}
		self._known_lock       = threading.Lock()

		self._sniff_thread     = None
		self._scan_thread      = None
		self._stop_event       = threading.Event()
		self._sniff_proc       = None   # tcpdump Popen — killed immediately on stop
		self._startup_time     = time.time()   # overwritten in startup(); guards offline grace

		# Set of lowercase MACs to never create Indigo devices for
		self._ignored_macs: set = self._load_ignored_macs()

		# MAC → Vendor lookup (async download on first run)
		self.M2V               = None
		self.waitForMAC2vendor = False
		self._init_mac2vendor()

		self._load_state()

	# ------------------------------------------------------------------
	# Logging helpers  (homematic pattern)
	# ------------------------------------------------------------------

	def setLogFromPrefs(self, theDict, writeToLog=True):
		"""Rebuild self.logAreas list from plugin prefs.
		Called at startup and after the prefs dialog closes.
		"""
		self.logAreas = []
		try:
			for d in _logAreas:
				if theDict.get("debug" + d, _logAreas[d]):
					self.logAreas.append(d)
			if writeToLog:
				self.indiLOG.log(20, f"debug areas: {self.logAreas}")
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, "", exc_info=True)

	def decideMyLog(self, msgLevel):
		"""Return True if msgLevel is in the active log-areas list.

		Usage:
		    if self.decideMyLog("NewDevice"): self.indiLOG.log(20, "...")
		"""
		try:
			if msgLevel == "All" or "All" in self.logAreas: return True
			if msgLevel == "" and "All" not in self.logAreas: return False
			if msgLevel in self.logAreas: return True
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, "", exc_info=True)
		return False

	# ------------------------------------------------------------------
	# Lifecycle
	# ------------------------------------------------------------------

	def _grace_period_secs(self) -> int:
		"""Return the startup grace period in seconds as a safe integer."""
		try:
			return max(0, int(self.pluginPrefs.get("startupGracePeriod", "60") or "60"))
		except (ValueError, TypeError):
			return 60

	def startup(self):
		grace = self._grace_period_secs()
		self.indiLOG.log(20, f"Network Scanner starting up…  (offline ignore period: {grace} s)")
		self._startup_time = time.time()
		self._stop_event.clear()
		self._rename_and_move_net_devices()       # single pass: rename + move
		#self.indiLOG.log(20, f"startup: rename/move done  ")
		self._backfill_history_from_devices()
		#self.indiLOG.log(20, f"startup: backfill done ")
		self._start_threads()
		self.indiLOG.log(20, f"Network Scanner active")



	def _getPrefixName(self):
		return self.pluginPrefs.get("prefixName",kDefaultPluginPrefs["prefixName"]).strip()

	def _is_auto_name(self, name: str, mac: str) -> bool:
		"""Return True if name was auto-generated (starts with Net_<MAC>).
		Used to decide whether it is safe to rename the device.
		"""
		return name.startswith(self._getPrefixName() + mac.upper())



	def _kill_tcpdump(self):
		"""Kill the tcpdump subprocess.

		Order matters: kill the process FIRST so that any thread blocked inside
		proc.stdout.readline() gets EOF and releases the TextIOWrapper internal
		lock.  Calling proc.stdout.close() before proc.kill() deadlocks: the main
		thread waits forever for the lock held by the sniff thread's blocking read,
		and proc.kill() is never reached — causing the 20-second SIGKILL timeout.
		"""
		proc = self._sniff_proc
		if proc:
			self._sniff_proc = None   # clear first so sniff thread won't re-enter
			try: proc.kill()          # unblocks any readline() in the sniff thread via EOF
			except Exception: pass
			# Do NOT call proc.stdout.close() here — the sniff thread may not have
			# processed the EOF yet, causing a race on the TextIOWrapper internal lock.
			# The fd is released automatically when the Popen object is GC'd.

	def runConcurrentThread(self):
		"""Indigo's cooperative loop – sleep in 1 s steps so stop is near-instant."""
		in_grace_period = True
		try:
			while True:
				self.sleep(1)
				if in_grace_period:
					in_grace_period = (time.time() - self._startup_time) < self._grace_period_secs()
					if not in_grace_period:
						self.indiLOG.log(20, f"startup finished, offline ignore period ended")
					
					

		except self.StopThread:
			pass

	# ------------------------------------------------------------------
	# Preferences
	# ------------------------------------------------------------------

	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			self.setLogFromPrefs(valuesDict)
			# Signal all threads to stop
			self._stop_event.set()
			self._kill_tcpdump()
			# Join with short timeout — scan/sniff threads check stop_event every 0.1–0.2 s
			# so they should exit well within 1 second.  Never block the main thread longer.
			for t in (self._scan_thread, self._sniff_thread):
				if t and t.is_alive():
					t.join(timeout=1.0)
			self._stop_event.clear()
			self._start_threads()

	# ------------------------------------------------------------------
	# Device lifecycle
	# ------------------------------------------------------------------

	def deviceStartComm(self, dev):
		# Refresh the state list only when Devices.xml schema has changed.
		# Calling stateListOrDisplayStateIdChanged() on every restart for every
		# device is an expensive Indigo API round-trip.  We store the schema
		# version in pluginProps and skip the call on normal restarts.
		stored_schema = dev.pluginProps.get("schemaVersion", "")
		if stored_schema != SCHEMA_VERSION:
			dev.stateListOrDisplayStateIdChanged()
			try:
				props = dev.pluginProps.copy()
				props["schemaVersion"] = SCHEMA_VERSION
				dev.replacePluginPropsOnServer(props)
			except Exception:
				pass

		mac = dev.states.get("macAddress", "")
		if mac:
			with self._known_lock:
				entry = self._known.get(mac, {})
				entry["indigo_device_id"] = dev.id
				self._known[mac] = entry

		# Backfill lastOnOffChange and onOffState uiValue for devices that
		# were created before these states/formats were introduced.
		try:
			backfill = []
			if not dev.states.get("lastOnOffChange", ""):
				ts = dev.states.get("created", _now_str())
				backfill.append({"key": "lastOnOffChange", "value": ts})
				online = dev.states.get("onOffState", False)
				backfill.append({
					"key":     "onOffState",
					"value":   online,
					"uiValue": f"{'on' if online else 'off'}  {ts}",
				})
			if backfill:
				dev.updateStatesOnServer(backfill)
		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Backfill states failed for {dev.name}: {e}")

		# Launch a port scan for this device in the background.
		# Covers both startup (all existing devices) and new device creation.
		# Delay 15 s on startup so ARP sweep has time to confirm the device is up.
		ip = dev.states.get("ipAddress", "")
		if ip:
			dev_id = dev.id
			def _deferred_scan(did, dip):
				self._stop_event.wait(timeout=15)
				if not self._stop_event.is_set():
					self._port_scan_device(did, dip)
			threading.Thread(
				target=_deferred_scan, args=(dev_id, ip),
				daemon=True, name=f"NS-PS-{mac[-5:] if mac else dev_id}"
			).start()

	def deviceStopComm(self, dev):
		pass  # nothing to tear down per-device

	def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
		"""Sync the comment pluginProp → comment device state whenever the dialog is saved."""
		if userCancelled:
			return
		try:
			dev     = indigo.devices[devId]
			comment = valuesDict.get("comment", "")
			dev.updateStateOnServer("comment", value=comment)
		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Could not update comment state for device {devId}: {e}")

	# ------------------------------------------------------------------
	# Internal: thread management
	# ------------------------------------------------------------------

	def _start_threads(self):
		iface    = self.pluginPrefs.get("networkInterface", "en0").strip() or "en0"
		sniff_on = self.pluginPrefs.get("sniffEnabled", True)
		sweep_on = self.pluginPrefs.get("arpSweepEnabled", True)
		password = self.pluginPrefs.get("sudoPassword", "").strip()

		if sniff_on:
			self._sniff_thread = threading.Thread(
				target=self._sniff_loop, args=(iface, password), daemon=True, name="NS-Sniff"
			)
			self._sniff_thread.start()
			self.indiLOG.log(20, f"traffic sniffer (tcpdump) started on {iface}")
		else:
			self.indiLOG.log(20, "Passive ARP sniffing disabled.")

		self._scan_thread = threading.Thread(
			target=self._scan_loop, args=(iface, sweep_on), daemon=True, name="NS-Scan"
		)
		self._scan_thread.start()
		self.indiLOG.log(20, "Device scan loop started.")

		# Periodic state-file save — every 2 minutes, independent of scan interval.
		# Ensures known_devices.json (including history) is never more than 2 min stale.
		threading.Thread(
			target=self._save_loop, daemon=True, name="NS-Save"
		).start()

	def _save_loop(self):
		"""Write known_devices.json every 2 minutes, independent of scan timing.

		Uses stop_event.wait(120) so it exits immediately when the plugin stops —
		no sleep loop needed and no risk of blocking shutdown.
		"""
		while not self._stop_event.is_set():
			self._stop_event.wait(timeout=120)   # wake after 2 min or on stop
			if not self._stop_event.is_set():    # skip save on clean shutdown (shutdown() handles it)
				self._save_state()

	# ------------------------------------------------------------------
	# Sniff loop (tcpdump subprocess — no root required)
	# ------------------------------------------------------------------

	def _sniff_loop(self, iface: str, password: str = ""):
		"""
		Passively capture ALL ethernet traffic via tcpdump to detect any active device.

		Each tcpdump line with -e looks like:
		  HH:MM:SS.ffffff  aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: ARP, Reply 192.168.1.1 is-at a4:91:b1:12:34:56
		  HH:MM:SS.ffffff  aa:bb:cc:dd:ee:ff > bb:cc:dd:ee:ff:00, ethertype IPv4 (0x0800), length 64: 192.168.1.45.54321 > 192.168.1.1.80: ...

		Parsing strategy:
		  1. ARP Reply  → definitive MAC+IP pair, register immediately
		  2. Any frame  → source MAC from ethernet header + source IP from IPv4 payload
		     Throttled: each MAC is registered at most once every 5 s to avoid
		     hammering _register_device on every packet of a busy device.

		If password is set, tcpdump is launched via  echo <pw> | sudo -S tcpdump …
		so that it can open the raw network socket without granting Indigo full root.
		"""
		# ARP Reply: "ARP, Reply 1.2.3.4 is-at aa:bb:cc:dd:ee:ff"
		_arp_reply_re = re.compile(
			r"ARP,\s+Reply\s+([\d.]+)\s+is-at\s+([0-9a-f:]{17})", re.IGNORECASE
		)
		# Source MAC from the ethernet header (first field after timestamp)
		_src_mac_re = re.compile(r"^\S+\s+([0-9a-f:]{17})\s+>", re.IGNORECASE)
		# Source IP from IPv4 payload: "length N: W.X.Y.Z.port >"
		_src_ip_re  = re.compile(r"length \d+:\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)\.\d+\s+>")

		_throttle: dict = {}   # mac → last time _register_device was called
		_THROTTLE_SECS  = 30.0 # minimum seconds between registrations per MAC

		# Targeted BPF filter: capture only frame types that signal device presence.
		# ARP covers discovery and IP changes; mDNS (5353) catches Apple/IoT/Chromecast;
		# DHCP (67/68) catches every device the moment it connects.
		# This reduces packet volume by ~95% vs capturing all traffic.
		_BPF = "arp or (udp port 5353) or (udp port 67) or (udp port 68)"

		while not self._stop_event.is_set():
			try:
				if password:
					# Single shell command: echo pipes the password into sudo -S
					shell_cmd = f"echo {password} | sudo -S /usr/sbin/tcpdump -i {iface} -n -e -l {_BPF}"
					proc = subprocess.Popen(
						shell_cmd,
						shell=True,
						stdout=subprocess.PIPE,
						stderr=subprocess.DEVNULL,
					)
				else:
					proc = subprocess.Popen(
						["/usr/sbin/tcpdump", "-i", iface, "-n", "-e", "-l", _BPF],
						stdout=subprocess.PIPE,
						stderr=subprocess.DEVNULL,
					)
				self._sniff_proc = proc
				fd  = proc.stdout.fileno()
				buf = b""
				while not self._stop_event.is_set():
					ready, _, _ = select.select([proc.stdout], [], [], 0.2)
					if not ready:
						continue
					try:
						chunk = os.read(fd, 4096)
					except OSError:
						break
					if not chunk:
						break
					buf += chunk
					while b"\n" in buf:
						raw, buf = buf.split(b"\n", 1)
						line = raw.decode("ascii", errors="replace")
						now  = time.time()

						# ── ARP Reply: definitive MAC→IP, always register ──────────
						m = _arp_reply_re.search(line)
						if m:
							ip  = m.group(1)
							mac = m.group(2).lower()
							if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
								_throttle[mac] = now
								self._register_device(mac, ip)
							continue

						# ── All other frames: src MAC + src IP (IPv4 only) ─────────
						mm = _src_mac_re.match(line)
						if not mm:
							continue
						mac = mm.group(1).lower()
						# Skip broadcast and multicast MACs (LSB of first octet = 1)
						if mac == "ff:ff:ff:ff:ff:ff" or (int(mac[:2], 16) & 1):
							continue
						# Throttle: skip if registered recently
						if now - _throttle.get(mac, 0) < _THROTTLE_SECS:
							continue
						# Need an IP — only IPv4 frames have one we can parse
						mi = _src_ip_re.search(line)
						if not mi:
							continue
						ip = mi.group(1)
						_throttle[mac] = now
						self._register_device(mac, ip)

			except Exception as e:
				if f"{e}".find("None") == -1: self.indiLOG.log(40, f"Sniff error: {e}", exc_info=True)
			finally:
				self._kill_tcpdump()

			if not self._stop_event.is_set():
				self._stop_event.wait(15)   # back off before retry

	# ------------------------------------------------------------------
	# Scan loop
	# ------------------------------------------------------------------

	def _scan_loop(self, iface: str, sweep_enabled: bool):
		"""
		Periodically:
		  1. ARP-sweep the local subnet to find new devices.
		  2. Ping all known devices to update online/offline state.
		"""
		# Short startup pause so all deviceStartComm() calls complete before
		# the first sweep.  Uses stop_event so shutdown exits immediately.
		self._stop_event.wait(timeout=4)
		if self._stop_event.is_set():
			return

		while not self._stop_event.is_set():
			interval = int(self.pluginPrefs.get("scanInterval", 60))

			if sweep_enabled:
				self._arp_sweep(iface)

			self._check_all_devices(iface)
			self._save_state()

			# Sleep in 0.2 s increments so stop_event is honoured quickly
			steps = int(interval / 0.2)
			for _ in range(steps):
				if self._stop_event.is_set():
					break
				time.sleep(0.2)

	def _arp_sweep(self, iface: str):
		"""
		Sweep the local subnet using ping + arp (both built into macOS).
		1. Send parallel pings to every host — only hosts that REPLY are "seen".
		2. Read 'arp -a' to get IP→MAC mappings.

		Critical: arp -a returns CACHED entries that can persist for ~20 minutes
		after a device goes offline.  We therefore distinguish:
		  • responded to ping  → _register_device()  (updates last_seen, marks online)
		  • in arp cache only  → _discover_device()   (creates Indigo device / updates
		                          IP mapping, but does NOT update last_seen or online)
		This prevents stale ARP cache entries from keeping devices "online".
		"""
		subnet_info = _local_subnet(iface)
		if not subnet_info:
			self.indiLOG.log(30, "Could not determine local subnet; skipping ARP sweep.")
			return
		net_str, cidr = subnet_info
		if self.decideMyLog("Sweep"):
			self.indiLOG.log(10, f"ARP sweep (ping+arp) → {net_str}/{cidr}")
		try:
			ip_int     = struct.unpack("!I", socket.inet_aton(net_str))[0]
			host_count = min((1 << (32 - cidr)) - 2, 254)   # cap at /24

			responded        = set()          # IPs that replied to ping or curl this cycle
			resp_lock        = threading.Lock()
			curl_ports_by_ip = {}             # ip → winning curl port (only curl hits)
			curl_lock        = threading.Lock()

			# Pre-build ip → last known curl port so _ping_host can pass preferred_port
			with self._known_lock:
				ip_to_curl_port = {e.get("ip"): e.get("curlPort")
				                   for e in self._known.values() if e.get("ip")}

			log_ping = self.decideMyLog("Ping")

			def _ping_host(ip):
				alive = _ping(ip)
				if log_ping:
					self.indiLOG.log(10, f"sweep ping  {ip}  {'ok' if alive else 'fail'}")
				if not alive:
					port  = _curl_check(ip, preferred_port=ip_to_curl_port.get(ip))
					alive = port is not None
					if log_ping and port is not None:
						self.indiLOG.log(10, f"sweep probe {ip}  ok port {port}")
					if port is not None:
						with curl_lock:
							curl_ports_by_ip[ip] = port
				if alive:
					with resp_lock:
						responded.add(ip)

			threads = []
			for i in range(1, host_count + 1):
				ip = socket.inet_ntoa(struct.pack("!I", ip_int + i))
				t  = threading.Thread(target=_ping_host, args=(ip,), daemon=True)
				t.start()
				threads.append(t)

			deadline = time.time() + 5
			while any(t.is_alive() for t in threads):
				if self._stop_event.is_set(): return
				if time.time() > deadline:    break
				time.sleep(0.1)

			if self._stop_event.is_set():
				return

			result = subprocess.run(
				[
					"/usr/sbin/arp",
					"-a",         # show ALL entries in the kernel ARP cache
					"-i", iface,  # limit output to entries learned on this interface
				],
				stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
				timeout=10, text=True
			)
			# macOS arp -a output format (one line per cached entry):
			#   hostname.local (192.168.1.42) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
			#   ?              (192.168.1.99) at cc:dd:ee:ff:00:11 on en0 ifscope [ethernet]
			# '?' means the device has not announced a hostname via mDNS/Bonjour.
			# A dotted-decimal string (same as the IP) means the OS only knows the IP.
			# Real hostnames come from the OS mDNS/Bonjour cache (Avahi / mdnsResponder).
			# Group 1 = raw name ('?' or hostname), Group 2 = IP, Group 3 = MAC
			arp_re   = re.compile(
				r"^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})",
				re.IGNORECASE
			)
			seen_n   = 0
			discov_n = 0
			for line in result.stdout.splitlines():
				m = arp_re.search(line)
				if m:
					raw_name, ip, mac = m.group(1), m.group(2), m.group(3).lower()
					# Discard '?' and bare IP strings — they are not useful local names
					if raw_name == "?" or re.match(r"^\d+\.\d+\.\d+\.\d+$", raw_name):
						local_name = ""
					else:
						local_name = raw_name.rstrip(".")  # strip trailing dot from FQDN
					if mac == "ff:ff:ff:ff:ff:ff":
						continue
					if ip in responded:
						self._register_device(mac, ip, local_name=local_name)   # actively replied → update last_seen
						seen_n += 1
					else:
						self._discover_device(mac, ip, local_name=local_name)   # stale cache → discover only
						discov_n += 1
					# Store the winning curl port (or None if ping sufficed / not reachable)
					with self._known_lock:
						if mac in self._known:
							self._known[mac]["curlPort"] = curl_ports_by_ip.get(ip)
			if self.decideMyLog("Sweep"):
				self.indiLOG.log(10,
					f"ARP sweep complete on {net_str}/{cidr}: "
					f"{seen_n} device(s) replied to ping (online), "
					f"{discov_n} in ARP cache but no ping reply (likely offline / stale)"
				)
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"ARP sweep error: {e}", exc_info=True)

	def _check_all_devices(self, iface: str):
		"""Ping all known devices in parallel and update online/offline state.

		Per-device props read from Indigo pluginProps:
		  pingMode         – "both" | "online" | "offline" | "confirm" | "pingOnly" | "none"
		  pingOfflineLogic – "and"  (timeout AND streak) | "or" (timeout OR streak)
		  pingMissedCount  – consecutive failed pings required before offline (default 1)
		  offlineThreshold – per-device override; 0 = use plugin-wide default

		Streak counter (ping_fail_streak) lives in _known and persists across cycles.
		"""
		if self._stop_event.is_set():
			return

		plugin_offline_threshold = int(self.pluginPrefs.get("offlineThreshold", 180))
		now                      = time.time()

		# Do not mark anything offline during the first 60 s after startup.
		# Gives ARP sniffing and the first sweep time to re-confirm all devices.
		in_grace_period = (now - self._startup_time) < self._grace_period_secs()

		with self._known_lock:
			snapshot = dict(self._known)

		results      = {}   # mac → (online, new_last_seen, new_streak)
		results_lock = threading.Lock()

		# MAC → device name — built once, read-only in threads
		names_by_mac = {
			dev.states.get("macAddress", "").lower(): dev.name
			for dev in indigo.devices.iter(PLUGIN_ID)
			if dev.states.get("macAddress", "")
		}

		_CURL_USELESS_LIMIT = 5   # consecutive all-port failures before skipping curl

		log_ping = self.decideMyLog("Ping")

		def _do_probe(ip, mac, entry, ping_only=False):
			"""Ping first; if blocked fall back to TCP socket probe (unless ping_only=True).
			Updates _known[mac]['curlPort']. Logs results if Log Ping is enabled.
			"""
			dev_name = names_by_mac.get(mac, mac)
			ping_ok  = _ping(ip)
			if log_ping:
				self.indiLOG.log(10, f"ping  {dev_name} ({ip})  {'ok' if ping_ok else 'fail'}")
			if ping_ok:
				with self._known_lock:
					e = self._known.setdefault(mac, {})
					e.setdefault("curlPort", None)
					e["curlUseless"] = 0
				return True
			if ping_only:
				return False
			# Skip TCP probe if it has never worked for this device
			if entry.get("curlUseless", 0) >= _CURL_USELESS_LIMIT:
				if log_ping:
					self.indiLOG.log(10, f"probe {dev_name} ({ip})  skipped (marked useless)")
				return False
			port = _curl_check(ip, preferred_port=entry.get("curlPort"))
			if log_ping:
				self.indiLOG.log(10,
					f"probe {dev_name} ({ip})  {'ok port ' + str(port) if port else 'fail all ports'}"
				)
			with self._known_lock:
				e = self._known.setdefault(mac, {})
				e["curlPort"]    = port
				e["curlUseless"] = 0 if port is not None else (entry.get("curlUseless", 0) + 1)
			return port is not None

		def _check_one(mac, entry):
			if self._stop_event.is_set():
				return
			ip        = entry.get("ip", "")
			last_seen = entry.get("last_seen", 0)
			if not ip:
				return
			# During the startup grace period suppress all offline decisions.
			# Do NOT write anything to results — this avoids force-setting devices
			# online (which caused everything to flash ON on the first scan cycle).
			# Devices confirmed online by ARP sniff/sweep update their own state.
			if in_grace_period:
				return

			# ── Per-device settings ──────────────────────────────────────────
			ping_mode         = "none"
			offline_logic     = "and"    # "and" | "or"
			missed_needed     = 1        # consecutive failures required
			offline_threshold = plugin_offline_threshold
			ping_only         = False    # derived from ping_mode == "pingOnly"
			dev_id            = entry.get("indigo_device_id")
			if dev_id:
				try:
					props         = indigo.devices[dev_id].pluginProps
					ping_mode     = props.get("pingMode",         "none")
					offline_logic = props.get("pingOfflineLogic", "and")
					missed_needed = max(1, int(props.get("pingMissedCount", 1) or 1))
					dev_thresh    = int(props.get("offlineThreshold", 0) or 0)
					if dev_thresh > 0:
						offline_threshold = dev_thresh
				except Exception:
					pass
			# "pingOnly" is a ping_mode value meaning "confirm + no TCP fallback"
			if ping_mode == "pingOnly":
				ping_only = True
				ping_mode = "both"

			silent_secs = now - last_seen
			timed_out   = silent_secs > offline_threshold

			if ping_mode == "none":
				# No active pinging — offline is decided purely by ARP timeout.
				# Only write a result when the state needs to change; otherwise
				# leave the entry untouched so a recent ARP sighting stays online.
				if timed_out and entry.get("online", True):
					with results_lock:
						results[mac] = (False, last_seen, 0)
				return
			current_streak = entry.get("ping_fail_streak", 0)

			# ── confirm mode ─────────────────────────────────────────────────
			# Only ping when ARP timeout has already expired.
			# Ping success resets the clock (keeps device online).
			# Ping failure increments streak; offline when streak >= missed_needed.
			if ping_mode == "confirm":
				if not timed_out:
					# ARP still recent — no need to ping, preserve current state
					with results_lock:
						results[mac] = (entry.get("online", True), last_seen, 0)
					return
				ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only)
				if ping_ok:
					new_streak    = 0
					online        = True
					new_last_seen = now
					# Log to plugin.log (level 10) — ping rescued device from ARP timeout
					dev_name = names_by_mac.get(mac, mac)
					self.indiLOG.log(10,
						f"Confirm-ping kept ONLINE: {dev_name} ({ip})  "
						f"silent for {int(silent_secs)}s (threshold {offline_threshold}s)"
					)
				else:
					new_streak    = current_streak + 1
					online        = new_streak < missed_needed   # stay online until streak fills
					new_last_seen = last_seen
				with results_lock:
					results[mac] = (online, new_last_seen, new_streak)
				return

			# ── online-only mode ─────────────────────────────────────────────
			# Ping success → online; failure never causes offline.
			if ping_mode == "online":
				ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only)
				if ping_ok:
					with results_lock:
						results[mac] = (True, now, 0)
				else:
					with results_lock:
						results[mac] = (entry.get("online", True), last_seen, current_streak)
				return

			# ── both / offline modes ─────────────────────────────────────────
			# Ping success always resets streak.
			# Ping failure increments streak; offline decision depends on logic + streak.
			ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only)

			if ping_ok:
				new_streak    = 0
				new_last_seen = now if ping_mode == "both" else last_seen
				online        = True if ping_mode == "both" else entry.get("online", True)
			else:
				new_streak  = current_streak + 1
				streak_met  = new_streak >= missed_needed

				if offline_logic == "or":
					offline_triggered = timed_out or  streak_met
				else:   # "and" — default, least false-positives
					offline_triggered = timed_out and streak_met

				if ping_mode == "both":
					online        = not offline_triggered
					new_last_seen = last_seen
				else:   # "offline" — ping can only make device go offline, not online
					online        = (not offline_triggered) if offline_triggered else entry.get("online", True)
					new_last_seen = last_seen

			with results_lock:
				results[mac] = (online, new_last_seen, new_streak)

		# ── launch all pings in parallel ─────────────────────────────────────
		threads = []
		for mac, entry in snapshot.items():
			if self._stop_event.is_set(): return
			if mac.lower() in self._ignored_macs: continue
			t = threading.Thread(target=_check_one, args=(mac, entry), daemon=True)
			t.start()
			threads.append(t)

		deadline = time.time() + 5
		while any(t.is_alive() for t in threads):
			if self._stop_event.is_set(): return
			if time.time() > deadline:    break
			time.sleep(0.1)

		if self._stop_event.is_set():
			return

		for mac, (online, new_last_seen, new_streak) in results.items():
			with self._known_lock:
				self._known[mac]["online"]           = online
				self._known[mac]["last_seen"]        = new_last_seen
				self._known[mac]["ping_fail_streak"] = new_streak
			ip = snapshot[mac].get("ip", "")
			self._update_indigo_device(mac, ip, online)

	# ------------------------------------------------------------------
	# Device registry
	# ------------------------------------------------------------------

	def _discover_device(self, mac: str, ip: str, local_name: str = ""):
		"""Called for stale ARP-cache entries that did NOT respond to ping this sweep.

		Updates IP mapping and creates the Indigo device if needed, but intentionally
		does NOT update last_seen or set online=True — those fields must only change
		when the device is genuinely reachable.
		local_name is the mDNS/Bonjour hostname from the arp -a output (empty if unknown).
		"""
		if mac.lower() in self._ignored_macs:
			return
		with self._known_lock:
			entry = self._known.get(mac, {})
			if not entry:                         # brand-new MAC — seed a minimal entry
				entry["online"]     = False
				entry["last_seen"]  = 0
				entry["history"]    = []
				entry["local_name"] = ""
				entry["name"]       = ""
			entry.setdefault("history",    [])    # backfill for entries added before history existed
			entry.setdefault("local_name", "")    # backfill for entries added before local_name existed
			entry.setdefault("name",       "")    # backfill for entries added before name existed
			entry.setdefault("curlPort",   None)  # last curl port that responded
			entry.setdefault("curlUseless", 0)   # consecutive all-port curl failures
			entry["ip"] = ip
			if local_name:                        # only overwrite with a real name, never with empty
				entry["local_name"] = local_name
			if "vendor" not in entry:
				entry["vendor"] = self.get_vendor(mac)
			self._known[mac] = entry
		# Ensure an Indigo device exists, but do not update online state
		self._ensure_indigo_device(mac, ip, entry.get("vendor", ""), entry.get("online", False),
		                           local_name=entry.get("local_name", ""))

	def _register_device(self, mac: str, ip: str, local_name: str = ""):
		"""Add or update a MAC entry, then create or refresh the Indigo device.

		Called from the sniff thread (passive ARP) and from ping-confirmed sweep hits.
		local_name is the mDNS/Bonjour hostname parsed from arp -a output (empty string
		when the device has not announced a name, i.e. arp -a showed '?').
		Only the ARP sweep populates local_name; sniff-thread calls leave it empty.
		"""
		if mac.lower() in self._ignored_macs:
			if self.decideMyLog("Ignored"):
				self.indiLOG.log(10, f"Ignored MAC skipped: {mac}")
			return

		now = time.time()
		with self._known_lock:
			entry      = self._known.get(mac, {})
			entry.setdefault("history",    [])    # ensure key present on every entry
			entry.setdefault("local_name", "")    # ensure key present on every entry
			entry.setdefault("name",       "")    # ensure key present on every entry
			entry.setdefault("curlPort",   None)  # last curl port that responded
			entry.setdefault("curlUseless", 0)   # consecutive all-port curl failures
			changed_ip = entry.get("ip") != ip
			old_ip     = entry.get("ip", "")
			prev_seen  = entry.get("last_seen", 0)

			# ── seen-interval stats ──────────────────────────────────────────
			if prev_seen > 0:
				delta = now - prev_seen
				# JSON round-trips dict keys as strings; normalise back to int.
				raw   = entry.get("seen_stats", {})
				stats = {b: int(raw.get(b, raw.get(str(b), 0))) for b in _SEEN_BINS}
				for edge in _SEEN_BINS[:-1]:          # all labelled edges except "300+"
					if delta <= edge:
						stats[edge] += 1
						break
				else:
					stats[_SEEN_BINS[-1]] += 1        # "300+" bucket
				entry["seen_stats"] = stats

			entry["ip"]             = ip
			entry["last_seen"]      = now
			entry["last_seen_str"]  = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
			entry["online"]         = True
			if local_name:                        # only overwrite with a real name, never with empty
				entry["local_name"] = local_name
			if "vendor" not in entry:
				entry["vendor"] = self.get_vendor(mac)
			self._known[mac] = entry

		# Read per-device log options (dev may not exist yet for brand-new MACs)
		suppress_ip_log  = False
		log_seen_to_file = False
		dev_id = entry.get("indigo_device_id")
		if dev_id:
			try:
				props            = indigo.devices[dev_id].pluginProps
				suppress_ip_log  = bool(props.get("suppressIpChangeLog", False))
				log_seen_to_file = bool(props.get("logSeenToFile",        False))
			except Exception:
				pass

		# Global "seen" flag → Indigo event log (level 20)
		if self.decideMyLog("Seen") or log_seen_to_file:
			self.indiLOG.log(10, f"Seen: {mac}  IP={ip}  vendor={entry['vendor']}")

		# IP-change log — honoured unless suppressed for this device
		if changed_ip and old_ip and self.decideMyLog("IpChange") and not suppress_ip_log:
			self.indiLOG.log(20, f"IP changed: {mac}  {old_ip} → {ip}")

		self._ensure_indigo_device(mac, ip, entry["vendor"], True,
		                           local_name=entry.get("local_name", ""))

	def _ensure_indigo_device(self, mac: str, ip: str, vendor: str, online: bool, local_name: str = ""):
		"""Create the Indigo device if it doesn't exist, then update its states."""
		dev_name = _mac_to_device_name(mac, vendor, local_name=local_name, prefixName = self._getPrefixName())
		existing = None
		for dev in indigo.devices.iter(PLUGIN_ID):
			if dev.states.get("macAddress", "").lower() == mac.lower():
				existing = dev
				break

		if existing is None and self.pluginPrefs.get("autoCreateDevices", True):
			existing = self._create_indigo_device(mac, ip, vendor, dev_name)

		if existing is not None:
			self._update_indigo_device_states(existing, mac, ip, vendor, online, local_name=local_name)

	def _create_indigo_device(self, mac: str, ip: str, vendor: str, name: str):
		"""Create a brand-new Indigo networkDevice."""
		props = {
			"address":          mac,    # shows in Indigo device list Address column
			"pingMode":         "confirm",
			"offlineThreshold": "0",    # 0 = use plugin-wide default
		}
		folder_id = self._get_or_create_folder()
		try:
			new_dev = indigo.device.create(
				protocol     = indigo.kProtocol.Plugin,
				name         = name,
				description  = _ip_for_notes(ip),   # Notes = IP (last octet padded)
				pluginId     = PLUGIN_ID,
				deviceTypeId = DEVICE_TYPE_ID,
				props        = props,
				folder       = folder_id,
			)
			new_dev.updateStateOnServer("created", value=_now_str())
			if self.decideMyLog("NewDevice"):
				self.indiLOG.log(20, f"Created device '{name}' for {mac}  IP={ip}  ({vendor})")
			with self._known_lock:
				e = self._known.setdefault(mac, {})
				e["indigo_device_id"] = new_dev.id
				e["name"]             = new_dev.name
			# Port-scan the new device in a background thread
			dev_id = new_dev.id
			threading.Thread(
				target=self._port_scan_device, args=(dev_id, ip),
				daemon=True, name=f"NS-PS-{mac[-5:]}"
			).start()
			return new_dev
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"Failed to create device for {mac}: {e}", exc_info=True)
			return None

	def _update_indigo_device_states(self, dev, mac: str, ip: str, vendor: str, online: bool, local_name: str = ""):
		"""Push only changed state values into an existing Indigo device.

		lastOnOffChange is only written when the online/offline value flips.
		last_seen (last ARP/ping ok epoch) lives only in _known — never pushed
		to Indigo, so routine scan hits produce zero device updates.
		localName is the mDNS/Bonjour hostname from arp -a; only updated when non-empty
		so a previously discovered name is never erased by a sniff-thread update.
		"""
		prev_online     = dev.states.get("onOffState",  None)
		prev_ip         = dev.states.get("ipAddress",   "")
		prev_mac        = dev.states.get("macAddress",  "")
		prev_vendor     = dev.states.get("vendorName",  "")
		prev_created    = dev.states.get("created",     "")
		prev_local_name = dev.states.get("localName",   "")

		online_changed     = (prev_online is None) or (bool(prev_online) != online)
		ip_changed         = prev_ip     != ip
		mac_changed        = prev_mac    != mac
		vendor_changed     = prev_vendor != vendor
		created_needed     = not prev_created
		# Only update localName when we have a real name AND it differs from stored
		local_name_changed = bool(local_name) and local_name != prev_local_name

		if not any([online_changed, ip_changed, mac_changed, vendor_changed, created_needed, local_name_changed]):
			return   # nothing to update — no Indigo server calls

		if online_changed and self.decideMyLog("StateChange"):
			status = "ONLINE" if online else "OFFLINE"
			lvl    = int(self.pluginPrefs.get("stateChangeLogLevel", "20") or "20")
			if not online:
				entry         = self._known.get(mac, {})
				last_seen_str = entry.get("last_seen_str", "")
				last_seen_ts  = entry.get("last_seen", 0)
				ago           = f"  =  {int(time.time() - last_seen_ts)}s ago" if last_seen_ts else ""
				suffix        = f"  (last seen: {last_seen_str}{ago})" if last_seen_str else ""
			else:
				suffix = ""
			self.indiLOG.log(lvl, f"{dev.name} ({ip}) is now {status}{suffix}")

		state_updates = []
		if online_changed:
			ts = _now_str()
			state_updates.append({
				"key":     "onOffState",
				"value":   online,
				"uiValue": f"{'on' if online else 'off'}  {ts}",
			})
			state_updates.append({"key": "lastOnOffChange", "value": ts})
			# Append to the rolling on/off history kept in _known (last 10 events).
			# This is stored in our own JSON state file, not in Indigo device states,
			# so it survives device deletions and plugin reinstalls.
			with self._known_lock:
				entry   = self._known.get(mac, {})
				history = entry.get("history", [])
				history.append({"ts": ts, "state": "on" if online else "off"})
				entry["history"] = history[-10:]   # cap at 10 entries
				entry["name"]    = dev.name        # keep Indigo device name in sync
				self._known[mac] = entry
		if ip_changed:
			state_updates.append({"key": "ipAddress",   "value": ip})
		if mac_changed:
			state_updates.append({"key": "macAddress",  "value": mac})
		if vendor_changed:
			state_updates.append({"key": "vendorName",  "value": vendor})
		if created_needed:
			state_updates.append({"key": "created",     "value": _now_str()})
		if local_name_changed:
			state_updates.append({"key": "localName",   "value": local_name})

		try:
			dev.updateStatesOnServer(state_updates)

			# Sync props only when relevant values changed
			props_changed = False
			new_props = dev.pluginProps
			if new_props.get("address")   != mac:
				new_props["address"]   = mac;  props_changed = True
			if new_props.get("ipAddress") != ip:
				new_props["ipAddress"] = ip;   props_changed = True
			if props_changed:
				dev.replacePluginPropsOnServer(new_props)

			# Notes (description) = padded IP — only when IP changed
			if ip_changed:
				padded_ip = _ip_for_notes(ip)
				if dev.description != padded_ip:
					dev.description = padded_ip
					dev.replaceOnServer()

			# Rename device when vendor or local name first becomes known and name is still auto-generated
			if (vendor_changed and vendor and vendor.lower() != "unknown") or local_name_changed:
				if self._is_auto_name(dev.name, mac):
					correct = _mac_to_device_name(mac, vendor, local_name=local_name or prev_local_name, prefixName = self._getPrefixName())
					if dev.name != correct:
						dev.name = correct
						dev.replaceOnServer()
						self.indiLOG.log(20, f"Device renamed to '{correct}'")

		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"State update failed for {dev.name}: {e}", exc_info=True)

	def _update_indigo_device(self, mac: str, ip: str, online: bool):
		"""Update an existing device's states from the scan loop thread."""
		for dev in indigo.devices.iter(PLUGIN_ID):
			if dev.states.get("macAddress", "").lower() == mac.lower():
				entry      = self._known.get(mac, {})
				vendor     = entry.get("vendor",     "Unknown")
				local_name = entry.get("local_name", "")
				self._update_indigo_device_states(dev, mac, ip, vendor, online, local_name=local_name)
				break

	# ------------------------------------------------------------------
	# Folder helpers
	# ------------------------------------------------------------------

	def _rename_and_move_net_devices(self):
		"""Single startup pass: rename auto-named devices and move them to the target folder.

		Combined into one loop so we only iterate indigo.devices.iter(PLUGIN_ID) once —
		far faster than the old approach of two separate passes, the second of which
		iterated ALL Indigo devices (slow when the user has many devices).
		"""
		folder_id = self._get_or_create_folder()
		renamed = moved = 0
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac        = dev.states.get("macAddress", "")
			vendor     = dev.states.get("vendorName", "")
			local_name = dev.states.get("localName",  "")
			changed    = False
			# ── rename if auto-name is stale ──────────────────────────────
			if mac and self._is_auto_name(dev.name, mac):
				correct = _mac_to_device_name(mac, vendor, local_name=local_name, prefixName = self._getPrefixName())
				if dev.name != correct:
					try:
						dev.name = correct
						changed  = True
						renamed += 1
					except Exception as e:
						self.indiLOG.log(30, f"Could not rename {dev.name} → {correct}: {e}")
			# ── move to configured folder if needed ───────────────────────
			if folder_id and dev.folderId != folder_id:
				try:
					if changed:
						# replaceOnServer() handles both rename and folder move at once
						dev.folderId = folder_id
					else:
						indigo.device.moveToFolder(dev.id, value=folder_id)
					moved += 1
					changed = False   # replaceOnServer below will cover it
				except Exception as e:
					self.indiLOG.log(30, f"Could not move {dev.name} to folder: {e}")
			# ── one replaceOnServer call covers rename + any other prop changes ──
			if changed:
				try:
					dev.replaceOnServer()
				except Exception as e:
					self.indiLOG.log(30, f"replaceOnServer failed for {dev.name}: {e}")
		if renamed:
			self.indiLOG.log(20, f"Renamed {renamed} Net_* device(s).")
		if moved:
			folder_name = self.pluginPrefs.get("deviceFolder", "Network Devices")
			self.indiLOG.log(20, f"Moved {moved} Net_* device(s) to folder '{folder_name}'.")

	def _backfill_history_from_devices(self):
		"""One-time startup backfill: seed history from Indigo device states for any
		known entry whose history list is still empty.

		Uses lastOnOffChange (timestamp) + onOffState (bool → 'on'/'off') to build
		a single seed entry in the same format as the live history — {"ts": ..., "state": ...}.
		Only touches entries with an empty history; devices that already have history
		are left untouched.  Saves state file if any entries were updated.
		"""
		filled = 0
		named  = 0
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac = dev.states.get("macAddress", "").lower()
			if not mac:
				continue
			with self._known_lock:
				entry = self._known.get(mac, {})
				if not entry:
					continue   # not yet in _known — will be populated on first ARP sighting
				changed = False
				# Always sync the Indigo device name
				if entry.get("name") != dev.name:
					entry["name"] = dev.name
					changed = True
					named  += 1
				# Seed history only when it is still empty
				if not entry.get("history"):
					state_str   = "on" if dev.states.get("onOffState", False) else "off"
					last_change = dev.states.get("lastOnOffChange", "")
					if last_change:
						entry["history"] = [{"ts": last_change, "state": state_str}]
						changed = True
						filled += 1
				if changed:
					self._known[mac] = entry
		msgs = []
		if named:  msgs.append(f"name synced for {named}")
		if filled: msgs.append(f"history seeded for {filled}")
		if msgs:
			self.indiLOG.log(20, f"Startup backfill: {', '.join(msgs)} device(s).")
			self._save_state()

	def _get_or_create_folder(self):
		folder_name = self.pluginPrefs.get("deviceFolder", "").strip()
		if not folder_name:
			return 0   # 0 = top level in Indigo
		for folder in indigo.devices.folders:
			if folder.name == folder_name:
				return folder.id
		try:
			return indigo.devices.folder.create(folder_name).id
		except Exception:
			return 0

	# ------------------------------------------------------------------
	# Persistence
	# ------------------------------------------------------------------

	def _init_mac2vendor(self):
		"""Initialise the MAP2Vendor lookup table.

		OUI files are stored next to the plugin state file.
		MAP2Vendor.__init__ already calls makeFinalTable() internally when the
		cached JSON is current, so we only call it again when the constructor
		indicated it was NOT ready (i.e. a background download was started).
		Calling makeFinalTable() twice was causing the large JSON file to be
		read and parsed twice on every startup — now avoided.
		"""
		mac_files_dir = os.path.dirname(self.stateFile) + "/mac2Vendor/"
		try:
			self.M2V = MAC2Vendor.MAP2Vendor(
				pathToMACFiles          = mac_files_dir,
				refreshFromIeeAfterDays = 10,
				myLogger                = self.indiLOG.log,
			)
			# MAP2Vendor.__init__ calls makeFinalTable() when the JSON is ready.
			# Check whether the dict is already populated to avoid a second read.
			already_ready = (
				hasattr(self.M2V, "mac2VendorDict") and
				isinstance(self.M2V.mac2VendorDict, dict) and
				len(self.M2V.mac2VendorDict.get("6", {})) > 1000
			)
			if already_ready:
				self.waitForMAC2vendor = False
				self.indiLOG.log(20, "MAC2Vendor lookup table ready.")
			else:
				# Table not yet built — background download must be in progress
				self.waitForMAC2vendor = not self.M2V.makeFinalTable(quiet=True)
				if not self.waitForMAC2vendor:
					self.indiLOG.log(20, "MAC2Vendor lookup table ready.")
				else:
					self.indiLOG.log(20, "MAC2Vendor: downloading OUI tables in background…")
		except Exception as e:
			self.indiLOG.log(30, f"MAC2Vendor init failed: {e} — vendor names will show as 'Unknown'")

	def _update_vendor_files(self) -> bool:
		"""Retry building the table if the background download has completed."""
		if self.M2V is None:
			return False
		if self.waitForMAC2vendor:
			self.waitForMAC2vendor = not self.M2V.makeFinalTable(quiet=False)
			if not self.waitForMAC2vendor:
				self.indiLOG.log(20, "MAC2Vendor lookup table ready.")
		return not self.waitForMAC2vendor

	def get_vendor(self, mac: str) -> str:
		"""Return vendor/manufacturer name for a MAC, or 'Unknown'."""
		if not self._update_vendor_files():
			return "Unknown"
		try:
			result = self.M2V.getVendorOfMAC(mac)
			return result.strip() if result else "Unknown"
		except Exception:
			return "Unknown"

	def _load_ignored_macs(self) -> set:
		"""Load ignored MACs from pluginPrefs as a set of lowercase strings."""
		raw = self.pluginPrefs.get("ignoredMacs", "")
		return {m.strip().lower() for m in raw.split(",") if m.strip()}

	def _save_ignored_macs(self):
		"""Persist ignored MACs back to pluginPrefs as a comma-separated string."""
		self.pluginPrefs["ignoredMacs"] = ", ".join(sorted(self._ignored_macs))

	def _load_state(self):
		if os.path.exists(self.stateFile):
			try:
				with open(self.stateFile, "r") as f:
					self._known = json.load(f)
				# Backfill keys added in later versions so every entry is uniform.
				for entry in self._known.values():
					entry.setdefault("history",    [])   # on/off history — empty list if absent
					entry.setdefault("local_name", "")   # mDNS/Bonjour name
					entry.setdefault("name",       "")   # Indigo device name
					entry.setdefault("curlPort",   None) # last curl port that responded
				entry.setdefault("curlUseless", 0)  # consecutive all-port curl failures
				self.indiLOG.log(20, f"Loaded {len(self._known)} known devices from state file.")
			except Exception as e:
				self.indiLOG.log(30, f"Could not load state file: {e}")

	def _save_state(self):
		try:
			with self._known_lock:
				snapshot = dict(self._known)
			with open(self.stateFile, "w") as f:
				json.dump(snapshot, f, indent=2)
		except Exception as e:
			self.indiLOG.log(30, f"Could not save state file: {e}")

	# ------------------------------------------------------------------
	# Menu actions (visible in Indigo's Plugins menu)
	# ------------------------------------------------------------------

	def importNamesFromFingscan(self, valuesDict=None,  *args):
		"""read device names from fingscan, store them in fingscan info and use when a matching mac number is found. write to dev state: fingscanDeviceName"""
		self.indiLOG.log(20, f"Importing fingscan dev names…")
		count = 0
		_fingScanDevices = {}
		for dev in indigo.devices.iter("com.karlwachs.fingscan"):
			if dev.deviceTypeId != "IP-Device": continue
			if "MACNumber" not in dev.states: continue
			_fingScanDevices[dev.states["MACNumber"]] = json.dumps({"name":dev.name, "pingMode": dev.pluginProps.get("setUsePing","none")})
		
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			for mac in _fingScanDevices:
				if dev.states["macAddress"].lower() == mac.lower():
					count += 1 
					if dev.states["fingscanDeviceInfo"] != _fingScanDevices[mac]:
						dev.updateStateOnServer("fingscanDeviceInfo", value=_fingScanDevices[mac])
						break
		self.indiLOG.log(20, f"Importing fingscan dev names, found {count} matches")

		return valuesDict


	def overwriteDevNamesWithFingNames(self, valuesDict=None, *args):
		"""use the above imported names to overwrite the device names like: NET_oldFingname"""
		self.indiLOG.log(20, f"overwriting  dev names with fingscan dev names… to NET_old fingscan name ")
		count = 0
	
		_fingToMyPingMode = {"doNotUsePing":"none", "usePingifUP":"offline", "usePingifDown":"online", "usePingifUPdown":"both", "useOnlyPing":"pingOnly"}
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			if dev.states["fingscanDeviceName"] != "":
				fingInfo = json.loads(dev.states["fingscanDeviceInfo"])
				pingMode = fingInfo["pingMode"]
				myPingMode = _fingToMyPingMode.get(pingMode,"none")

				oldName = dev.states['fingscanDeviceName']
				newName =  f"{oldName}-{self._getPrefixName()}".strip("_").strip("-")
				if dev.name != newName:
					count += 1 
					dev.name = newName
					dev.replaceOnServer()

				if myPingMode != "none":
					props = dev.pluginProps
					props["pingMode"] = myPingMode
					dev.replacePluginPropsOnServer(props)


		self.indiLOG.log(20, f"overwriting dev names, found {count} overwrites")

		return valuesDict


	def listKnownDevices(self):
		with self._known_lock:
			snapshot = dict(self._known)
		if not snapshot:
			self.indiLOG.log(20, "No devices discovered yet.")
			return

		# Build a lookup: mac → Indigo device (if it exists)
		dev_by_mac = {}
		for dev in indigo.devices.iter(PLUGIN_ID):
			m = dev.states.get("macAddress", "").lower()
			if m:
				dev_by_mac[m] = dev

		sep = "─" * 110
		self.indiLOG.log(20, sep)
		self.indiLOG.log(20, "All Discovered Network Devices")
		self.indiLOG.log(20, sep)

		for mac, entry in sorted(snapshot.items()):
			ip        = entry.get("ip",     "")
			vendor    = entry.get("vendor", "Unknown")
			online    = entry.get("online", False)
			last_seen = entry.get("last_seen", 0)
			ts        = datetime.datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M:%S") if last_seen else "never"

			local_name = entry.get("local_name", "")
			self.indiLOG.log(20, f"  MAC       : {mac}")
			self.indiLOG.log(20, f"  IP        : {ip or '—'}")
			self.indiLOG.log(20, f"  LocalName : {local_name or '—'}")
			self.indiLOG.log(20, f"  Vendor    : {vendor}")
			streak = entry.get("ping_fail_streak", 0)
			self.indiLOG.log(20, f"  Online  : {'Yes' if online else 'No'}   Last seen: {ts}   Ping-fail streak: {streak}")

			dev = dev_by_mac.get(mac)
			if dev:
				# --- Indigo device states ---
				states = dev.states
				self.indiLOG.log(20, f"  Indigo  : {dev.name}  (id={dev.id})")
				self.indiLOG.log(20, f"    onOffState      : {'on' if states.get('onOffState') else 'off'}")
				self.indiLOG.log(20, f"    lastOnOffChange : {states.get('lastOnOffChange', '')}")
				self.indiLOG.log(20, f"    created         : {states.get('created', '')}")
				open_ports = states.get("openPorts", "")
				self.indiLOG.log(20, f"    openPorts       : {open_ports or '—'}")
				comment = states.get("comment", "")
				self.indiLOG.log(20, f"    comment         : {comment or '—'}")

				# --- per-device plugin properties ---
				props          = dev.pluginProps
				ping_mode      = props.get("pingMode",         "none")
				offline_logic  = props.get("pingOfflineLogic", "and")
				missed_needed  = props.get("pingMissedCount",  "1")
				offline_thresh = props.get("offlineThreshold", "0")
				suppress_ip    = bool(props.get("suppressIpChangeLog", False))
				log_seen       = bool(props.get("logSeenToFile",       False))
				global_thresh  = int(self.pluginPrefs.get("offlineThreshold", "180"))
				eff_thresh     = int(offline_thresh) if offline_thresh and int(offline_thresh) > 0 else global_thresh
				self.indiLOG.log(20, f"    pingMode        : {ping_mode}")
				if ping_mode not in ("none", "online"):
					self.indiLOG.log(20, f"    offlineLogic    : {offline_logic}   missedPings: {missed_needed}   streak now: {streak}")
				self.indiLOG.log(20, f"    offlineThreshold: {offline_thresh or '0'}  (effective: {eff_thresh}s)")
				self.indiLOG.log(20, f"    suppressIpLog   : {suppress_ip}")
				self.indiLOG.log(20, f"    logSeenToFile   : {log_seen}")
			else:
				self.indiLOG.log(20, f"  Indigo  : no Indigo device")

			# --- on/off history (stored in known_devices.json, last 10 events) ---
			history = entry.get("history", [])
			if history:
				self.indiLOG.log(20, f"  History : (newest first)")
				for h in reversed(history):
					self.indiLOG.log(20, f"    {h.get('ts','?')}  →  {h.get('state','?')}")
			else:
				# No history recorded yet — fall back to the onOffState uiValue from
				# the Indigo device state, which is set to "on/off  YYYY-MM-DD HH:MM:SS"
				fallback = ""
				if dev:
					state_str   = "on" if dev.states.get("onOffState", False) else "off"
					last_change = dev.states.get("lastOnOffChange", "")
					fallback    = f"{state_str}  {last_change}" if last_change else state_str
				if fallback:
					self.indiLOG.log(20, f"  History : (from device state)  {fallback}")
				else:
					self.indiLOG.log(20, f"  History : none recorded yet")

			self.indiLOG.log(20, sep)


	def forceRescan(self):
		"""Trigger an immediate ARP sweep + ping check."""
		iface = self.pluginPrefs.get("networkInterface", "en0").strip() or "en0"
		self.indiLOG.log(20, "Forcing immediate network rescan…")
		t = threading.Thread(
			target=self._scan_loop_once,
			args=(iface, self.pluginPrefs.get("arpSweepEnabled", True)),
			daemon=True,
		)
		t.start()

	def _scan_loop_once(self, iface: str, sweep_enabled: bool):
		if sweep_enabled:
			self._arp_sweep(iface)
		self._check_all_devices(iface)
		self._save_state()
		self.indiLOG.log(20, "Forced rescan complete.")


	def printInstableDevices(self, valuesDict=None, *args):
		"""Menu: print devices that have frequent on off to enable better settings fr ping and threshold"""
		cutoff = float(valuesDict.get("cutoff", "60"))


		with self._known_lock:
			snapshot = dict(self._known)
			
		if not snapshot:
			self.indiLOG.log(20, "No devices discovered yet.")
			return valuesDict
			
		for mac in snapshot:
			history = snapshot[mac]["history"]
			#self.indiLOG.log(20,f" mac:{mac},  history:{history}")
			if len(history) < 4: continue
			
			"""history:[
				  {"ts": "2026-04-15 17:58:48", "state": "on"       },
				  {"ts": "2026-04-15 18:00:23", "state": "off"       },
				  {"ts": "2026-04-15 18:05:09", "state": "on"       },
				  {"ts": "2026-04-15 18:06:44", "state": "off"       }, ...
				  ]
			"""		
			# first do on -> off
			firstOn = False
			dt = {"on":list(), "off":list()}
			maxSec = {"on":0., "off":0.}
			counter = {"on":0, "off":0}
			opposit = {"on":"off","off":"on"}
			for event in history:
				if dt["on"] == list() and event["state"] != "on": continue
				if event["state"] == "on": dt["on"].append([event["ts"],"",0])
				else: dt["on"][-1][1] = event["ts"]
				
			for event in history:
				if dt["off"] == list() and event["state"] != "off": continue
				if event["state"] == "off": dt["off"].append([event["ts"],"",0])
				else: dt["off"][-1][1] = event["ts"]
			#self.indiLOG.log(20,f" mac:{mac},  dt:{dt}")
				
			for onoff in dt:
				for event in dt[onoff]:
					if event[1] == "": continue
					deltaSecs  = _date_diff_in_Seconds(event[0], event[1])
					#self.indiLOG.log(20,f" mac:{mac}, onoff:{onoff};  deltaSecs:{deltaSecs}")
					if deltaSecs > cutoff: continue
					maxSec[onoff] = max(maxSec[onoff], deltaSecs)
					counter[onoff] += 1
				#self.indiLOG.log(20,f" mac:{mac},  onOff:{onoff}; av:{average[onoff]}, count:{counter[onoff]}")
				if counter[onoff] < 3: continue
				try: 
					dev = indigo.devices[snapshot[mac]["indigo_device_id"]]
					pingMode = dev.pluginProps["pingMode"]
				except: pingMode = "       "
				
				self.indiLOG.log(20,f"{snapshot[mac]['name'][:30]:30}  transition:{onoff} → {opposit[onoff]};  max time:{maxSec[onoff]:3} secs; number of events:{counter[onoff]:2}; pingMode used:{pingMode}; suggestion: increase  \"Offline Threshold\" to {int(maxSec[onoff]*1.7)//60:3} minutes")
				
				
		return valuesDict   # button callback inside ConfigUI — must return valuesDict to keep dialog open
				
				
	def printSeenStats(self, valuesDict=None, *args):
		"""Menu: print per-device seen-interval histograms to the log."""
		sort_by = (valuesDict or {}).get("sortOrder", "ip")
		now     = time.time()

		with self._known_lock:
			snapshot = dict(self._known)
		if not snapshot:
			self.indiLOG.log(20, "No devices discovered yet.")
			return valuesDict

		# Build MAC → device name  and  MAC → device object (for pluginProps)
		names       = {}
		devs_by_mac = {}
		for dev in indigo.devices.iter(PLUGIN_ID):
			m = dev.states.get("macAddress", "").lower()
			if m:
				names[m]       = dev.name
				devs_by_mac[m] = dev

		def _ip_sort_key(item):
			return _ip_for_notes(item[1].get("ip", "999.999.999.999"))

		def _name_sort_key(item):
			return names.get(item[0], item[0]).lower()

		def _lastseen_sort_key(item):
			return item[1].get("last_seen_str", "")

		key_fns  = {"ip": _ip_sort_key, "name": _name_sort_key, "lastseen": _lastseen_sort_key}
		key_fn   = key_fns.get(sort_by, _ip_sort_key)
		sort_lbl = {"ip": "IP address", "name": "device name", "lastseen": "last seen"}.get(sort_by, "IP address")

		# Column widths (adjust here to reformat the table)
		W_NAME = 36   # Indigo device name
		W_IP   = 16   # zero-padded IP
		W_PING = 8    # ping mode  (longest value: "offline " = 7 + 1 pad)

		hdr_bins = "  ".join(f"{_SEEN_LABEL[b]:>7}" for b in _SEEN_BINS)
		sep_len  = W_NAME + 1 + W_IP + 1 + 3 + 1 + W_PING + 19 + 1 + 8 + 1 + 7 + 2 + (9 * len(_SEEN_BINS) - 1)
		sep      = "─" * sep_len

		out =  "\n"+sep 
		out += "\n"+f"Seen-Interval Statistics  (sorted by {sort_lbl})"
		out += "\n"
		out += 		f"{'Device':<{W_NAME}} {'IP':<{W_IP}} {'St':<3} {'Ping':<{W_PING}}"
		out += 		f"{'Last Seen':<19} {'Ago':>8} {'Total':>7}  {hdr_bins}"
		out += "\n"+sep

		for mac, entry in sorted(snapshot.items(), key=key_fn):
			raw        = entry.get("seen_stats", {})
			stats      = {b: int(raw.get(b, raw.get(str(b), 0))) for b in _SEEN_BINS}
			total      = sum(stats[b] for b in _SEEN_BINS)
			name       = names.get(mac, mac)[:W_NAME - 1]
			ip         = _ip_for_notes(entry.get("ip", ""))
			state      = "on " if entry.get("online", False) else "off"
			last_seen  = entry.get("last_seen_str", "")
			last_ts    = entry.get("last_seen", 0)
			ago_str    = f"={int(now - last_ts):>5}s" if last_ts else "       "
			local_name = entry.get("local_name", "")
			counts     = "  ".join(f"{stats[b]:>7}" for b in _SEEN_BINS)

			# Ping mode from Indigo device pluginProps (— if no Indigo device yet)
			ping_mode = "—"
			dev = devs_by_mac.get(mac)
			if dev:
				try:
					ping_mode = dev.pluginProps.get("pingMode", "—")
				except Exception:
					pass

			out += "\n"
			out += 		f"{name:<{W_NAME}} {ip:<{W_IP}} {state:<3} {ping_mode:<{W_PING}}"
			out += 		f"{last_seen:<19} {ago_str:>8} {total:>7}  {counts}"
			
			# Local name on its own indented line — only when present
			if local_name:
				indent = " " * 20
				out += "\n"+f"{indent}local: {local_name}"

		out += "\n"+sep
		out += "\n"
		out +=		"Bins: " + "  ".join(f"{_SEEN_LABEL[b]}" for b in _SEEN_BINS)
		out +=		"   (counts = number of sightings within that gap)"
		
		out += "\n"+sep
		self.indiLOG.log(20,out)
		return valuesDict   # button callback inside ConfigUI — must return valuesDict to keep dialog open

	def resetSeenStats(self):
		"""Menu: clear all seen-interval histograms for every known device."""
		with self._known_lock:
			count = len(self._known)
			for mac in self._known:
				self._known[mac]["seen_stats"] = {b: 0 for b in _SEEN_BINS}
		self._save_state()
		self.indiLOG.log(20, f"Seen-interval stats reset for {count} device(s).")

	def helpPlugin(self):
		"""Menu: print PLUGIN_HELP to log """
		self.indiLOG.log(20, "\n"+PLUGIN_HELP)

	# ------------------------------------------------------------------
	# Per-device port scanning
	# ------------------------------------------------------------------

	def _scan_ports_one(self, ip: str) -> list:
		"""Probe all _SCAN_PORTS on a single IP; return sorted list of open ports."""
		open_p = []
		lock   = threading.Lock()
		threads = []

		def _probe(port):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(0.5)
				if s.connect_ex((ip, port)) == 0:
					with lock:
						open_p.append(port)
				s.close()
			except Exception:
				pass

		for port in _SCAN_PORTS:
			if self._stop_event.is_set():
				return []
			t = threading.Thread(target=_probe, args=(port,), daemon=True)
			t.start()
			threads.append(t)

		deadline = time.time() + 3
		for t in threads:
			remaining = deadline - time.time()
			t.join(timeout=max(remaining, 0))

		return sorted(open_p)

	def _port_scan_device(self, dev_id: int, ip: str):
		"""Port-scan one device, update openPorts state, and fix device name with vendor."""
		if self._stop_event.is_set() or not ip:
			return
		open_p   = self._scan_ports_one(ip)
		port_str = ", ".join(f"{p}/{_SCAN_PORTS[p][0]}" for p in open_p) if open_p else ""
		try:
			dev        = indigo.devices[dev_id]
			mac        = dev.states.get("macAddress", "")
			vendor     = dev.states.get("vendorName", "")
			local_name = self._known.get(mac.lower(), {}).get("local_name", "") if mac else ""
			# Update openPorts state
			dev.updateStateOnServer("openPorts", value=port_str)
			# Rename if still auto-named and a better label (local name or vendor) is now known
			if mac and self._is_auto_name(dev.name, mac):
				correct = _mac_to_device_name(mac, vendor, local_name=local_name, prefixName = self._getPrefixName())
				if dev.name != correct:
					dev.name = correct
					dev.replaceOnServer()
					self.indiLOG.log(20, f"Device renamed to '{correct}'")
		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Port scan update failed for device {dev_id}: {e}")

	def scanOpenPorts(self):
		"""Menu: launch TCP port scan on all online devices in a background thread."""
		t = threading.Thread(target=self._port_scan_worker, daemon=True, name="NS-PortScan")
		t.start()

	def _port_scan_worker(self):
		"""Scan _SCAN_PORTS on every online known device and print a formatted report."""
		scan_start = time.time()

		with self._known_lock:
			snapshot = dict(self._known)

		# Collect online devices, sorted by IP address
		targets = sorted(
			[
				(entry.get("ip", ""), mac, entry.get("vendor", "Unknown"))
				for mac, entry in snapshot.items()
				if entry.get("online") and entry.get("ip")
			],
			key=lambda x: [int(o) for o in x[0].split(".") if o.isdigit()]
		)

		if not targets:
			self.indiLOG.log(20, "Port scan: no online devices to scan.")
			return

		self.indiLOG.log(20,
			f"Port scan starting — {len(targets)} online device(s), "
			f"{len(_SCAN_PORTS)} ports each…"
		)

		# Probe all (ip, port) pairs in parallel threads (I/O-bound, 0.5 s timeout each)
		open_ports   = {ip: [] for ip, _, _ in targets}
		results_lock = threading.Lock()

		def _probe(ip, port):
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(0.5)
				if sock.connect_ex((ip, port)) == 0:
					with results_lock:
						open_ports[ip].append(port)
				sock.close()
			except Exception:
				pass

		threads = []
		for ip, _mac, _vendor in targets:
			for port in _SCAN_PORTS:
				if self._stop_event.is_set():
					return
				t = threading.Thread(target=_probe, args=(ip, port), daemon=True)
				t.start()
				threads.append(t)

		# Wait for all probes (hard ceiling: 0.5 s timeout + 2 s slack)
		deadline = time.time() + 3
		for t in threads:
			remaining = deadline - time.time()
			if remaining <= 0:
				break
			t.join(timeout=max(remaining, 0))

		elapsed    = time.time() - scan_start
		total_open = sum(len(v) for v in open_ports.values())

		# ── Format report ──────────────────────────────────────────────────
		W    = 72
		sep  = "─" * W
		sep2 = "═" * W

		self.indiLOG.log(20, "")
		self.indiLOG.log(20, f"  Port Scan Results — {_now_str()}")
		self.indiLOG.log(20, sep2)

		for ip, mac, vendor in targets:
			ports    = sorted(open_ports.get(ip, []))
			dev_name = _mac_to_device_name(mac, prefixName = self._getPrefixName())
			self.indiLOG.log(20, f"  {dev_name}   {_ip_for_notes(ip)}   {vendor}")

			if ports:
				self.indiLOG.log(20, f"  {'Port':<7} {'Service':<12} Description")
				self.indiLOG.log(20, "  " + "─" * 58)
				for port in ports:
					svc, desc = _SCAN_PORTS[port]
					self.indiLOG.log(20, f"  {port:<7} {svc:<12} {desc}")
			else:
				self.indiLOG.log(20, "  (no open ports found in scanned range)")
			self.indiLOG.log(20, "")

		self.indiLOG.log(20, sep)
		self.indiLOG.log(20,
			f"  Scan complete: {len(targets)} device(s)  •  "
			f"{total_open} open port(s) found  •  {elapsed:.1f} s"
		)
		self.indiLOG.log(20, "")

	def getNetworkDeviceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""List of discovered devices NOT yet ignored — shown in top panel."""
		pending = self._dialog_ignored(valuesDict)
		items   = []
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac    = dev.states.get("macAddress", "").lower()
			ip     = dev.states.get("ipAddress",  "")
			vendor = dev.states.get("vendorName", "Unknown")
			if not mac or mac in pending: continue
			items.append((mac, f"{_ip_for_notes(ip)}   {mac}   {vendor}"))
		items.sort(key=lambda x: x[1])
		return items

	def getIgnoredDeviceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""List of currently ignored devices — shown in bottom panel."""
		pending = self._dialog_ignored(valuesDict)
		items   = []
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac    = dev.states.get("macAddress", "").lower()
			ip     = dev.states.get("ipAddress",  "")
			vendor = dev.states.get("vendorName", "Unknown")
			if not mac or mac not in pending: continue
			items.append((mac, f"{_ip_for_notes(ip)}   {mac}   {vendor}"))
		# Also include ignored MACs that have no Indigo device (deleted manually)
		for mac in sorted(pending):
			if not any(mac == item[0] for item in items):
				items.append((mac, f"(no device)   {mac}"))
		items.sort(key=lambda x: x[1])
		return items

	def _dialog_ignored(self, valuesDict):
		"""Return the working ignored-set for the current dialog session."""
		if valuesDict is None:
			return set(self._ignored_macs)
		raw = valuesDict.get("pendingIgnoredMacs", None)
		if raw is None:
			return set(self._ignored_macs)   # first open — seed from real set
		return {m.strip() for m in raw.split(",") if m.strip()}

	@staticmethod
	def _list_selection(valuesDict, fieldId):
		"""Safely extract a single selected value from an Indigo list field."""
		val = valuesDict.get(fieldId, "")
		if isinstance(val, str):
			return val.strip().lower()
		try:
			items = list(val)
			return str(items[0]).strip().lower() if items else ""
		except Exception:
			return str(val).strip().lower()

	def addToIgnored(self, valuesDict, *args):
		"""Button: move selected device from available list → ignored list."""
		mac = self._list_selection(valuesDict, "availableDevicesList")
		if not mac:
			return valuesDict
		pending = self._dialog_ignored(valuesDict)
		pending.add(mac)
		valuesDict["pendingIgnoredMacs"] = ",".join(sorted(pending))
		return valuesDict

	def removeFromIgnored(self, valuesDict, *args):
		"""Button: move selected device from ignored list → available list."""
		mac = self._list_selection(valuesDict, "ignoredDevicesList")
		if not mac:
			return valuesDict
		pending = self._dialog_ignored(valuesDict)
		pending.discard(mac)
		valuesDict["pendingIgnoredMacs"] = ",".join(sorted(pending))
		return valuesDict

	def manageIgnoredMacs(self, valuesDict, *args):
		"""OK button — commit the pending ignored set to persistent storage."""
		new_set = self._dialog_ignored(valuesDict)
		added   = new_set - self._ignored_macs
		removed = self._ignored_macs - new_set
		self._ignored_macs = new_set
		self._save_ignored_macs()
		if added:
			self.indiLOG.log(20, f"Ignored MACs added:   {', '.join(sorted(added))}")
		if removed:
			self.indiLOG.log(20, f"Ignored MACs removed: {', '.join(sorted(removed))}")
		self.indiLOG.log(20,
			f"Ignored MACs: {len(self._ignored_macs)} "
			f"entr{'y' if len(self._ignored_macs) == 1 else 'ies'}"
			+ (f" — {', '.join(sorted(self._ignored_macs))}" if self._ignored_macs else " — none")
		)
		return True

	# ------------------------------------------------------------------
	# Action callbacks
	# ------------------------------------------------------------------

	def pingDeviceAction(self, pluginAction, dev, callerWaitingForResult):
		"""Ping a single device on demand."""
		mac   = dev.states.get("macAddress", "")
		ip    = dev.states.get("ipAddress",  "")
		iface = self.pluginPrefs.get("networkInterface", "en0").strip() or "en0"

		if not ip:
			self.indiLOG.log(20, f"No IP known for {dev.name}; cannot ping.")
			return

		online = _arp_ping(ip, iface)
		vendor = self._known.get(mac, {}).get("vendor", dev.states.get("vendorName", "Unknown"))

		with self._known_lock:
			entry = self._known.get(mac, {})
			entry["online"] = online
			if online:
				entry["last_seen"] = time.time()
			self._known[mac] = entry

		local_name = self._known.get(mac, {}).get("local_name", "")
		self._update_indigo_device_states(dev, mac, ip, vendor, online, local_name=local_name)
		self.indiLOG.log(10, f"{dev.name} ({ip}) is {'ONLINE' if online else 'OFFLINE'}")

	# ------------------------------------------------------------------
	# Set-device-state dialog callbacks
	# ------------------------------------------------------------------

	def filterNetworkAllDevices(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Populate device selector in setDevState dialog."""
		items = []
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac = dev.states.get("macAddress", "")
			ip  = dev.states.get("ipAddress",  "")
			items.append((str(dev.id), f"{dev.name}   {ip}   {mac}"))
		items.sort(key=lambda x: x[1])
		return items

	def dynamicCallbackSetDeviceID(self, valuesDict, typeId="", devId=0):
		"""Called when the device selector changes — refresh stateName list and oldValue."""
		dev_id_str = valuesDict.get("devId", "0")
		try:
			dev_id = int(dev_id_str)
			dev    = indigo.devices[dev_id]
			# Pre-select first state if none chosen yet
			if not valuesDict.get("stateName", ""):
				states = list(dev.states.keys())
				if states:
					valuesDict["stateName"] = states[0]
			state_name = valuesDict.get("stateName", "")
			if state_name and state_name in dev.states:
				valuesDict["oldValue"] = str(dev.states[state_name])
			else:
				valuesDict["oldValue"] = ""
			valuesDict["MSG"] = f"Device: {dev.name}"
		except Exception:
			valuesDict["oldValue"] = ""
			valuesDict["MSG"]      = ""
		return valuesDict

	def selectState(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Populate state-name list for the currently selected device."""
		if valuesDict is None:
			return []
		dev_id_str = valuesDict.get("devId", "0")
		try:
			dev_id = int(dev_id_str)
			dev    = indigo.devices[dev_id]
			items  = [(k, k) for k in sorted(dev.states.keys())]
			# Also update oldValue while we're here
			state_name = valuesDict.get("stateName", "")
			if state_name and state_name in dev.states:
				valuesDict["oldValue"] = str(dev.states[state_name])
			return items
		except Exception:
			return []

	def executeOverwriteButtonState(self, valuesDict, *args):
		"""Button: write newValue (and optional newValueUi) to the selected state."""
		dev_id_str  = valuesDict.get("devId", "0")
		state_name  = valuesDict.get("stateName", "").strip()
		new_value   = valuesDict.get("newValue",   "").strip()
		new_value_ui = valuesDict.get("newValueUi", "").strip()
		try:
			dev_id = int(dev_id_str)
			dev    = indigo.devices[dev_id]
			if not state_name:
				self.indiLOG.log(30, "setDevState: no state name selected")
				return valuesDict
			old_value = str(dev.states.get(state_name, ""))
			if new_value_ui:
				dev.updateStateOnServer(state_name, value=new_value, uiValue=new_value_ui)
			else:
				dev.updateStateOnServer(state_name, value=new_value)
			self.indiLOG.log(20,
				f"setDevState: {dev.name}  state={state_name}  "
				f"old={old_value!r}  new={new_value!r}"
				+ (f"  ui={new_value_ui!r}" if new_value_ui else "")
			)
			# Refresh oldValue display
			valuesDict["oldValue"] = new_value
			valuesDict["MSG"]      = f"Done — {dev.name}.{state_name} = {new_value!r}"
		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(40, f"setDevState error: {e}", exc_info=True)
			valuesDict["MSG"] = f"Error: {e}"
		return valuesDict

	def renameWithVendorAction(self, pluginAction, dev, callerWaitingForResult):
		"""Rename the Indigo device to include the vendor name."""
		mac    = dev.states.get("macAddress", "")
		vendor = dev.states.get("vendorName", "")
		if vendor and vendor != "Unknown":
			safe_vendor = re.sub(r"[^A-Za-z0-9_\- ]", "", vendor)[:20].strip()
			new_name    = f"{safe_vendor}_{mac.replace(':','').upper()[-6:]}"
			try:
				dev.name = new_name
				dev.replaceOnServer()
				self.indiLOG.log(20, f"Renamed device to '{new_name}'")
			except Exception as e:
				if f"{e}".find("None") == -1: self.indiLOG.log(40, f"Rename failed: {e}", exc_info=True)
		else:
			self.indiLOG.log(20, f"No vendor info for {dev.name}; rename skipped.")


# ---------------------------------------------------------------------------
# LevelFormatter  (same class as used in homematic and all other plugins)
# Allows a different format string and date format per log level.
# ---------------------------------------------------------------------------
class LevelFormatter(logging.Formatter):
	def __init__(self, fmt=None, datefmt=None, level_fmts=None, level_date=None):
		self._level_formatters = {}
		if level_fmts and level_date:
			for level, fmt_str in level_fmts.items():
				self._level_formatters[level] = logging.Formatter(
					fmt=fmt_str, datefmt=level_date.get(level, datefmt)
				)
		super().__init__(fmt=fmt, datefmt=datefmt)

	def format(self, record):
		if record.levelno in self._level_formatters:
			return self._level_formatters[record.levelno].format(record)
		return super().format(record)
