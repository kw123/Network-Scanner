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
  /usr/sbin/tcpdump   — passive ARP sniffing
  /sbin/ping          — subnet sweep and reachability checks
  /usr/sbin/arp       — reads ARP cache after sweep
  MAC2Vendor.py       — bundled OUI vendor lookup (auto-downloads + caches)

--------------------------------------------------------------------------------
DISCOVERY METHODS
  1. Passive ARP sniffing  — listens for ARP broadcasts via tcpdump (no sweep)
  2. Active ARP sweep      — parallel ping sweep of the entire subnet, then
                             reads ARP cache; only ping-responders update
                             last-seen (stale ARP entries are ignored)
  3. Periodic ping check   — keeps online/offline states current between sweeps

--------------------------------------------------------------------------------
PLUGIN CONFIGURATION  (Plugins → Network Scanner → Configure…)
  Network Interface                 interface to sniff, default en0 (WiFi)
  Scan Interval (s)                 how often to ping known devices  [30/60/90/120]
  Enable ARP Sweep                  active subnet sweep each scan cycle
  Enable Passive Sniffing           listen for ARP traffic between sweeps
  Offline Threshold (s)             unreachable for this long → marked offline
                                    [30/60/90/120/180/240/300/360/420, default 180]
                                    can be overridden per device in device edit
  Ignore offline changes at startup suppress offline decisions for N seconds after
                                    plugin start so ARP can re-confirm devices
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

--------------------------------------------------------------------------------
DEVICE EDIT  (double-click any Net_* device)
  Ping Usage
    Online + Offline (both)         ping sets both online and offline state
    Online only                     ping can mark online, not offline
    Offline only                    ping can mark offline, not online
    Confirm offline  [default]      ping only fires when ARP timeout exceeded;
                                    logs to plugin.log when ping keeps device online
    Not at all                      ping ignored; ARP timeout alone decides offline
				use "Online + Offline" for verbose ping tracking of device
				use "Online only"  to get devices back to "on" fast when they disappeared (left house and came back)
				use "Offline only" to make devices go offline fast when they disappear
				use "Confirm offline" to make sure that devices that have the tendency to be quiet do not go off to fast
				use "Not at all" if device is fine w/o ping checks
  Offline Trigger Logic
    AND  [default]                  timeout expired AND ping failed (fewest false alarms)
    OR                              timeout expired OR  ping failed (faster detection)
  Missed Pings Before Offline       consecutive failures before offline [1–5, default 1]
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

def _now_str():
	return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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


def _mac_to_device_name(mac: str, vendor: str = "") -> str:
	"""Build the auto-generated device name.
	Without vendor : Net_AA:BB:CC:DD:EE:FF
	With vendor    : Net_AA:BB:CC:DD:EE:FF  Apple Inc
	"""
	base = "Net_" + mac.upper()
	if vendor and vendor.strip().lower() not in ("", "unknown"):
		safe = re.sub(r"[^A-Za-z0-9 _\-]", "", vendor).strip()[:20]
		if safe:
			return f"{base}  {safe}"
	return base


def _is_auto_name(name: str, mac: str) -> bool:
	"""Return True if name was auto-generated (starts with Net_<MAC>).
	Used to decide whether it is safe to rename the device.
	"""
	return name.startswith("Net_" + mac.upper())


def _ping(ip: str, timeout: int = 1) -> bool:
	"""Return True if host replies to a single ICMP ping."""
	try:
		result = subprocess.run(
			["/sbin/ping", "-c", "1", "-W", str(timeout * 1000), "-t", str(timeout), ip],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
			timeout=timeout + 2,
		)
		return result.returncode == 0
	except Exception:
		return False


def _arp_ping(ip: str, iface: str, timeout: int = 2) -> bool:
	"""Check reachability via ping (built-in macOS tool, no root required)."""
	return _ping(ip, timeout)


def _local_subnet(iface: str):
	"""
	Return (network_str, cidr) e.g. ('192.168.1.0', 24)
	by parsing `ifconfig` output.  Returns None on failure.
	"""
	try:
		out = subprocess.check_output(["/sbin/ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
		m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", out)
		if not m:
			return None
		ip_str, mask_str = m.group(1), m.group(2)
		if mask_str.startswith("0x"):
			mask_int = int(mask_str, 16)
		else:
			parts = [int(p) for p in mask_str.split(".")]
			mask_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
		cidr    = bin(mask_int).count("1")
		ip_int  = struct.unpack("!I", socket.inet_aton(ip_str))[0]
		net_int = ip_int & mask_int
		net_str = socket.inet_ntoa(struct.pack("!I", net_int))
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

		# Register SIGTERM handler so Indigo's "polite stop" exits immediately
		# without waiting for the IPC message pump
		signal.signal(signal.SIGTERM, self._on_sigterm)

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
		self.indiLOG.log(20, f"Network Scanner starting up…  (offline grace period: {grace} s)")
		self._startup_time = time.time()   # offline grace period starts here
		self._stop_event.clear()
		self._rename_existing_net_devices()
		self._move_existing_net_devices()
		self._start_threads()
		# Port scans are now launched per-device from deviceStartComm().

	def _on_sigterm(self, signum, frame):
		"""SIGTERM handler — Indigo's polite stop signal."""
		self._stop_event.set()
		self._kill_tcpdump()
		self._save_state_fast()
		os._exit(0)

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

	def _save_state_fast(self):
		"""Lockless best-effort state save for use in shutdown paths.

		We deliberately skip _known_lock here: acquiring a lock that a scan/sniff
		thread might be holding would block the main thread indefinitely, preventing
		os._exit(0) from being reached and causing macOS to wait 20 s before SIGKILL.
		A slightly inconsistent snapshot is better than a hung process.
		"""
		try:
			snapshot = dict(self._known)   # shallow copy without lock — fine on CPython
			with open(self.stateFile, "w") as f:
				json.dump(snapshot, f, indent=2)
		except Exception:
			pass   # never log here — Indigo IPC may already be gone

	def shutdown(self):
		"""Called by Indigo after runConcurrentThread exits."""
		self._stop_event.set()
		self._kill_tcpdump()
		self._save_state_fast()
		os._exit(0)

	def runConcurrentThread(self):
		"""Indigo's cooperative loop – sleep in 1 s steps so stop is near-instant."""
		try:
			while True:
				self.sleep(1)
		except self.StopThread:
			pass

	def stopConcurrentThread(self):
		self._stop_event.set()
		super().stopConcurrentThread()   # raises StopThread inside runConcurrentThread
		# Kill tcpdump immediately — its open stdout pipe is what keeps
		# the Python process alive after Indigo's polite stop signal.
		proc = self._sniff_proc
		if proc and proc.poll() is None:
			try:
				proc.kill()
			except Exception:
				pass

	# ------------------------------------------------------------------
	# Preferences
	# ------------------------------------------------------------------

	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			self.setLogFromPrefs(valuesDict)
			# Restart threads so new interface/interval settings take effect
			self._stop_event.set()
			time.sleep(2)
			self._stop_event.clear()
			self._start_threads()

	# ------------------------------------------------------------------
	# Device lifecycle
	# ------------------------------------------------------------------

	def deviceStartComm(self, dev):
		# Tell Indigo to refresh the device's state list against the current
		# Devices.xml definition.  Required for existing devices to pick up
		# newly added states (e.g. openPorts) without recreating the device.
		dev.stateListOrDisplayStateIdChanged()

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

		if sniff_on:
			self._sniff_thread = threading.Thread(
				target=self._sniff_loop, args=(iface,), daemon=True, name="NS-Sniff"
			)
			self._sniff_thread.start()
			self.indiLOG.log(20, f"ARP sniffer (tcpdump) started on {iface}")
		else:
			self.indiLOG.log(20, "Passive ARP sniffing disabled.")

		self._scan_thread = threading.Thread(
			target=self._scan_loop, args=(iface, sweep_on), daemon=True, name="NS-Scan"
		)
		self._scan_thread.start()
		self.indiLOG.log(20, "Device scan loop started.")

	# ------------------------------------------------------------------
	# Sniff loop (tcpdump subprocess — no root required)
	# ------------------------------------------------------------------

	def _sniff_loop(self, iface: str):
		"""
		Passively capture ARP packets using tcpdump subprocess.
		tcpdump on macOS has the necessary entitlements and does not
		require the plugin to run as root.
		Example tcpdump lines parsed:
		  14:23:11.456789 ARP, Request who-has 192.168.1.1 tell 192.168.1.45
		  14:23:11.457123 ARP, Reply 192.168.1.1 is-at a4:91:b1:ff:12:34
		"""
		_reply_re = re.compile(
			r"ARP,\s+Reply\s+([\d.]+)\s+is-at\s+([0-9a-f:]{17})", re.IGNORECASE
		)
		_ether_re = re.compile(
			r"([0-9a-f:]{17})\s+>\s+[0-9a-f:]{17}.*?ARP.*?tell\s+([\d.]+)",
			re.IGNORECASE,
		)

		while not self._stop_event.is_set():
			try:
				proc = subprocess.Popen(
					["/usr/sbin/tcpdump", "-i", iface, "-n", "-e", "-l", "arp"],
					stdout=subprocess.PIPE,
					stderr=subprocess.DEVNULL,
					text=True,
					bufsize=1,
				)
				self._sniff_proc = proc
				# Use select() so we check stop_event every 0.2 s
				# even when the network is quiet and tcpdump has no output
				while not self._stop_event.is_set():
					ready, _, _ = select.select([proc.stdout], [], [], 0.2)
					if not ready:
						continue          # timeout — loop back and check stop_event
					line = proc.stdout.readline()
					if not line:
						break             # tcpdump exited
					# Parse Reply lines → definitive MAC→IP mapping
					m = _reply_re.search(line)
					if m:
						ip, mac = m.group(1), m.group(2).lower()
						if mac != "00:00:00:00:00:00":
							self._register_device(mac, ip)
						continue
					# Parse Request lines → sender MAC + IP
					m2 = _ether_re.search(line)
					if m2:
						mac, ip = m2.group(1).lower(), m2.group(2)
						if mac != "00:00:00:00:00:00":
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
			self.indiLOG.log(20, f"ARP sweep (ping+arp) → {net_str}/{cidr}")
		try:
			ip_int     = struct.unpack("!I", socket.inet_aton(net_str))[0]
			host_count = min((1 << (32 - cidr)) - 2, 254)   # cap at /24

			responded   = set()          # IPs that replied to ping this cycle
			resp_lock   = threading.Lock()

			def _ping_host(ip):
				try:
					r = subprocess.run(
						["/sbin/ping", "-c", "1", "-W", "1000", "-t", "1", ip],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
					)
					if r.returncode == 0:
						with resp_lock:
							responded.add(ip)
				except Exception:
					pass

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
				["/usr/sbin/arp", "-a", "-i", iface],
				stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
				timeout=10, text=True
			)
			arp_re   = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", re.IGNORECASE)
			seen_n   = 0
			discov_n = 0
			for line in result.stdout.splitlines():
				m = arp_re.search(line)
				if m:
					ip, mac = m.group(1), m.group(2).lower()
					if mac == "ff:ff:ff:ff:ff:ff":
						continue
					if ip in responded:
						self._register_device(mac, ip)   # actively replied → update last_seen
						seen_n += 1
					else:
						self._discover_device(mac, ip)   # stale cache → discover only
						discov_n += 1
			if self.decideMyLog("Sweep"):
				self.indiLOG.log(20,
					f"ARP sweep complete on {net_str}/{cidr}: "
					f"{seen_n} device(s) replied to ping (online), "
					f"{discov_n} in ARP cache but no ping reply (likely offline / stale)"
				)
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"ARP sweep error: {e}", exc_info=True)

	def _check_all_devices(self, iface: str):
		"""Ping all known devices in parallel and update online/offline state.

		Per-device props read from Indigo pluginProps:
		  pingMode         – "both" | "online" | "offline" | "confirm" | "none"
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
				ping_ok = _arp_ping(ip, iface)
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
				ping_ok = _arp_ping(ip, iface)
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
			ping_ok = _arp_ping(ip, iface)

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

	def _discover_device(self, mac: str, ip: str):
		"""Called for stale ARP-cache entries that did NOT respond to ping this sweep.

		Updates IP mapping and creates the Indigo device if needed, but intentionally
		does NOT update last_seen or set online=True — those fields must only change
		when the device is genuinely reachable.
		"""
		if mac.lower() in self._ignored_macs:
			return
		with self._known_lock:
			entry = self._known.get(mac, {})
			if not entry:                         # brand-new MAC — seed a minimal entry
				entry["online"]    = False
				entry["last_seen"] = 0
			entry["ip"] = ip
			if "vendor" not in entry:
				entry["vendor"] = self.get_vendor(mac)
			self._known[mac] = entry
		# Ensure an Indigo device exists, but do not update online state
		self._ensure_indigo_device(mac, ip, entry.get("vendor", ""), entry.get("online", False))

	def _register_device(self, mac: str, ip: str):
		"""
		Add or update a MAC entry, then create or refresh the Indigo device.
		Called from sniff thread and ping-confirmed sweep hits.
		"""
		if mac.lower() in self._ignored_macs:
			if self.decideMyLog("Ignored"):
				self.indiLOG.log(20, f"Ignored MAC skipped: {mac}")
			return

		now = time.time()
		with self._known_lock:
			entry      = self._known.get(mac, {})
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
		if self.decideMyLog("Seen"):
			self.indiLOG.log(20, f"Seen: {mac}  IP={ip}  vendor={entry['vendor']}")
		# Per-device seen flag → plugin.log only (level 10, below indigo_log_handler threshold)
		if log_seen_to_file:
			self.indiLOG.log(10, f"Seen: {mac}  IP={ip}  vendor={entry['vendor']}")
		# IP-change log — honoured unless suppressed for this device
		if changed_ip and old_ip and self.decideMyLog("IpChange") and not suppress_ip_log:
			self.indiLOG.log(20, f"IP changed: {mac}  {old_ip} → {ip}")

		self._ensure_indigo_device(mac, ip, entry["vendor"], True)

	def _ensure_indigo_device(self, mac: str, ip: str, vendor: str, online: bool):
		"""Create the Indigo device if it doesn't exist, then update its states."""
		dev_name = _mac_to_device_name(mac, vendor)
		existing = None
		for dev in indigo.devices.iter(PLUGIN_ID):
			if dev.states.get("macAddress", "").lower() == mac.lower():
				existing = dev
				break

		if existing is None and self.pluginPrefs.get("autoCreateDevices", True):
			existing = self._create_indigo_device(mac, ip, vendor, dev_name)

		if existing is not None:
			self._update_indigo_device_states(existing, mac, ip, vendor, online)

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
				self._known.setdefault(mac, {})["indigo_device_id"] = new_dev.id
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

	def _update_indigo_device_states(self, dev, mac: str, ip: str, vendor: str, online: bool):
		"""Push only changed state values into an existing Indigo device.

		lastOnOffChange is only written when the online/offline value flips.
		last_seen (last ARP/ping ok epoch) lives only in _known — never pushed
		to Indigo, so routine scan hits produce zero device updates.
		"""
		prev_online  = dev.states.get("onOffState",  None)
		prev_ip      = dev.states.get("ipAddress",   "")
		prev_mac     = dev.states.get("macAddress",  "")
		prev_vendor  = dev.states.get("vendorName",  "")
		prev_created = dev.states.get("created",     "")

		online_changed = (prev_online is None) or (bool(prev_online) != online)
		ip_changed     = prev_ip     != ip
		mac_changed    = prev_mac    != mac
		vendor_changed = prev_vendor != vendor
		created_needed = not prev_created

		if not any([online_changed, ip_changed, mac_changed, vendor_changed, created_needed]):
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
		if ip_changed:
			state_updates.append({"key": "ipAddress",  "value": ip})
		if mac_changed:
			state_updates.append({"key": "macAddress",  "value": mac})
		if vendor_changed:
			state_updates.append({"key": "vendorName",  "value": vendor})
		if created_needed:
			state_updates.append({"key": "created",     "value": _now_str()})

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

			# Rename device when vendor first becomes known and name is still auto-generated
			if vendor_changed and vendor and vendor.lower() != "unknown":
				if _is_auto_name(dev.name, mac):
					correct = _mac_to_device_name(mac, vendor)
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
				vendor = self._known.get(mac, {}).get("vendor", "Unknown")
				self._update_indigo_device_states(dev, mac, ip, vendor, online)
				break

	# ------------------------------------------------------------------
	# Folder helpers
	# ------------------------------------------------------------------

	def _rename_existing_net_devices(self):
		"""Ensure auto-named Net_* devices have the correct name (MAC + vendor).
		Only touches devices whose name starts with Net_<MAC> — user renames are preserved.
		"""
		renamed = 0
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac    = dev.states.get("macAddress", "")
			vendor = dev.states.get("vendorName", "")
			if not mac: continue
			if not _is_auto_name(dev.name, mac):
				continue   # user has renamed this device — leave it alone
			correct = _mac_to_device_name(mac, vendor)
			if dev.name != correct:
				try:
					dev.name = correct
					dev.replaceOnServer()
					renamed += 1
				except Exception as e:
					self.indiLOG.log(30, f"Could not rename {dev.name} → {correct}: {e}")
		if renamed:
			self.indiLOG.log(20, f"Renamed {renamed} Net_* device(s).")

	def _move_existing_net_devices(self):
		"""Move any existing Net_* devices into the configured folder."""
		folder_id = self._get_or_create_folder()
		if folder_id == 0:
			return
		moved = 0
		for dev in indigo.devices:
			if dev.name.startswith("Net_") and dev.folderId != folder_id:
				try:
					indigo.device.moveToFolder(dev.id, value=folder_id)
					moved += 1
				except Exception as e:
					self.indiLOG.log(30, f"Could not move {dev.name} to folder: {e}")
		if moved:
			self.indiLOG.log(20, f"Moved {moved} Net_* device(s) to folder '{self.pluginPrefs.get('deviceFolder', 'Network Devices')}'")

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
		The download is asynchronous — waitForMAC2vendor stays True until
		the files arrive and the table is built.
		"""
		mac_files_dir = os.path.dirname(self.stateFile) + "/mac2Vendor/"
		try:
			self.M2V = MAC2Vendor.MAP2Vendor(
				pathToMACFiles          = mac_files_dir,
				refreshFromIeeAfterDays = 10,
				myLogger                = self.indiLOG.log,
			)
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

			self.indiLOG.log(20, f"  MAC     : {mac}")
			self.indiLOG.log(20, f"  IP      : {ip or '—'}")
			self.indiLOG.log(20, f"  Vendor  : {vendor}")
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

	def printSeenStats(self, valuesDict=None, *args):
		"""Menu: print per-device seen-interval histograms to the log."""
		sort_by = (valuesDict or {}).get("sortOrder", "ip")

		with self._known_lock:
			snapshot = dict(self._known)
		if not snapshot:
			self.indiLOG.log(20, "No devices discovered yet.")
			return valuesDict

		# Build a MAC → device-name lookup
		names = {}
		for dev in indigo.devices.iter(PLUGIN_ID):
			m = dev.states.get("macAddress", "").lower()
			if m:
				names[m] = dev.name

		def _ip_sort_key(item):
			return _ip_for_notes(item[1].get("ip", "999.999.999.999"))

		def _name_sort_key(item):
			return names.get(item[0], item[0]).lower()

		def _lastseen_sort_key(item):
			return item[1].get("last_seen_str", "")

		key_fns  = {"ip": _ip_sort_key, "name": _name_sort_key, "lastseen": _lastseen_sort_key}
		key_fn   = key_fns.get(sort_by, _ip_sort_key)
		sort_lbl = {"ip": "IP address", "name": "device name", "lastseen": "last seen"}.get(sort_by, "IP address")

		# Header row
		hdr_bins = "  ".join(f"{_SEEN_LABEL[b]:>7}" for b in _SEEN_BINS)
		sep      = "─" * (76 + 9 * len(_SEEN_BINS))
		self.indiLOG.log(20, sep)
		self.indiLOG.log(20, f"Seen-Interval Statistics  (sorted by {sort_lbl})")
		self.indiLOG.log(20, f"{'Device':<36} {'IP':<16} {'St':<4} {'Last Seen':<20} {'Total':>6}  {hdr_bins}")
		self.indiLOG.log(20, sep)

		for mac, entry in sorted(snapshot.items(), key=key_fn):
			raw       = entry.get("seen_stats", {})
			stats     = {b: int(raw.get(b, raw.get(str(b), 0))) for b in _SEEN_BINS}
			total     = sum(stats[b] for b in _SEEN_BINS)
			name      = names.get(mac, mac)[:35]
			ip        = _ip_for_notes(entry.get("ip", ""))
			state     = "on " if entry.get("online", False) else "off"
			last_seen = entry.get("last_seen_str", "")
			counts    = "  ".join(f"{stats[b]:>7}" for b in _SEEN_BINS)
			self.indiLOG.log(20, f"{name:<36} {ip:<16} {state:<4} {last_seen:<20} {total:>6}  {counts}")

		self.indiLOG.log(20, sep)
		self.indiLOG.log(20,
			"Bins: " + "  ".join(f"{_SEEN_LABEL[b]}" for b in _SEEN_BINS) +
			"   (counts = number of sightings within that gap)"
		)
		self.indiLOG.log(20, sep)
		return valuesDict   # button callback inside ConfigUI must return valuesDict to keep dialog open

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
			dev    = indigo.devices[dev_id]
			mac    = dev.states.get("macAddress", "")
			vendor = dev.states.get("vendorName", "")
			# Update openPorts state
			dev.updateStateOnServer("openPorts", value=port_str)
			# Rename if still auto-named and vendor is now known
			if mac and _is_auto_name(dev.name, mac):
				correct = _mac_to_device_name(mac, vendor)
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
			dev_name = _mac_to_device_name(mac)
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

		self._update_indigo_device_states(dev, mac, ip, vendor, online)
		self.indiLOG.log(20, f"{dev.name} ({ip}) is {'ONLINE' if online else 'OFFLINE'}")

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
