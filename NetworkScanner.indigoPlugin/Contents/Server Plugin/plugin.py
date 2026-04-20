#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ---------------------------------------------------------------------------
# Full documentation is in Contents/README.md
# The Help menu item reads and prints that file.
# ---------------------------------------------------------------------------
__doc__ = "Network Scanner – Indigo Plugin.  See README.md for full documentation."

import indigo          # type: ignore  (provided by Indigo at runtime)
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
import shlex
import logging
import urllib.request

import MAC2Vendor  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PLUGIN_ID			= "com.karlwachs.networkscanner"
DEVICE_TYPE_ID		= "networkDevice"
EXT_DEVICE_TYPE_ID	= "externalDevice"
HOME_AWAY			= "networkDevicesHomeAway"   # aggregate device: tracks up to 6 network devices
ONLINE				= "externalDevicesOffline"   # aggregate device: tracks up to 3 external devices
INTERNET_ADDRESS	= "internetAddress"          # monitors public WAN IP address

STDDTSTRING    = "%Y-%m-%d %H:%M:%S"
_CURL_PORTS_DEFAULT = (80, 443, 22, 8080)
_THROTTLE_SECS      = 30.0   # minimum seconds between registrations per MAC

# ---------------------------------------------------------------------------
# Plugin config defaults
# Indigo ignores defaultValue= in PluginConfig.xml for prefs already saved,
# so we apply these ourselves in __init__ for any key that is missing.
# ---------------------------------------------------------------------------
kDefaultPluginPrefs = {
	"networkInterface":		"en0",
	"scanInterval":			"60",
	"arpSweepEnabled":		True,
	"sniffEnabled":			True,
	"offlineThreshold":		"180",
	"startupGracePeriod":	"60",
	"autoCreateDevices":	True,
	"deviceFolder":			"Network Devices",
	"variableFolder":		"Network Devices",
	"prefixName":			"NET_",
	"pingMissedCount":		"1",
	"sudoPassword": 		"",
	# 							per-device defaults (applied when creating new devices)
	"pingMode":				"confirm",
	# 							logging categories  (key = "debug" + area-name)
	"showdebugsection":		True,
	"debugNewDevice":		True,
	"debugStateChange":		True,
	"stateChangeLogLevel":	"20",
	"debugIpChange":		True,
	"debugSeen":			False,
	"debugSweep":			False,
	"debugIgnored":			False,
	"debugPing":			False,
	"debugTcpdumpArp":		False,   # log every ARP reply captured by tcpdump (before throttle)
	"debugArpSweepEntries":	False,   # log every entry parsed from  arp -a  during sweep
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
		data += b'\x00'              # pad to even length — required by the algorithm
	s = sum(struct.unpack('!%dH' % (len(data) // 2), data))  # sum all 16-bit words
	s = (s >> 16) + (s & 0xFFFF)    # fold 32-bit carry back into 16 bits
	s += s >> 16                     # fold again in case the addition itself overflowed
	return ~s & 0xFFFF               # one's complement, masked to 16 bits


def _ping(ip: str, timeout: float = 1.0) -> bool:
	"""Return True if host replies to an ICMP echo request.

	Uses SOCK_DGRAM + IPPROTO_ICMP — no subprocess, no root required on macOS.
	The kernel fills in the IP header; we supply only the ICMP payload.

	Error mapping:
	  recv() returns data  → echo reply received → True
	  socket.timeout       → no reply within timeout → False
	  OSError              → unreachable / no route / permission denied → False
	"""
	icmp_id  = os.getpid() & 0xFFFF              # unique id per process so replies match our request
	header   = struct.pack('!BBHHH', 8, 0, 0, icmp_id, 1)   # type=8 (echo request), code=0, checksum placeholder, id, seq=1
	payload  = b'NS'                              # arbitrary payload — just needs to be non-empty
	checksum = _icmp_checksum(header + payload)   # compute checksum over header+payload with placeholder=0
	packet   = struct.pack('!BBHHH', 8, 0, checksum, icmp_id, 1) + payload  # rebuild with real checksum

	s = None
	try:
		# SOCK_DGRAM + IPPROTO_ICMP: macOS allows this without root — kernel handles IP header
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
		s.settimeout(timeout)
		s.sendto(packet, (ip, 0))  # port 0 is ignored for ICMP; kernel fills in IP header
		s.recv(1024)               # any reply means the host is up
		return True
	except Exception:
		return False               # timeout, unreachable, or permission denied → host not responding
	finally:
		if s:
			try: s.close()
			except Exception: pass



def _curl_check(ip: str, preferred_port: int = None, timeout: float = 0.5,
                rst_counts_alive: bool = True) -> int | None:
	"""TCP-connect probe: try common ports and return the first responding port, or None.

	Uses a raw Python socket — no subprocess overhead.
	preferred_port is tried first (last port that worked for this device).

	rst_counts_alive (default True):
	  True  – ConnectionRefusedError (TCP RST) counts as alive.  Use for periodic
	           reachability probes: if the device sent RST its TCP stack is running.
	  False – RST is ignored (try next port, eventually return None if no full
	           handshake succeeds).  Use for ARP-sweep probes: some routers send
	           RST on behalf of all subnet IPs, which would cause false ON transitions
	           for devices that are actually offline.

	Result logic:
	  connect() succeeds          → port open,   device alive  → return port
	  ConnectionRefusedError      → rst_counts_alive=True  → return port (TCP stack alive)
	                                 rst_counts_alive=False → skip (router may have sent RST)
	  socket.timeout / OSError    → no response on this port   → try next
	"""
	# Try preferred_port first (last port that worked), then the standard list minus that port
	ports = ((preferred_port,) + tuple(p for p in _CURL_PORTS_DEFAULT if p != preferred_port)
	         if preferred_port else _CURL_PORTS_DEFAULT)
	for port in ports:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.settimeout(timeout)
			s.connect((ip, port))
			return port                      # full TCP handshake succeeded — port is open, device alive
		except ConnectionRefusedError:
			if rst_counts_alive:
				return port                  # device sent RST — port closed but TCP stack is running → alive
			# else: router may have sent RST on device's behalf — don't count as alive in sweep mode
		except (socket.timeout, OSError):
			pass                             # no response (filtered/dropped) or unreachable — try next port
		finally:
			try:
				s.close()                    # always release the socket fd
			except Exception:
				pass
	return None                              # no port responded — device unreachable


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
# ---------------------------------------------------------------------------
# Public IP helpers
# ---------------------------------------------------------------------------

_PUBLIC_IP_SERVICES = [
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
]

def _fetch_public_ip() -> tuple[bool, str]:
	"""Try several well-known IP-echo services in order.

	Returns (True, ip_string) on the first success, or (False, "") if all fail.
	Each service is given a 10-second timeout; errors are silently skipped.
	"""
	for url in _PUBLIC_IP_SERVICES:
		try:
			with urllib.request.urlopen(url, timeout=10) as resp:
				ip = resp.read().decode().strip()
				socket.inet_aton(ip)   # validate — raises OSError if not a valid IPv4
				return True, ip
		except Exception:
			continue
	return False, ""


# ---------------------------------------------------------------------------
# Plugin Class
# ---------------------------------------------------------------------------

class Plugin(indigo.PluginBase):

	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super().__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)

		# Compare running version against last-saved version stored in pluginPrefs.
		# self._schema_changed is True on every version upgrade — deviceStartComm()
		# uses it to call stateListOrDisplayStateIdChanged() once per device without
		# reading or writing any per-device prop.
		self._plugin_version  = pluginVersion
		old_schema            = self.pluginPrefs.get("schemaVersion", "")
		self._schema_changed  = (old_schema != pluginVersion)
		if self._schema_changed:
			self.pluginPrefs["schemaVersion"] = pluginVersion

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
		# README.md sits one level up from "Server Plugin/" inside the bundle.
		# os.getcwd() is set to "Server Plugin/" by Indigo before __init__ runs.
		self._readme_path  = os.path.realpath(os.path.join(os.getcwd(), "..", "README.md"))

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

		# dev_id → {"host": str, "fail_streak": int}  for externalDevice type
		self._ext_devices: dict = {}

		# dev_id → last epoch when lastOnMessage was written (throttle: max 1/min)
		self._last_on_msg_ts: dict = {}

		# dev_id → threading.Event  for internetAddress device background threads
		self._pub_ip_stop: dict = {}

		self._triggers: dict = {}   # unused; kept so existing pickled state doesn't break

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

	# ------------------------------------------------------------------
	# Offline watchdog
	# ------------------------------------------------------------------

	def _offline_watchdog(self):
		"""Continuously check every known device's last_seen against its offline threshold.

		Runs every 15 s independent of the scan interval.  When a device has not
		been seen for longer than its threshold it is marked offline immediately,
		regardless of what the probe cycle is doing.  This is the authoritative
		source for timeout-triggered offline transitions.

		setOffBy is set to "timeout" so the user can see why the device went offline.
		"""
		CHECK_INTERVAL = 15   # seconds between watchdog sweeps

		while not self._stop_event.wait(timeout=CHECK_INTERVAL):
			# Wait out the startup grace period before making any offline decisions.
			if (time.time() - self._startup_time) < self._grace_period_secs():
				continue

			now              = time.time()
			plugin_threshold = int(self.pluginPrefs.get(
				"offlineThreshold", kDefaultPluginPrefs["offlineThreshold"]) or
				kDefaultPluginPrefs["offlineThreshold"])

			with self._known_lock:
				snapshot = dict(self._known)

			for mac, entry in snapshot.items():
				if self._stop_event.is_set():
					break
				if mac.lower() in self._ignored_macs:
					continue
				if not entry.get("online", False):
					continue   # already offline — nothing to do
				last_seen = entry.get("last_seen", 0)
				if last_seen == 0:
					continue   # never confirmed online — skip

				# Per-device threshold (0 = use plugin-wide default)
				threshold = plugin_threshold
				dev_id    = entry.get("indigo_device_id")
				if dev_id:
					try:
						idev = indigo.devices[dev_id]
						if not idev.enabled:
							continue   # device disabled in Indigo — skip offline check
						dev_thresh = int(idev.pluginProps.get("offlineThreshold", 0) or 0)
						if dev_thresh > 0:
							threshold = dev_thresh
					except Exception:
						pass

				if now - last_seen > threshold:
					with self._known_lock:
						self._known[mac]["online"] = False
					self._update_indigo_device(mac, entry.get("ip", ""), False,
					                           source="timeout")

	def _grace_period_secs(self) -> int:
		"""Return the startup grace period in seconds as a safe integer."""
		try:
			return max(0, int(self.pluginPrefs.get("startupGracePeriod", kDefaultPluginPrefs["startupGracePeriod"]) or kDefaultPluginPrefs["startupGracePeriod"]))
		except (ValueError, TypeError):
			return 60

	def startup(self):
		grace = self._grace_period_secs()
		self.indiLOG.log(20, f"Network Scanner starting up…  (offline ignore period: {grace} s)")
		self._startup_time = time.time()
		self._stop_event.clear()
		self._ensure_plugin_variables()
		self._rename_and_move_net_devices()       # single pass: rename + move
		#self.indiLOG.log(20, f"startup: rename/move done  ")
		self._backfill_history_from_devices()
		#self.indiLOG.log(20, f"startup: backfill done ")
		self._start_threads()
		self.indiLOG.log(20, f"Network Scanner active")



	def _getPrefixName(self):
		return self.pluginPrefs.get("prefixName",kDefaultPluginPrefs["prefixName"]).strip()

	def _is_auto_name(self, name: str, mac: str) -> bool:
		"""Return True if name was auto-generated (starts with prefix+MAC).
		Returns False when mac is empty — an empty MAC would match every device name.
		"""
		if not mac:
			return False
		return name.startswith(self._getPrefixName() + mac.upper())



	def _kill_tcpdump(self):
		"""Kill the tcpdump subprocess and release its stdout pipe fd.

		Kill first so that any blocking os.read() in the sniff thread gets EOF,
		then immediately close stdout to free the file descriptor.  We use raw
		os.read() (not readline / TextIOWrapper), so there is no lock contention
		on proc.stdout.close().
		"""
		proc = self._sniff_proc
		if proc:
			self._sniff_proc = None   # clear first so sniff thread won't re-enter
			try: proc.kill()          # unblocks os.read() in the sniff thread via EOF
			except Exception: pass
			try: proc.stdout.close()  # release the pipe fd immediately (prevents EMFILE)
			except Exception: pass
			try: proc.wait(timeout=2) # reap the zombie so the OS frees its fd table entry
			except Exception: pass

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
			self._ensure_plugin_variables()
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
		# ── Internet Address device (public WAN IP monitor) ─────────────────
		if dev.deviceTypeId == INTERNET_ADDRESS:
			if self._schema_changed:
				dev.stateListOrDisplayStateIdChanged()
			self._start_internet_address_device(dev)
			return

		# ── External device (ping-only, user-configured host) ──────────────
		if dev.deviceTypeId == EXT_DEVICE_TYPE_ID:
			host = dev.pluginProps.get("host", "").strip()
			self._ext_devices[dev.id] = {"host": host, "fail_streak": 0, "last_ping": 0}

			# Build all props changes in one read → modify → write to avoid
			# stale-local-object overwrites from multiple replacePluginPropsOnServer calls.
			props         = dict(dev.pluginProps)
			props_changed = False
			if self._schema_changed:
				dev.stateListOrDisplayStateIdChanged()
			if host and props.get("address", "") != host:
				props["address"] = host
				props_changed = True
			if props_changed:
				try:
					dev.replacePluginPropsOnServer(props)
				except Exception:
					pass

			# Sync host into device state
			if host and dev.states.get("host", "") != host:
				dev.updateStateOnServer("host", value=host)
			return   # no MAC lookup, no port scan

		# ── Aggregate group devices (HOME_AWAY / ONLINE) ────────────────────
		if dev.deviceTypeId in (HOME_AWAY, ONLINE):
			# Always refresh state list — needed for newly created devices as well
			# as after a schema/version change.
			dev.stateListOrDisplayStateIdChanged()
			dev_id = dev.id
			def _deferred_recalc(did, delay):
				# Wait for Indigo to register the (possibly new) state list before
				# pushing state values — especially important after stateListOrDisplayStateIdChanged().
				time.sleep(delay)
				try:
					d = indigo.devices[did]
					self._recalc_group_device(d)
				except Exception:
					pass
			# Always wait at least 1 s so Indigo can process stateListOrDisplayStateIdChanged()
			# before we push state values — 0 causes a race where the icon never appears.
			delay = 2.0 if self._schema_changed else 1.0
			threading.Thread(
				target=_deferred_recalc, args=(dev_id, delay),
				daemon=True, name=f"NS-GroupRecalc-{dev_id}"
			).start()
			return

		# ── Network device (MAC-based, auto-discovered) ─────────────────────
		# Refresh the state list only when the plugin version changed since the
		# last run.  self._schema_changed is computed once in __init__ by comparing
		# pluginVersion to pluginPrefs["schemaVersion"] — avoids a per-device prop
		# read/write on every normal restart.
		if self._schema_changed:
			dev.stateListOrDisplayStateIdChanged()

		mac = dev.states.get("MACNumber", "")
		if mac:
			with self._known_lock:
				entry = self._known.get(mac, {})
				entry["indigo_device_id"] = dev.id
				self._known[mac] = entry

		# Sync pingMode property → state so it's visible in Indigo device columns / triggers.
		try:
			pm = dev.pluginProps.get("pingMode", "confirm")
			if dev.states.get("pingMode", "") != pm:
				dev.updateStateOnServer("pingMode", value=pm)
		except Exception:
			pass

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
		ip = dev.states.get("ipNumber", "")
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
		if dev.deviceTypeId == INTERNET_ADDRESS:
			stop_ev = self._pub_ip_stop.pop(dev.id, None)
			if stop_ev:
				stop_ev.set()
			return
		if dev.deviceTypeId == EXT_DEVICE_TYPE_ID:
			self._ext_devices.pop(dev.id, None)
		elif dev.deviceTypeId == DEVICE_TYPE_ID:
			# Clear the cached device ID so the next _ensure_indigo_device call
			# does a fresh lookup rather than chasing a stale ID.
			mac = dev.states.get("MACNumber", "").lower()
			if mac:
				with self._known_lock:
					entry = self._known.get(mac, {})
					if entry.get("indigo_device_id") == dev.id:
						entry.pop("indigo_device_id", None)

	def getExternalDeviceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list callback: returns all externalDevice entries for trigger menus."""
		items = [("0", "— not used —")]
		for dev in sorted(indigo.devices.iter(PLUGIN_ID), key=lambda d: d.name.lower()):
			if dev.deviceTypeId == EXT_DEVICE_TYPE_ID:
				host = dev.pluginProps.get("host", "")
				label = f"{dev.name}  ({host})" if host else dev.name
				items.append((str(dev.id), label))
		return items

	def getNetworkDeviceListForTrigger(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list callback: returns all networkDevice entries for trigger menus."""
		items = [("0", "— not used —")]
		for dev in sorted(indigo.devices.iter(PLUGIN_ID), key=lambda d: d.name.lower()):
			if dev.deviceTypeId == DEVICE_TYPE_ID:
				ip = dev.states.get("ipNumber", "")
				label = f"{dev.name}  ({ip})" if ip else dev.name
				items.append((str(dev.id), label))
		return items

	def getDeviceConfigUiValues(self, pluginProps, typeId=None, devId=None):
		"""Pre-populate device edit fields with current live values."""
		theDictList = super(Plugin, self).getDeviceConfigUiValues(pluginProps, typeId, devId)
		if typeId == DEVICE_TYPE_ID and devId:
			try:
				dev = indigo.devices[devId]
				theDictList[0]["manualIpOverride"]     = dev.states.get("ipNumber", "")
				theDictList[0]["isApOrRouterOverride"] = dev.states.get("isApOrRouter", False)
			except Exception:
				pass
		return theDictList

	def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
		"""Sync pluginProps → device states whenever the dialog is saved."""
		if userCancelled:
			return
		try:
			dev     = indigo.devices[devId]
			comment = valuesDict.get("comment", "")
			dev.updateStateOnServer("comment", value=comment)
			# externalDevice: sync host → state, address column and registry
			if typeId == EXT_DEVICE_TYPE_ID:
				host = valuesDict.get("host", "").strip()
				host_changed = self._ext_devices.get(devId, {}).get("host", "") != host
				state_updates = [{"key": "host", "value": host}]
				if host_changed:
					state_updates += [
						{"key": "ipNumber", "value": ""},
						{"key": "pingMs",     "value": ""},
					]
				dev.updateStatesOnServer(state_updates)
				# Address column
				if dev.pluginProps.get("address", "") != host:
					props = dict(dev.pluginProps)
					props["address"] = host
					dev.replacePluginPropsOnServer(props)
				self._ext_devices[devId] = {"host": host, "fail_streak": 0, "last_ping": 0}
				# Probe immediately so the device doesn't sit offline until the next scan cycle
				threading.Thread(
					target=self._check_external_devices,
					daemon=True, name=f"NS-ExtPing-{devId}"
				).start()

			# ── Network device ──────────────────────────────────────────────────
			elif typeId == DEVICE_TYPE_ID:
				# Sync pingMode property → state immediately on save
				pm = valuesDict.get("pingMode", "confirm")
				if dev.states.get("pingMode", "") != pm:
					dev.updateStateOnServer("pingMode", value=pm)
				manual_ip = valuesDict.get("manualIpOverride", "").strip()
				if manual_ip and not self.isValidIP(manual_ip):
					self.indiLOG.log(30, f"{dev.name}: invalid IP address '{manual_ip}' — not applied")
					manual_ip = ""
				if manual_ip and manual_ip != dev.states.get("ipNumber", ""):
					dev.updateStateOnServer("ipNumber", value=manual_ip)
					# Keep _known in sync so the next scan doesn't immediately revert it
					mac = dev.states.get("MACNumber", "").lower()
					if mac:
						with self._known_lock:
							entry = self._known.get(mac, {})
							if entry:
								old_ip = entry.get("ip", "")
								entry["ip"] = manual_ip
								history = entry.setdefault("ip_history", [])
								if old_ip and old_ip != "0.0.0.0" and manual_ip != "0.0.0.0":
									history.append({
										"ts":     _now_str(),
										"old_ip": old_ip,
										"new_ip": manual_ip,
										"source": "manual",
									})
								if len(history) > 20:
									entry["ip_history"] = history[-20:]
								self._known[mac] = entry
						self._save_state()
					self.indiLOG.log(20, f"{dev.name}: IP manually set to {manual_ip}")
					# Update Notes column after a short delay — Indigo finishes writing
					# pluginProps after closedDeviceConfigUi returns, so an immediate
					# replaceOnServer() gets overwritten.
					_did    = devId
					_padded = _ip_for_notes(manual_ip)
					def _deferred_notes(did, padded):
						time.sleep(1.0)
						try:
							d = indigo.devices[did]
							if d.description != padded:
								d.description = padded
								d.replaceOnServer()
						except Exception as _e:
							if f"{_e}".find("None") == -1:
								self.indiLOG.log(30, f"Could not update Notes: {_e}")
					threading.Thread(target=_deferred_notes, args=(_did, _padded),
					                 daemon=True, name=f"NS-Notes-{devId}").start()

				# ── Manual AP/router flag ──────────────────────────────────────────
				new_is_ap = bool(valuesDict.get("isApOrRouterOverride", False))
				old_is_ap = bool(dev.states.get("isApOrRouter", False))
				if new_is_ap != old_is_ap:
					dev.updateStateOnServer("isApOrRouter", value=new_is_ap)
					mac = dev.states.get("MACNumber", "").lower()
					if mac:
						with self._known_lock:
							entry = self._known.get(mac, {})
							if entry:
								entry["is_ap_or_router"] = new_is_ap
								self._known[mac] = entry
						self._save_state()
					flag = "set" if new_is_ap else "cleared"
					self.indiLOG.log(20, f"{dev.name}: isApOrRouter manually {flag}")

		# ── Aggregate group devices: recalculate immediately after participant list changes ──
			elif typeId in (HOME_AWAY, ONLINE):
				self._recalc_group_device(dev)

		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Could not update states for device {devId}: {e}")

	# ------------------------------------------------------------------
	# Internal: thread management
	# ------------------------------------------------------------------

	def _start_threads(self):
		iface    = self.pluginPrefs.get("networkInterface", kDefaultPluginPrefs["networkInterface"]).strip() or kDefaultPluginPrefs["networkInterface"]
		sniff_on = self.pluginPrefs.get("sniffEnabled",     kDefaultPluginPrefs["sniffEnabled"])
		sweep_on = self.pluginPrefs.get("arpSweepEnabled",  kDefaultPluginPrefs["arpSweepEnabled"])
		password = self.pluginPrefs.get("sudoPassword",     kDefaultPluginPrefs["sudoPassword"]).strip()

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

		# Offline watchdog — checks last_seen every 15 s and marks devices offline
		# as soon as their threshold is exceeded, independent of the probe cycle.
		threading.Thread(
			target=self._offline_watchdog, daemon=True, name="NS-OfflineWatchdog"
		).start()
		self.indiLOG.log(20, "Offline watchdog started.")

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
		  HH:MM:SS.ffffff  aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Reply 192.168.1.1 is-at a4:91:b1:12:34:56
		  HH:MM:SS.ffffff  aa:bb:cc:dd:ee:ff > bb:cc:dd:ee:ff:00, ethertype IPv4 (0x0800), length 64: 192.168.1.45.54321 > 192.168.1.1.80: ...

		Parsing strategy:
		  1. ARP Reply  → definitive MAC+IP pair, register immediately
		  2. Any frame  → source MAC from ethernet header + source IP from IPv4 payload
		     Throttled: each MAC is registered at most once every 5 s to avoid
		     hammering _register_device on every packet of a busy device.

		If password is set, tcpdump is launched via  echo <pw> | sudo -S tcpdump …
		so that it can open the raw network socket without granting Indigo full root.
		"""
		self.indiLOG.log(20, f"_sniff_loop started  iface={iface}  sudo={'yes' if password else 'no'}")
		# ARP Reply: tcpdump -n -e without -v outputs ": Reply 1.2.3.4 is-at aa:bb:cc:dd:ee:ff"
		# (no leading "ARP," prefix).  \b matches both the verbose and non-verbose format.
		_arp_reply_re = re.compile(
			r"\bReply\s+([\d.]+)\s+is-at\s+([0-9a-f:]{17})", re.IGNORECASE
		)
		# Source MAC from the ethernet header (first field after timestamp)
		_src_mac_re = re.compile(r"^\S+\s+([0-9a-f:]{17})\s+>", re.IGNORECASE)
		# Source IP from IPv4 payload: "length N: W.X.Y.Z.port >"
		_src_ip_re  = re.compile(r"length \d+:\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)\.\d+\s+>")
		# Sender IP from ARP lines:
		#   Request: "tell 192.168.1.15"   Announcement: "Announcement 192.168.1.194"
		_arp_ip_re  = re.compile(r"(?:tell|Announcement)\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)", re.IGNORECASE)

		_throttle: dict = {}   # mac → last time _register_device was called

		def _log_raw_if_wanted(mac: str, line: str):
			"""Log the raw tcpdump line to plugin.log when logSeenToFile is set for this device."""
			with self._known_lock:
				entry = self._known.get(mac)
			if not entry:
				return
			dev_id = entry.get("indigo_device_id")
			if not dev_id:
				return
			try:
				if indigo.devices[dev_id].pluginProps.get("logSeenToFile", False):
					self.indiLOG.log(10, f"tcpdump [{mac}]: {line}")
			except Exception:
				pass

		# Targeted BPF filter: capture only frame types that signal device presence.
		# ARP covers discovery and IP changes; mDNS (5353) catches Apple/IoT/Chromecast;
		# DHCP (67/68) catches every device the moment it connects.
		# This reduces packet volume by ~95% vs capturing all traffic.
		_BPF = "arp or (udp port 5353) or (udp port 67) or (udp port 68)"

		while not self._stop_event.is_set():
			try:
				# Build shell command.  BPF filter must be single-quoted to protect
				# parentheses from shell interpretation.  stderr=DEVNULL: if stderr
				# were PIPE and nothing read it, sudo's password-prompt output fills
				# the 64 KB pipe buffer, blocks the process, and stdout goes silent.
				if password:
					shell_cmd = f"echo {shlex.quote(password)} | sudo -S /usr/sbin/tcpdump -i {iface} -n -e -l '{_BPF}'"
				else:
					shell_cmd = f"/usr/sbin/tcpdump -i {iface} -n -e -l '{_BPF}'"
				log_cmd = shell_cmd.replace(shlex.quote(password), "***") if password else shell_cmd
				self.indiLOG.log(20, f"tcpdump launch: {log_cmd}")
				proc = subprocess.Popen(
					shell_cmd, shell=True,
					stdout=subprocess.PIPE,
					stderr=subprocess.DEVNULL,
				)
				self._sniff_proc = proc

				# Read tcpdump stdout via pipe.  os.read on the raw fd avoids
				# TextIOWrapper buffering; select() with 0.2 s timeout lets the
				# stop_event be checked regularly without busy-looping.
				fd  = proc.stdout.fileno()
				buf = b""
				_diag_logged = False
				log_tcpdump_arp = self.decideMyLog("TcpdumpArp")
				while not self._stop_event.is_set():
					try: # when saving pluginconfig this line generates an error: OSError: [Errno 9] Bad file descriptor, this try except continue masks it
						ready, _, _ = select.select([proc.stdout], [], [], 0.2)
					except: 
						continue
				
					if not ready:
						if proc.poll() is not None:
							break
						continue
					try:
						chunk = os.read(fd, 65536)
					except OSError:
						break
					if not chunk:
						break
					if not _diag_logged:
						_diag_logged = True
						if log_tcpdump_arp:
							self.indiLOG.log(10, f"tcpdump first chunk {len(chunk)} bytes: {repr(chunk[:200])}")
					buf += chunk
					while b"\n" in buf:
						raw, buf = buf.split(b"\n", 1)
						line = raw.decode("utf-8", errors="replace")
						now = time.time()
						if False and line.find("ff:ff:ff:ff:ff:ff") == -1 and line.find("00:00:00:00:00:00") == -1:
							self.indiLOG.log(10, f" >>>  {len(line)} line: {line}")

						# ── ARP Reply: definitive MAC→IP, register once per (mac,ip) per throttle window ──
						m = _arp_reply_re.search(line)
						if m:
							ip  = m.group(1)
							mac = m.group(2).lower()
							if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
								# Log every ARP reply received (plugin config: Log Tcpdump ARP) — logged
								# BEFORE throttle so all replies are visible, with throttle status shown.
								if log_tcpdump_arp:
									key_check = (mac, ip)
									throttled = (now - _throttle.get(key_check, 0)) < _THROTTLE_SECS
									self.indiLOG.log(10, f"ARP reply  mac={mac}  ip={ip}"
									                     f"{'  [throttled]' if throttled else ''}")
								# Throttle per (mac, ip): a new IP always gets one pass,
								# but rapid repeats of the same mac (cycling IPs or busy AP)
								# are suppressed for _THROTTLE_SECS.
								key = (mac, ip)
								if now - _throttle.get(key, 0) < _THROTTLE_SECS:
									continue
								_throttle[key] = now
								_throttle[mac] = now   # also block the generic-frame path
								_log_raw_if_wanted(mac, line)
								self._register_device(mac, ip, source="traffic observed (tcpdump)")
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
						# Need an IP — try IPv4 payload format first, then ARP sender format
						mi = _src_ip_re.search(line) or _arp_ip_re.search(line)
						if not mi:
							continue
						ip = mi.group(1)
						# Skip unroutable source IPs: DHCP Discover/Request uses 0.0.0.0
						# before the client has an address; 169.254.x.x is link-local only.
						if ip == "0.0.0.0" or ip.startswith("169.254."):
							continue
						_log_raw_if_wanted(mac, line)
						_throttle[mac] = now
						self._register_device(mac, ip, source="traffic observed (tcpdump)")

				# Inner loop exited — kill tcpdump if still running
				try:
					self._kill_tcpdump()
				except Exception:
					pass

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
			interval = int(self.pluginPrefs.get("scanInterval", kDefaultPluginPrefs["scanInterval"]))

			if sweep_enabled:
				self._arp_sweep(iface)

			self._check_all_devices(iface)
			self._check_external_devices()
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
				"""Probe one IP: ICMP ping, then TCP fallback if ICMP is blocked.
				Adds IP to `responded` set if alive (used later to distinguish
				active ping replies from stale ARP cache entries).
				"""
				alive = _ping(ip)
				if log_ping:
					self.indiLOG.log(10, f"sweep ping  {ip}  {'ok' if alive else 'fail'}")
				if not alive:
					# ICMP may be filtered (firewall, iOS privacy mode) — try TCP ports.
					# rst_counts_alive=False: some routers send TCP RST on behalf of all
					# subnet IPs, which would add an offline device to `responded` and cause
					# a false ON transition.  Only a full TCP handshake counts here.
					port  = _curl_check(ip, preferred_port=ip_to_curl_port.get(ip),
					                    rst_counts_alive=False)
					alive = port is not None
					if log_ping and port is not None:
						self.indiLOG.log(10, f"sweep probe {ip}  ok port {port}")
					if port is not None:
						with curl_lock:
							curl_ports_by_ip[ip] = port   # remember winning port for next sweep
				if alive:
					with resp_lock:
						responded.add(ip)   # only IPs that actively replied go into this set

			# Ping all subnet hosts in parallel — bounded thread pool (max 30 concurrent)
			ips = [socket.inet_ntoa(struct.pack("!I", ip_int + i)) for i in range(1, host_count + 1)]
			with ThreadPoolExecutor(max_workers=30) as pool:
				futures = {pool.submit(_ping_host, ip): ip for ip in ips}
				deadline = time.time() + 8
				for fut in as_completed(futures, timeout=max(0.1, deadline - time.time())):
					if self._stop_event.is_set():
						return
					try:
						fut.result()
					except Exception:
						pass

			if self._stop_event.is_set():
				return

			# Adaptive arp timeout: start from last known-good value stored in pluginPrefs.
			# On each timeout double it and save back so the next call (and next plugin
			# start) uses the higher value.  Cap at 120 s to avoid hanging the scan loop.
			_ARP_TIMEOUT_MIN = 15
			_ARP_TIMEOUT_MAX = 40
			arp_timeout = max(_ARP_TIMEOUT_MIN,
			                  int(self.pluginPrefs.get("arpTimeout", _ARP_TIMEOUT_MIN)))
			result = None
			for _arp_attempt in range(2):
				try:
					result = subprocess.run(
						[
							"/usr/sbin/arp",
							"-a",         # show ALL entries in the kernel ARP cache
							"-i", iface,  # limit output to entries learned on this interface
						],
						stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
						timeout=arp_timeout, text=True
					)
					break   # success — keep current timeout
				except subprocess.TimeoutExpired:
					new_timeout = min(arp_timeout + 10, _ARP_TIMEOUT_MAX)
					self.pluginPrefs["arpTimeout"] = str(new_timeout)
					self.indiLOG.log(30,
						f"arp -a timeout ({arp_timeout}s) — raising to {new_timeout}s"
						+ (", retrying" if _arp_attempt == 0 else ", giving up"))
					arp_timeout = new_timeout
					result = None
				except Exception as e:
					self.indiLOG.log(30, f"arp -a error: {e}")
					result = None
					break
			if result is None:
				return
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
			# Deduplicate ARP entries by MAC: a proxy-ARP router or WiFi AP can appear
			# with many IPs for the same MAC.  Pick the best entry per MAC:
			#   1. responded to ping  (always beats cache-only)
			#   2. has a real hostname  (beats bare '?' entries)
			#   3. non-link-local IP  (169.254.x.x is a fallback address)
			#   4. first seen  (stable tie-break)
			arp_by_mac: dict = {}   # mac → (ip, local_name, responded_flag, proxy_arp_flag)
			log_arp_sweep = self.decideMyLog("ArpSweepEntries")
			for line in result.stdout.splitlines():
				m = arp_re.search(line)
				if not m:
					continue
				raw_name, ip, mac = m.group(1), m.group(2), m.group(3).lower()
				if mac == "ff:ff:ff:ff:ff:ff":
					continue
				# Log every raw arp -a entry (plugin config: Log ARP Sweep Entries)
				if log_arp_sweep:
					self.indiLOG.log(10, f"arp -a  mac={mac}  ip={ip}  name={raw_name}"
					                     f"{'  [replied]' if ip in responded else '  [cache-only]'}")
				if raw_name == "?" or re.match(r"^\d+\.\d+\.\d+\.\d+$", raw_name):
					local_name = ""
				else:
					local_name = raw_name.rstrip(".")
				replied    = ip in responded
				try:
					# inet_aton converts "169.254.x.x" → bytes; 0xA9=169, 0xFE=254.
					# 169.254.0.0/16 is the IANA link-local block (RFC 3927) — assigned
					# automatically by the OS when DHCP fails (APIPA / self-assigned).
					# These addresses are temporary and not routable, so deprioritised.
					link_local = (socket.inet_aton(ip)[0] == 0xA9 and socket.inet_aton(ip)[1] == 0xFE)
				except OSError:
					link_local = False
				if mac not in arp_by_mac:
					arp_by_mac[mac] = (ip, local_name, replied, False)
				else:
					cur_ip, cur_name, cur_replied, _ = arp_by_mac[mac]
					try:
						cur_ll = (socket.inet_aton(cur_ip)[0] == 0xA9 and socket.inet_aton(cur_ip)[1] == 0xFE)  # same check for current winner
					except OSError:
						cur_ll = False
					# Replace if new entry is strictly better.
					# Priority: no-hostname (?) > has-hostname > link-local
					# A bare '?' entry is the AP's own IP; named entries are proxy-ARP
					# clients behind it — we want the AP's real address, not a client's.
					# proxy_arp=True marks that multiple IPs shared this MAC so that a
					# stale localName from a previous sweep can be cleared.
					no_name     = not bool(local_name)
					cur_no_name = not bool(cur_name)
					if (replied     and not cur_replied) \
					   or (replied == cur_replied and no_name  and not cur_no_name) \
					   or (replied == cur_replied and no_name  == cur_no_name and cur_ll and not link_local):
						arp_by_mac[mac] = (ip, local_name, replied, True)
					else:
						# Keep current winner but mark as proxy-ARP
						arp_by_mac[mac] = (cur_ip, cur_name, cur_replied, True)

			seen_n   = 0
			discov_n = 0
			for mac, (ip, local_name, replied, proxy_arp) in arp_by_mac.items():
				if replied:
					self._register_device(mac, ip, local_name=local_name, clear_local_name=proxy_arp and not local_name)
					seen_n += 1
				else:
					self._discover_device(mac, ip, local_name=local_name, clear_local_name=proxy_arp and not local_name)
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

		plugin_offline_threshold = int(self.pluginPrefs.get("offlineThreshold", kDefaultPluginPrefs["offlineThreshold"]))
		now                      = time.time()

		# Do not mark anything offline during the first 60 s after startup.
		# Gives ARP sniffing and the first sweep time to re-confirm all devices.
		in_grace_period = (now - self._startup_time) < self._grace_period_secs()

		with self._known_lock:
			snapshot = dict(self._known)

		results      = {}   # mac → (online, new_last_seen, new_streak) — written by worker threads
		results_lock = threading.Lock()

		# Build MAC → device name lookup once; worker threads only read it (no lock needed)
		names_by_mac = {
			dev.states.get("MACNumber", "").lower(): dev.name
			for dev in indigo.devices.iter(PLUGIN_ID)
			if dev.states.get("MACNumber", "")
		}

		_CURL_USELESS_LIMIT = 5   # suspend TCP probe after this many consecutive all-port failures

		log_ping = self.decideMyLog("Ping")

		probe_source: dict = {}   # mac → "ping(ICMP)" or "tcp:<port>" — set by _do_probe, read by _check_one

		def _do_probe(ip, mac, entry, ping_only=False):
			"""Ping first; if blocked fall back to TCP socket probe (unless ping_only=True).
			Updates _known[mac]['curlPort']. Logs results if Log Ping is enabled.
			Sets probe_source[mac] to "ping(ICMP)" or "tcp:<port>" when the probe succeeds.
			"""
			dev_name = names_by_mac.get(mac, mac)
			ping_ok  = _ping(ip)
			if log_ping:
				self.indiLOG.log(10, f"ping  {dev_name} ({ip})  {'ok' if ping_ok else 'fail'}")
			if ping_ok:
				probe_source[mac] = "ping(ICMP)"
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
			if port is not None:
				probe_source[mac] = f"tcp:{port}"
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
			# A last_seen of 0 means the device was just discovered (e.g. loaded from
			# stale JSON with no scan timestamp).  Treat it as seen right now so the
			# very first probe cycle doesn't immediately flip the device offline.
			if last_seen == 0:
				last_seen = now
				with self._known_lock:
					self._known.setdefault(mac, {})["last_seen"] = now

			# ── Per-device settings ──────────────────────────────────────────
			ping_mode         = "none"
			offline_logic     = "and"    # "and" | "or"
			missed_needed     = 1        # consecutive failures required
			offline_threshold = plugin_offline_threshold
			ping_only         = False    # derived from ping_mode == "pingOnly"
			dev_id            = entry.get("indigo_device_id")
			if dev_id:
				try:
					idev = indigo.devices[dev_id]
					if not idev.enabled:
						return   # device disabled in Indigo — skip probe entirely
					props         = idev.pluginProps
					ping_mode     = props.get("pingMode",         "none")
					offline_logic = props.get("pingOfflineLogic", "and")
					missed_needed = max(1, int(props.get("pingMissedCount", kDefaultPluginPrefs.get("pingMissedCount", "1") )))
					dev_thresh    = int(props.get("offlineThreshold", kDefaultPluginPrefs.get("offlineThreshold", "180") ) )
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
					if log_ping:
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
				streak_met  = new_streak >= missed_needed  # enough consecutive failures?

				# "or"  — either condition alone triggers offline (faster detection)
				# "and" — both must be true (default, fewest false-positives on flaky wifi)
				if offline_logic == "or":
					offline_triggered = timed_out or  streak_met
				else:
					offline_triggered = timed_out and streak_met

				if ping_mode == "both":
					# both mode: ping drives online AND offline
					online        = not offline_triggered
					new_last_seen = last_seen
				else:
					# offline mode: ping can only push device offline, never bring it back online
					online        = (not offline_triggered) if offline_triggered else entry.get("online", True)
					new_last_seen = last_seen

			with results_lock:
				results[mac] = (online, new_last_seen, new_streak)

		# ── probe all known devices — bounded thread pool (max 20 concurrent) ──────
		# Using threads (not asyncio) because socket.connect() is blocking.
		probe_items = [
			(mac, entry) for mac, entry in snapshot.items()
			if not self._stop_event.is_set() and mac.lower() not in self._ignored_macs
		]
		with ThreadPoolExecutor(max_workers=20) as pool:
			futures = {pool.submit(_check_one, mac, entry): mac for mac, entry in probe_items}
			deadline = time.time() + 8
			for fut in as_completed(futures, timeout=max(0.1, deadline - time.time())):
				if self._stop_event.is_set():
					return
				try:
					fut.result()
				except Exception:
					pass

		if self._stop_event.is_set():
			return

		for mac, (online, new_last_seen, new_streak) in results.items():
			with self._known_lock:
				self._known[mac]["online"]           = online
				self._known[mac]["last_seen"]        = new_last_seen
				self._known[mac]["ping_fail_streak"] = new_streak
			ip  = snapshot[mac].get("ip", "")
			src = probe_source.get(mac, "") if online else "probe"
			self._update_indigo_device(mac, ip, online, source=src)

	# ------------------------------------------------------------------
	# Device registry
	# ------------------------------------------------------------------

	# ------------------------------------------------------------------
	# ------------------------------------------------------------------
	# Aggregate group devices  (HOME_AWAY / ONLINE)
	# ------------------------------------------------------------------

	def _recalc_group_device(self, dev):
		"""Recalculate and push the aggregate state for one HOME_AWAY or ONLINE device.

		HOME_AWAY (networkDevicesHomeAway) — watches up to 6 networkDevice entries.
		  onOffState = True  when at least one participant is home (online)
		  onOffState = False when ALL participants are away (offline)
		  ParticipantsHome = count currently online

		ONLINE (externalDevicesOffline) — watches up to 3 externalDevice entries.
		  onOffState = True  when at least one participant is online
		  onOffState = False when ALL participants are offline
		  ParticipantsOnline = count currently online

		Two separate updateStatesOnServer calls are used so that a missing count
		state (device created before Devices.xml added it) never blocks the
		critical onOffState / lastOnOffChange update.
		"""
		if not dev.enabled:
			return   # aggregate device disabled in Indigo — skip recalc

		typeId    = dev.deviceTypeId
		slots     = 6 if typeId == HOME_AWAY else 3
		count_key = "ParticipantsHome" if typeId == HOME_AWAY else "ParticipantsOnline"
		props     = dev.pluginProps

		participants = [
			props.get(f"watchDevice{i}", "").strip()
			for i in range(1, slots + 1)
		]
		participants = [p for p in participants if p and p not in ("", "0")]

		online_count   = 0
		participant_names = []
		for pid in participants:
			try:
				pdev = indigo.devices[int(pid)]
				participant_names.append(pdev.name)
				if bool(pdev.states.get("onOffState", False)):
					online_count += 1
			except Exception:
				participant_names.append(pid)   # fallback: show raw ID if device not found

		new_state  = online_count > 0   # True = at least one home/online
		prev_state = dev.states.get("onOffState", None)

		# ── Call 1: critical states (onOffState + lastOnOffChange) ──────────
		# These always exist — safe to batch together.
		if prev_state is None or bool(prev_state) != new_state:
			ts = _now_str()
			try:
				dev.updateStatesOnServer([
					{"key": "onOffState",      "value": new_state,
					 "uiValue": f"{'on' if new_state else 'off'}  {ts}"},
					{"key": "lastOnOffChange", "value": ts},
				])
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"Group device state update failed for {dev.name}: {e}")

		# ── Call 2: count + participants states ─────────────────────────────
		# Silently skipped if states are not yet registered (device hasn't
		# restarted since the plugin was last upgraded).
		participants_str = ",".join(participants)
		count_changed        = dev.states.get(count_key,     -1)  != online_count
		participants_changed = dev.states.get("participants", "") != participants_str
		if count_changed or participants_changed:
			updates2 = []
			if count_changed:
				updates2.append({"key": count_key,      "value": online_count})
			if participants_changed:
				updates2.append({"key": "participants", "value": participants_str})
			try:
				dev.updateStatesOnServer(updates2)
			except Exception:
				pass   # states not yet defined — will appear after next plugin restart

		# ── Address column for HOME_AWAY: "192.168.1. - 12 15 25" ─────────────
		# Built from the last octets of all participants' current IP addresses.
		# Updated whenever recalc runs; only writes pluginProps when the value changes.
		if typeId == HOME_AWAY and participants:
			try:
				ips = []
				for pid in participants:
					try:
						ip = indigo.devices[int(pid)].states.get("ipNumber", "")
						if ip and ip not in ("0.0.0.0", ""):
							ips.append(ip)
					except Exception:
						pass
				if ips:
					# Find longest common prefix ending with "."
					parts = [ip.rsplit(".", 1) for ip in ips]
					prefixes = [p[0] + "." for p in parts if len(p) == 2]
					prefix = prefixes[0] if len(set(prefixes)) == 1 else ""
					octets = " ".join(p[1] for p in parts if len(p) == 2)
					desired = f"{prefix} - {octets}" if prefix else octets
				else:
					desired = ""
				current_addr = props.get("address", "")
				if desired and desired != current_addr:
					new_props = dict(props)
					new_props["address"] = desired
					dev.replacePluginPropsOnServer(new_props)
			except Exception:
				pass

		# ── Notes (description) — written once only for HOME_AWAY devices.
		# ONLINE devices already have the watched hosts in the Address column,
		# so their Notes field is left entirely to the user.
		# For HOME_AWAY: only write when Notes is still blank so the user can
		# edit it freely afterwards.
		if typeId == HOME_AWAY and not dev.description.strip() and participants:
			try:
				labels = []
				for pid in participants:
					try:
						pdev = indigo.devices[int(pid)]
						labels.append(pdev.states.get("MACNumber", pid))
					except Exception:
						labels.append(pid)
				dev.description = ",".join(participants) + " - " + ",".join(labels)
				dev.replaceOnServer()
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"Could not update notes for {dev.name}: {e}")

	def _update_group_devices(self, changed_dev_id: int):
		"""Called after any participant device's onOffState changes.
		Finds every HOME_AWAY / ONLINE aggregate device that watches changed_dev_id
		and recalculates its state.
		"""
		changed_id_str = str(changed_dev_id)
		for dev in indigo.devices.iter(PLUGIN_ID):
			typeId = dev.deviceTypeId
			if typeId not in (HOME_AWAY, ONLINE):
				continue
			slots = 6 if typeId == HOME_AWAY else 3
			props = dev.pluginProps
			participants = [
				props.get(f"watchDevice{i}", "").strip()
				for i in range(1, slots + 1)
			]
			if changed_id_str not in participants:
				continue
			self._recalc_group_device(dev)

	# External device ping (user-configured hosts / DNS names)
	# ------------------------------------------------------------------

	def _check_external_devices(self):
		"""Ping (+ TCP fallback) all registered externalDevice entries and update their onOffState."""
		now = time.time()
		for dev_id, info in list(self._ext_devices.items()):
			if self._stop_event.is_set():
				break
			host = info.get("host", "").strip()
			if not host:
				continue
			try:
				dev = indigo.devices[dev_id]
			except Exception:
				continue

			# Honour per-device ping interval
			interval = int(dev.pluginProps.get("pingInterval", 60))
			if now - info.get("last_ping", 0) < interval:
				continue
			info["last_ping"] = now

			# Resolve hostname → IPv4 address (handles plain IPs transparently)
			try:
				results     = socket.getaddrinfo(host, None, socket.AF_INET)
				resolved_ip = results[0][4][0]
			except Exception:
				# DNS resolution failed — count as a ping failure
				self._ext_update_state(dev, info, host, resolved_ip="", alive=False, ms=None)
				continue

			# 1. ICMP ping (fast, works for LAN devices and some internet hosts)
			t0    = time.time()
			alive = _ping(resolved_ip, timeout=2.0)
			ms    = int((time.time() - t0) * 1000) if alive else None

			# 2. TCP fallback on 443 → 80 when ICMP is blocked (e.g. www.google.com)
			if not alive:
				t0 = time.time()
				for port in (443, 80):
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					try:
						s.settimeout(2.0)
						s.connect((resolved_ip, port))
						alive = True
					except ConnectionRefusedError:
						alive = True    # TCP RST → host is up, port just closed
					except Exception:
						pass
					finally:
						try: s.close()
						except Exception: pass
					if alive:
						ms = int((time.time() - t0) * 1000)
						break

			self._ext_update_state(dev, info, host, resolved_ip, alive, ms)

	# ------------------------------------------------------------------
	# Internet Address device  (public WAN IP monitor)
	# ------------------------------------------------------------------

	def _start_internet_address_device(self, dev):
		"""Start (or restart) the background polling thread for one internetAddress device."""
		# Cancel any existing thread for this device
		old_ev = self._pub_ip_stop.pop(dev.id, None)
		if old_ev:
			old_ev.set()
		if not dev.enabled:
			return
		stop_ev = threading.Event()
		self._pub_ip_stop[dev.id] = stop_ev
		threading.Thread(
			target=self._internet_address_loop,
			args=(dev.id, stop_ev),
			daemon=True,
			name=f"NS-PublicIP-{dev.id}",
		).start()

	def _internet_address_loop(self, dev_id: int, stop_ev: threading.Event):
		"""Background loop: fetch public IP, sleep, repeat until stop_ev is set."""
		# Fetch immediately on start
		self._update_internet_address_device(dev_id)
		while True:
			try:
				interval = int(indigo.devices[dev_id].pluginProps.get("checkInterval", "300"))
			except Exception:
				interval = 300
			if stop_ev.wait(timeout=interval):
				break   # stop_ev set — device stopped or plugin shutting down
			self._update_internet_address_device(dev_id)

	def _update_internet_address_device(self, dev_id: int):
		"""Fetch the public IP and push any changed values to the Indigo device."""
		try:
			dev = indigo.devices[dev_id]
		except Exception:
			return
		if not dev.enabled:
			return

		alive, ip = _fetch_public_ip()
		now        = _now_str()
		prev_ip    = dev.states.get("publicIp",  "")
		was_online = bool(dev.states.get("onOffState", None))

		state_updates = []

		# Always stamp the appropriate timestamp regardless of other changes
		if alive:
			state_updates.append({"key": "lastSuccessfulUpdate", "value": now})
		else:
			state_updates.append({"key": "lastFailedUpdate", "value": now})

		# online/offline flip
		if alive != was_online:
			state_updates.append({"key": "onOffState", "value": alive,
			                      "uiValue": "on" if alive else "off"})

		# IP changed (only meaningful when fetch succeeded)
		if alive and ip and ip != prev_ip:
			if prev_ip:
				state_updates.append({"key": "previousIp", "value": prev_ip})
			state_updates.append({"key": "publicIp",   "value": ip})
			state_updates.append({"key": "lastChanged", "value": now})
			self.indiLOG.log(20, f"Public IP changed: {prev_ip or '(none)'} → {ip}")
		elif alive and not prev_ip and ip:
			# First successful fetch — populate publicIp even if "changed" is vacuous
			state_updates.append({"key": "publicIp",   "value": ip})
			state_updates.append({"key": "lastChanged", "value": now})

		try:
			dev.updateStatesOnServer(state_updates)
			# Show current IP in the Notes (description) column for easy reading
			if alive and ip and ip != dev.description:
				dev.description = ip
				dev.replaceOnServer()
		except Exception as e:
			if "None" not in str(e):
				self.indiLOG.log(30, f"internetAddress update failed for {dev.name}: {e}")

	def addInternetAddressDevice(self, valuesDict=None, *args):
		"""Menu: create one Internet Address device (skips if one already exists)."""
		for dev in indigo.devices.iter(PLUGIN_ID):
			if dev.deviceTypeId == INTERNET_ADDRESS:
				self.indiLOG.log(20, f"Internet Address device already exists: '{dev.name}' — skipped.")
				return valuesDict
		folder_id = self._get_or_create_folder()
		props     = {"checkInterval": "300", "comment": ""}
		try:
			kwargs = {
				"deviceTypeId": INTERNET_ADDRESS,
				"name":         "Internet Address",
				"props":        props,
			}
			if folder_id:
				kwargs["folder"] = folder_id
			indigo.device.create(indigo.kProtocol.Plugin, **kwargs)
			self.indiLOG.log(20, "Internet Address device created.")
		except Exception as e:
			self.indiLOG.log(30, f"Could not create Internet Address device: {e}")
		return valuesDict

	# ------------------------------------------------------------------

	def _ext_update_state(self, dev, info: dict, host: str,
	                      resolved_ip: str, alive: bool, ms):
		"""Apply ping result to one externalDevice: update fail streak, flip state if needed."""
		missed_needed = int(dev.pluginProps.get("pingMissedCount", kDefaultPluginPrefs.get("pingMissedCount", "1")))
		if alive:
			info["fail_streak"] = 0
		else:
			info["fail_streak"] = info.get("fail_streak", 0) + 1

		prev_online = bool(dev.states.get("onOffState", False))
		if alive:
			new_online = True
		elif info["fail_streak"] >= missed_needed:
			new_online = False
		else:
			new_online = prev_online   # not enough consecutive failures yet

		updates = []
		if new_online != prev_online:
			ts     = _now_str()
			status = "ONLINE" if new_online else "OFFLINE"
			if self.decideMyLog("StateChange"):
				lvl = int(self.pluginPrefs.get("stateChangeLogLevel",
				          kDefaultPluginPrefs["stateChangeLogLevel"]) or
				          kDefaultPluginPrefs["stateChangeLogLevel"])
				self.indiLOG.log(lvl, f"{dev.name} ({host}) is now {status}")
			updates += [
				{"key": "onOffState",     "value": new_online,
				 "uiValue": f"{'on' if new_online else 'off'}  {_now_str()}"},
				{"key": "lastOnOffChange","value": _now_str()},
			]

		if resolved_ip and dev.states.get("ipNumber", "") != resolved_ip:
			updates.append({"key": "ipNumber", "value": resolved_ip})
			# Keep Notes column in sync (zero-padded last octet for sortable IP order)
			try:
				notes = _ip_for_notes(resolved_ip)
				if dev.description != notes:
					dev.description = notes
					dev.replaceOnServer()
			except Exception:
				pass

		ping_str = f"{ms} ms" if ms is not None else ("timeout" if not alive else "")
		if ping_str and dev.states.get("pingMs", "") != ping_str:
			updates.append({"key": "pingMs", "value": ping_str})

		if updates:
			try:
				dev.updateStatesOnServer(updates)
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"External device state update failed for {dev.name}: {e}")

		# ── Update aggregate ONLINE group devices ──────────────────────────
		if new_online != prev_online:
			self._update_group_devices(dev.id)

	# ------------------------------------------------------------------

	def _discover_device(self, mac: str, ip: str, local_name: str = "", clear_local_name: bool = False):
		"""Called for stale ARP-cache entries that did NOT respond to ping this sweep.

		Updates IP mapping and creates the Indigo device if needed, but intentionally
		does NOT update last_seen — that field must only change when the device is
		genuinely reachable.  For brand-new MACs we seed online=True because the
		ARP-cache entry proves the device was recently on the network; the normal
		offline-timeout logic will correct the state if it never responds to ping.
		local_name is the mDNS/Bonjour hostname from the arp -a output (empty if unknown).
		"""
		if mac.lower() in self._ignored_macs:
			return
		now = time.time()
		with self._known_lock:
			entry = self._known.get(mac, {})
			if not entry:                         # brand-new MAC — seed a minimal entry
				entry["online"]     = True         # detected = on by definition
				entry["last_seen"]  = now          # ARP cache proves recently on network
				entry["history"]    = []
				entry["local_name"] = ""
				entry["name"]       = ""
			entry.setdefault("history",      [])    # backfill for entries added before history existed
			entry.setdefault("ip_history",   [])    # backfill for entries added before ip_history existed
			entry.setdefault("local_name",   "")    # backfill for entries added before local_name existed
			entry.setdefault("name",         "")    # backfill for entries added before name existed
			entry.setdefault("curlPort",     None)  # last curl port that responded
			entry.setdefault("curlUseless",  0)     # consecutive all-port curl failures
			entry.setdefault("is_ap_or_router", False) # True when device does proxy-ARP for others
			entry["ip"] = ip
			if clear_local_name:                    # proxy-ARP AP: mark and wipe stale client name
				entry["is_ap_or_router"] = True
				entry["local_name"]   = ""
			elif local_name:                        # real name → always store
				entry["local_name"] = local_name
			if "vendor" not in entry:
				entry["vendor"] = self.get_vendor(mac)
			self._known[mac] = entry
		# Ensure an Indigo device exists.  Stale ARP-cache entries are NOT
		# ping-confirmed, so we must NOT flip the online state — only update
		# IP / vendor / local_name.  Pass update_online=False.
		self._ensure_indigo_device(mac, ip, entry.get("vendor", ""), entry.get("online", False),
		                           local_name=entry.get("local_name", ""),
		                           clear_local_name=clear_local_name,
		                           update_online=False)

	def _register_device(self, mac: str, ip: str, local_name: str = "", clear_local_name: bool = False, source: str = "sweep (arp)"):
		"""Add or update a MAC entry, then create or refresh the Indigo device.

		Called from the sniff thread (passive ARP) and from ping-confirmed sweep hits.
		local_name is the mDNS/Bonjour hostname parsed from arp -a output (empty string
		when the device has not announced a name, i.e. arp -a showed '?').
		Only the ARP sweep populates local_name; sniff-thread calls leave it empty.
		source: "sweep (arp)" (sweep replied), "traffic observed (tcpdump)" (passive packet capture).
		"""
		# Reject unroutable IPs — DHCP Discover/Request packets have src IP 0.0.0.0;
		# link-local 169.254.x.x addresses are not meaningful for LAN tracking.
		if not ip or ip == "0.0.0.0" or ip.startswith("169.254."):
			return
		if mac.lower() in self._ignored_macs:
			if self.decideMyLog("Ignored"):
				self.indiLOG.log(10, f"Ignored MAC skipped: {mac}")
			return

		now = time.time()
		with self._known_lock:
			entry      = self._known.get(mac, {})
			entry.setdefault("history",         [])    # ensure key present on every entry
			entry.setdefault("ip_history",      [])    # list of IP changes: [{ts, old_ip, new_ip}]
			entry.setdefault("ip_change_times", [])    # epoch list for AP/router auto-detection
			entry.setdefault("local_name",      "")    # ensure key present on every entry
			entry.setdefault("name",            "")    # ensure key present on every entry
			entry.setdefault("curlPort",        None)  # last curl port that responded
			entry.setdefault("curlUseless",     0)     # consecutive all-port curl failures
			entry.setdefault("last_indigo_push", 0)    # epoch of last _ensure_indigo_device call
			entry.setdefault("is_ap_or_router",  False) # True when device does proxy-ARP for others
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

			# ── AP/router IP suppression ─────────────────────────────────────
			# Once a device is flagged as an AP/router (proxy-ARP), its IP is
			# stable and known.  Ignore any IP change coming from the sniff
			# thread — sniff sees packets the AP forwards for many clients, so
			# the source IP varies with every proxied frame.  The ARP sweep
			# calls _register_device with local_name / clear_local_name set,
			# which is the only authoritative source for the AP's own IP.
			if changed_ip and old_ip and entry.get("is_ap_or_router") and not local_name and not clear_local_name:
				# sniff-sourced call for a known AP — keep the existing IP
				entry["last_seen"]     = now
				entry["last_seen_str"] = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
				entry["online"]        = True
				self._known[mac] = entry
				# skip _ensure_indigo_device entirely — nothing changed
				return

			newly_promoted = False
			if changed_ip and old_ip and old_ip != "0.0.0.0" and ip != "0.0.0.0":
				rec = {
					"ts":     datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
					"old_ip": old_ip,
					"new_ip": ip,
					"source": "scan",
				}
				entry["ip_history"].append(rec)
				if len(entry["ip_history"]) > 20:
					entry["ip_history"] = entry["ip_history"][-20:]

				# ── AP/router auto-detection (runs before throttle) ──────────
				# Count IP changes within a sliding window; if a device flips IPs
				# frequently it is almost certainly a proxy-ARP AP/router.
				# This must live here — the throttle below skips _ensure_indigo_device
				# on rapid changes, so any detection inside that function is blind.
				_IP_CHURN_COUNT  = 5
				_IP_CHURN_WINDOW = 900   # seconds
				if not entry.get("is_ap_or_router"):
					times = entry["ip_change_times"]
					times = [t for t in times if now - t < _IP_CHURN_WINDOW]
					times.append(now)
					entry["ip_change_times"] = times
					if len(times) >= _IP_CHURN_COUNT:
						entry["is_ap_or_router"] = True
						newly_promoted = True
						self.indiLOG.log(20,
							f"Auto-detected AP/router: {mac} — {len(times)} IP changes "
							f"in {_IP_CHURN_WINDOW} s, marking isApOrRouter=True")
			entry["ip"]             = ip
			entry["last_seen"]      = now
			entry["last_seen_str"]  = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
			entry["online"]         = True
			if clear_local_name:                  # proxy-ARP AP: mark and wipe stale client name
				entry["is_ap_or_router"] = True
				entry["local_name"]   = ""
			elif local_name:                      # real name → always store
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

		# Throttle Indigo IPC: if this is a pure IP-change update (device already known
		# and online state unchanged) and the last push was less than 30 s ago, skip to
		# avoid flooding the Indigo server when a device or AP cycles through many IPs.
		last_push       = entry.get("last_indigo_push", 0)
		push_too_recent = (now - last_push) < _THROTTLE_SECS
		# Skip the Indigo IPC call when the only change is a rapid IP rotation
		# (proxy-ARP AP cycling through client IPs) — avoids flooding the server.
		# Always push when: first time seen, online state changed, local_name updated,
		# or the device was just auto-promoted to AP/router (need to write the state).
		skip_push       = push_too_recent and changed_ip and not local_name and not newly_promoted
		if not skip_push:
			with self._known_lock:
				self._known.setdefault(mac, {})["last_indigo_push"] = now  # record push time
			self._ensure_indigo_device(mac, ip, entry["vendor"], True,
			                           local_name=entry.get("local_name", ""),
			                           clear_local_name=clear_local_name,
			                           source=source)

	def _ensure_indigo_device(self, mac: str, ip: str, vendor: str, online: bool, local_name: str = "", clear_local_name: bool = False, update_online: bool = True, source: str = ""):
		"""Create the Indigo device if it doesn't exist, then update its states.

		update_online=False: skip the onOffState update (used by _discover_device for
		stale ARP-cache entries that were NOT ping-confirmed — prevents ghost ON transitions).
		source: what set the device online ("sweep (arp)", "traffic observed (tcpdump)", "ping(ICMP)", "tcp:port"); stored in setOnBy state.
		"""
		dev_name = _mac_to_device_name(mac, vendor, local_name=local_name, prefixName = self._getPrefixName())

		# Fast path: look up cached device ID stored in _known by deviceStartComm.
		# Falls back to a full linear scan only on the first call for a new MAC.
		existing = None
		with self._known_lock:
			dev_id = self._known.get(mac, {}).get("indigo_device_id")
		if dev_id:
			try:
				existing = indigo.devices[dev_id]
			except Exception:
				existing = None   # device was deleted externally

		if existing is None:
			# Fallback: scan all plugin devices (covers new MACs and deleted/re-created devices)
			for dev in indigo.devices.iter(PLUGIN_ID):
				if dev.states.get("MACNumber", "").lower() == mac.lower():
					existing = dev
					# Cache the ID so subsequent calls are fast
					with self._known_lock:
						self._known.setdefault(mac, {})["indigo_device_id"] = dev.id
					break

		if existing is None and self.pluginPrefs.get("autoCreateDevices", kDefaultPluginPrefs["autoCreateDevices"]):
			existing = self._create_indigo_device(mac, ip, vendor, dev_name)

		if existing is not None:
			if not existing.enabled:
				return   # device disabled in Indigo — leave all states untouched
			with self._known_lock:
				is_ap = bool(self._known.get(mac, {}).get("is_ap_or_router", False))
			self._update_indigo_device_states(existing, mac, ip, vendor, online, local_name=local_name,
			                                  clear_local_name=clear_local_name, is_ap_or_router=is_ap,
			                                  update_online=update_online, source=source)

	def _create_indigo_device(self, mac: str, ip: str, vendor: str, name: str):
		"""Create a brand-new Indigo networkDevice."""
		props = {
			"address":          mac,    # shows in Indigo device list Address column
			"pingMode":         "confirm",
			"offlineThreshold": "0",    # 0 = use plugin-wide default
		}
		folder_id = self._get_or_create_folder()
		try:
			# Resolve any name collision — another device may already have this name.
			_create_name = name
			_suffix      = 0
			while _create_name in [d.name for d in indigo.devices]:
				_suffix     += 1
				_create_name = f"{name} ({_suffix})"
			new_dev = indigo.device.create(
				protocol     = indigo.kProtocol.Plugin,
				name         = _create_name,
				description  = _ip_for_notes(ip),   # Notes = IP (last octet padded)
				pluginId     = PLUGIN_ID,
				deviceTypeId = DEVICE_TYPE_ID,
				props        = props,
				folder       = folder_id,
			)
			new_dev.updateStateOnServer("created", value=_now_str())
			# Always log new device creation — important event regardless of debug settings.
			# Re-attempt vendor lookup in case the table finished loading since first seen.
			vendor_str = vendor if (vendor and vendor != "Unknown") else self.get_vendor(mac)
			self.indiLOG.log(20,
				f"New device: '{name}'"
				f"  MAC={mac}"
				f"  IP={ip}"
				f"  vendor={vendor_str}"
			)
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
			# Update / create the networkScanner_newdevice variable
			_var_name  = "networkScanner_newdevice"
			_var_value = f"{new_dev.id}  {_now_str()}"
			try:
				indigo.variable.updateValue(indigo.variables[_var_name].id, value=_var_value)
			except KeyError:
				try:
					_var_folder_id = self._get_or_create_variable_folder()
					_create_kwargs = {"value": _var_value}
					if _var_folder_id:
						_create_kwargs["folder"] = _var_folder_id
					indigo.variable.create(_var_name, **_create_kwargs)
				except Exception as ve:
					if f"{ve}".find("None") == -1:
						self.indiLOG.log(30, f"Could not create variable {_var_name}: {ve}")
			except Exception as ve:
				if f"{ve}".find("None") == -1:
					self.indiLOG.log(30, f"Could not update variable {_var_name}: {ve}")

			return new_dev
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"Failed to create device for {mac}: {e}", exc_info=True)
			return None

	def _update_indigo_device_states(self, dev, mac: str, ip: str, vendor: str, online: bool, local_name: str = "", clear_local_name: bool = False, is_ap_or_router: bool = False, update_online: bool = True, source: str = ""):
		"""Push only changed state values into an existing Indigo device.

		lastOnOffChange is only written when the online/offline value flips.
		last_seen (last ARP/ping ok epoch) lives only in _known — never pushed
		to Indigo, so routine scan hits produce zero device updates.
		localName is the mDNS/Bonjour hostname from arp -a; only updated when non-empty
		so a previously discovered name is never erased by a sniff-thread update.
		clear_local_name=True overrides that guard and explicitly blanks a stale name
		(used when a proxy-ARP AP's winner entry has no hostname of its own).
		"""
		prev_online     = dev.states.get("onOffState",   None)
		prev_ip         = dev.states.get("ipNumber",    "")
		prev_mac        = dev.states.get("MACNumber",   "")
		prev_vendor     = dev.states.get("hardwareVendor",   "")
		prev_created    = dev.states.get("created",      "")
		prev_local_name = dev.states.get("localName",    "")
		prev_is_ap      = bool(dev.states.get("isApOrRouter", False))

		online_changed     = update_online and ((prev_online is None) or (bool(prev_online) != online))
		ip_changed         = prev_ip     != ip
		mac_changed        = prev_mac    != mac
		vendor_changed     = prev_vendor != vendor
		created_needed     = not prev_created
		# Update localName when we have a real name, OR when explicitly clearing a stale one
		local_name_changed = (bool(local_name) and local_name != prev_local_name) \
		                     or (clear_local_name and bool(prev_local_name))

		# AP/router auto-detection is done in _register_device (before the throttle).
		# Here we just pick up whatever is_ap_or_router was passed in / already stored.
		ap_changed         = is_ap_or_router != prev_is_ap

		# lastOnMessage: throttled to once per minute while device is online.
		# Must be evaluated BEFORE the early-return guard so a "nothing else changed"
		# cycle doesn't silently skip the update.
		_now_epoch         = time.time()
		last_on_msg_due    = (dev.deviceTypeId == DEVICE_TYPE_ID and online
		                      and (_now_epoch - self._last_on_msg_ts.get(dev.id, 0) >= 60))

		if not any([online_changed, ip_changed, mac_changed, vendor_changed, created_needed,
		            local_name_changed, ap_changed, last_on_msg_due]):
			return   # nothing to update — no Indigo server calls

		if online_changed and self.decideMyLog("StateChange"):
			status = "ONLINE" if online else "OFFLINE"
			lvl    = int(self.pluginPrefs.get("stateChangeLogLevel", kDefaultPluginPrefs["stateChangeLogLevel"]) or kDefaultPluginPrefs["stateChangeLogLevel"])
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
			if online and source:
				state_updates.append({"key": "setOnBy",  "value": source})
			if not online and source:
				state_updates.append({"key": "setOffBy", "value": source})
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
			state_updates.append({"key": "ipNumber",   "value": ip})
		if mac_changed:
			state_updates.append({"key": "MACNumber",  "value": mac})
		if vendor_changed:
			state_updates.append({"key": "hardwareVendor",  "value": vendor})
		if created_needed:
			state_updates.append({"key": "created",     "value": _now_str()})
		if local_name_changed:
			state_updates.append({"key": "localName",   "value": local_name if local_name else ""})
		if ap_changed:
			state_updates.append({"key": "isApOrRouter", "value": is_ap_or_router})

		# ── lastOnMessage + setOnBy: update when online, throttled to once per minute ──
		# last_on_msg_due was computed before the early-return guard (above) so this
		# block is only reached when the throttle window has actually elapsed.
		if last_on_msg_due:
			self._last_on_msg_ts[dev.id] = _now_epoch
			ts_short = time.strftime("%Y-%m-%d %H:%M", time.localtime(_now_epoch))
			state_updates.append({"key": "lastOnMessage", "value": ts_short})
			if source:
				state_updates.append({"key": "setOnBy", "value": source})

		try:
			dev.updateStatesOnServer(state_updates)

			# Sync props only when relevant values changed
			props_changed = False
			new_props = dict(dev.pluginProps)
			if new_props.get("address")   != mac:
				new_props["address"]   = mac;  props_changed = True
			if new_props.get("ipNumber") != ip:
				new_props["ipNumber"] = ip;   props_changed = True
			if props_changed:
				dev.replacePluginPropsOnServer(new_props)

			# Notes (description) — keep zero-padded IP for sortable column
			if ip_changed:
				padded_ip = _ip_for_notes(ip)
				if dev.description != padded_ip:
					dev.description = padded_ip
					try:
						dev.replaceOnServer()
					except Exception as _re:
						if f"{_re}".find("None") == -1:
							self.indiLOG.log(30, f"replaceOnServer failed for {dev.name}: {_re}")

		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"State update failed for {dev.name}: {e}", exc_info=True)

		# ── Update aggregate HOME_AWAY group devices ──────────────────────
		if online_changed and prev_online is not None:
			self._update_group_devices(dev.id)


	def _update_indigo_device(self, mac: str, ip: str, online: bool, source: str = ""):
		"""Update an existing device's states from the scan loop thread."""
		with self._known_lock:
			entry  = self._known.get(mac, {})
			dev_id = entry.get("indigo_device_id")
		dev = None
		if dev_id:
			try:
				dev = indigo.devices[dev_id]
			except Exception:
				dev = None
		if dev is None:
			# Fallback linear scan (e.g. cache not yet populated)
			for d in indigo.devices.iter(PLUGIN_ID):
				if d.states.get("MACNumber", "").lower() == mac.lower():
					dev = d
					break
		if dev is not None:
			vendor     = entry.get("vendor",     "Unknown")
			local_name = entry.get("local_name", "")
			self._update_indigo_device_states(dev, mac, ip, vendor, online, local_name=local_name, source=source)

	# ------------------------------------------------------------------
	# Folder helpers
	# ------------------------------------------------------------------

	def _rename_and_move_net_devices(self):
		"""Startup pass — renaming disabled: device names are set once at creation and never changed."""
		pass

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
			mac = dev.states.get("MACNumber", "").lower()
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

	@staticmethod
	def isValidIP(ip0):
		ipx = ip0.split(".")
		if len(ipx) != 4:							return False
		for ip in ipx:
			try:
				if int(ip) < 0 or int(ip) > 255:	return False
			except:									return False
		return True

	def _unique_device_name(self, desired: str, exclude_id: int = 0) -> str:
		"""Return *desired* if no other device uses it, otherwise append *(1)*, *(2)* … until unique."""
		taken = {d.name for d in indigo.devices if d.id != exclude_id}
		if desired not in taken:
			return desired
		suffix = 1
		while f"{desired} ({suffix})" in taken:
			suffix += 1
		return f"{desired} ({suffix})"

	def _ensure_plugin_variables(self):
		"""Create any plugin-managed Indigo variables that don't exist yet.

		Called at startup so variables are always present in the variable list
		even before the first new device is discovered.
		Current variables:
		  networkScanner_newdevice  — last auto-created device id + timestamp
		"""
		_var_names = ["networkScanner_newdevice", "networkScanner_pingDevice"]
		_folder_id = self._get_or_create_variable_folder()
		for _var_name in _var_names:
			if _var_name in indigo.variables:
				continue   # already exists — leave value untouched
			try:
				_create_kwargs = {"value": ""}
				if _folder_id:
					_create_kwargs["folder"] = _folder_id
				indigo.variable.create(_var_name, **_create_kwargs)
			except Exception as ve:
				if f"{ve}".find("None") == -1:
					self.indiLOG.log(30, f"Could not create variable {_var_name}: {ve}")

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

	def _get_or_create_variable_folder(self):
		"""Return the Indigo variable folder ID configured in 'variableFolder'.

		Creates the folder if it doesn't exist yet.  Returns 0 (root) when the
		setting is blank or the folder cannot be created.
		"""
		folder_name = self.pluginPrefs.get("variableFolder", "").strip()
		if not folder_name:
			return 0
		for folder in indigo.variables.folders:
			if folder.name == folder_name:
				return folder.id
		try:
			return indigo.variables.folder.create(folder_name).id
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
					entry.setdefault("history",         [])
					entry.setdefault("ip_history",      [])
					entry.setdefault("local_name",      "")
					entry.setdefault("name",            "")
					entry.setdefault("curlPort",        None)
					entry.setdefault("curlUseless",     0)
					entry.setdefault("last_indigo_push",  0)
					entry.setdefault("is_ap_or_router",  False)
					entry.setdefault("ip_change_times",  [])
					# Remove any ip_history entries involving 0.0.0.0, then cap at 20
					entry["ip_history"] = [
						r for r in entry["ip_history"]
						if r.get("old_ip") != "0.0.0.0" and r.get("new_ip") != "0.0.0.0"
					][-20:]
				self.indiLOG.log(20, f"Loaded {len(self._known)} known devices from state file.")
			except Exception as e:
				self.indiLOG.log(30, f"Could not load state file: {e}")

		# Sync indigo_device_id and name from live Indigo devices — covers the case
		# where devices were renamed or recreated while the plugin was stopped.
		changed = False
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac = dev.states.get("MACNumber", "").lower()
			if not mac:
				continue
			with self._known_lock:
				entry = self._known.setdefault(mac, {})
				if entry.get("indigo_device_id") != dev.id:
					entry["indigo_device_id"] = dev.id
					changed = True
				if entry.get("name") != dev.name:
					entry["name"] = dev.name
					changed = True
		if changed:
			self._save_state()

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

	def compareFingscanToNetworkScannerDevices(self, valuesDict=None, *args):
		"""Compare Fingscan and NetworkScanner devices by MAC and report differences."""

		# ── Build O(1) lookup dicts  ──────────────────────────────────────────
		fing = {}   # mac → fingscan dev
		for dev in indigo.devices.iter("com.karlwachs.fingscan"):
			if dev.deviceTypeId != "IP-Device":
				continue
			mac = dev.states.get("MACNumber", "").lower()
			if mac:
				fing[mac] = dev

		net = {}    # mac → networkscanner dev
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			if dev.deviceTypeId != "networkDevice":
				continue
			mac = dev.states.get("MACNumber", "").lower()
			if mac:
				net[mac] = dev

		# ── Single pass over the union of all MACs ──────────────────────────────
		fing_only = []   # in Fingscan only
		net_only  = []   # in NetworkScanner only
		conflicts = []   # in both, but ON/OFF state disagrees
		matched   = 0    # in both, state agrees

		for mac in sorted(set(fing) | set(net)):
			f = fing.get(mac)
			n = net.get(mac)

			if f and not n:
				on_f = f.states.get("status", "") == "up"
				ip   = f.states.get("ipNumber", "?")
				fing_only.append(
					f"  {mac}  IP:{ip:<15}  {'ON ' if on_f else 'off'}  {f.name}"
				)

			elif n and not f:
				on_n   = bool(n.states.get("onOffState", False))
				ip     = n.states.get("ipNumber", "?")
				vendor = n.states.get("hardwareVendor", "")
				net_only.append(
					f"  {mac}  IP:{ip:<15}  {'ON ' if on_n else 'off'}  {n.name}"
					+ (f"  ({vendor})" if vendor else "")
				)

			else:   # present in both
				on_f = f.states.get("status", "") == "up"
				on_n = bool(n.states.get("onOffState", False))
				if on_f != on_n:
					ip = n.states.get("ipNumber", f.states.get("ipNumber", "?"))
					conflicts.append(
						f"  {mac}  IP:{ip:<15}  "
						f"fing:{'ON ' if on_f else 'off'}  net:{'ON ' if on_n else 'off'}"
						f"\n    fing-name: {f.name}"
						f"\n    net-name:  {n.name}"
					)
				else:
					matched += 1

		# ── Format sections ────────────────────────────────────────────────────
		SEP = "=" * 72

		def section(title, lines):
			body = "\n".join(lines) if lines else "  (none)"
			return f"\n\n{SEP}\n{title}  ({len(lines)})\n{body}"

		report = (
			f"\n\n{SEP}"
			f"\nFingscan ↔ NetworkScanner comparison"
			f"\n  Fingscan: {len(fing)} devices    NetworkScanner: {len(net)} devices"
			f"\n  Matched: {matched + len(conflicts)}    Conflicts: {len(conflicts)}"
			+ section("Fingscan devices with NO match in NetworkScanner", fing_only)
			+ section("NetworkScanner devices with NO match in Fingscan",  net_only)
			+ section("Devices in BOTH with conflicting ON/OFF state",     conflicts)
			+ f"\n\n{SEP}\n  Matched + state agrees: {matched} device(s)\n{SEP}\n"
		)

		self.indiLOG.log(20, report)
		summary = (
			f"Fingscan:{len(fing)}  Net:{len(net)}  "
			f"fing-only:{len(fing_only)}  net-only:{len(net_only)}  conflicts:{len(conflicts)}"
		)
		valuesDict["MSG"] = summary
		return valuesDict

	def importNamesFromFingscan(self, valuesDict=None,  *args):
		"""read device names from fingscan, store them in fingscan info and use when a matching mac number is found. write to dev state: fingscanDeviceName"""
		self.indiLOG.log(20, f"Importing fingscan dev names…")
		count = 0
		_fingScanDevices = {}
		for dev in indigo.devices.iter("com.karlwachs.fingscan"):
			if dev.deviceTypeId != "IP-Device": continue
			if "MACNumber" not in dev.states: continue
			MACNumber = dev.states["MACNumber"].lower()
			_fingScanDevices[MACNumber] = dev.name
			
		out = ["\n"]
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			for MACNumber in _fingScanDevices:
				if dev.states["MACNumber"].lower() == MACNumber:
					count += 1 
					dev.updateStateOnServer("fingscanDeviceInfo", value = _fingScanDevices[MACNumber])
					out.append(f"{MACNumber}: {_fingScanDevices[MACNumber]}")
					break

		out = '\n'.join(out)
		self.indiLOG.log(20, f" ... found {count} MAC matches: {out}")
		valuesDict["MSG"] = f"found {count} matching mac numbers"

		return valuesDict


	def overwriteDevNamesWithFingNames(self, valuesDict=None, *args):
		"""use the above imported names to overwrite the device names like: oldFingname-Net"""
		self.indiLOG.log(20, f"overwriting dev names with fingscan dev names… to old fingscan name-net ... ")
		countN = 0
		# not used countP = 0
	
		#  not used _fingToMyPingMode = {"doNotUsePing":"none", "usePingifUP":"offline", "usePingifDown":"online", "usePingifUPdown":"both", "useOnlyPing":"pingOnly"}
		out = ["\n"]
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			if dev.states["fingscanDeviceInfo"] != "":
				oldName = dev.states["fingscanDeviceInfo"]
				newName =  f"{oldName}-{self._getPrefixName()}".strip("_").strip("-")
				if dev.name != newName:
					safe_name = self._unique_device_name(newName, exclude_id=dev.id)
					out.append(f"{dev.name:40} --> {safe_name}")
					countN += 1
					dev.name = safe_name
					dev.replaceOnServer()

		out = '\n'.join(out)
		self.indiLOG.log(20, f" ... found {countN} name overwrites: {out}")
		valuesDict["MSG"] = f"{countN} name overwrites"

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
			m = dev.states.get("MACNumber", "").lower()
			if m:
				dev_by_mac[m] = dev

		sep = "─" * 110
		lines = ["\n",sep, "All Discovered Network Devices", sep,"\n"]

		for mac, entry in sorted(snapshot.items()):
			ip        = entry.get("ip",     "")
			vendor    = entry.get("vendor", "Unknown")
			online    = entry.get("online", False)
			last_seen = entry.get("last_seen", 0)
			ts        = datetime.datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d %H:%M:%S") if last_seen else "never"
			local_name = entry.get("local_name", "")
			streak     = entry.get("ping_fail_streak", 0)

			lines.append(f"  MAC       : {mac}")
			lines.append(f"  IP        : {ip or '—'}")
			lines.append(f"  LocalName : {local_name or '—'}")
			lines.append(f"  Vendor    : {vendor}")
			is_ap = entry.get("is_ap_or_router", False)
			lines.append(f"  Online    : {'Yes' if online else 'No'}   Last seen: {ts}   Ping-fail streak: {streak}   AP/bridge: {'Yes' if is_ap else 'No'}")

			dev = dev_by_mac.get(mac)
			if dev:
				# --- Indigo device states ---
				states = dev.states
				lines.append(f"  Indigo    : {dev.name}  (id={dev.id})")
				lines.append(f"    onOffState      : {'on' if states.get('onOffState') else 'off'}")
				lines.append(f"    lastOnOffChange : {states.get('lastOnOffChange', '') or '—'}")
				lines.append(f"    created         : {states.get('created',         '') or '—'}")
				lines.append(f"    ipNumber       : {states.get('ipNumber',        '') or '—'}")
				lines.append(f"    MACNumber      : {states.get('MACNumber',       '') or '—'}")
				lines.append(f"    hardwareVendor      : {states.get('hardwareVendor',       '') or '—'}")
				lines.append(f"    localName       : {states.get('localName',        '') or '—'}")
				lines.append(f"    openPorts       : {states.get('openPorts',        '') or '—'}")
				lines.append(f"    comment         : {states.get('comment',          '') or '—'}")
				lines.append(f"    fingscanInfo    : {states.get('fingscanDeviceInfo','') or '—'}")
				lines.append(f"    isApOrRouter      : {bool(states.get('isApOrRouter', False))}")

				# --- per-device plugin properties ---
				props          = dev.pluginProps
				ping_mode      = props.get("pingMode",         "none")
				offline_logic  = props.get("pingOfflineLogic", "and")
				missed_needed  = props.get("pingMissedCount",  kDefaultPluginPrefs.get("pingMissedCount", "1"))
				offline_thresh = props.get("offlineThreshold", "0")
				suppress_ip    = bool(props.get("suppressIpChangeLog", False))
				log_seen       = bool(props.get("logSeenToFile",       False))
				global_thresh  = int(self.pluginPrefs.get("offlineThreshold", kDefaultPluginPrefs["offlineThreshold"]))
				eff_thresh     = int(offline_thresh) if offline_thresh and int(offline_thresh) > 0 else global_thresh
				lines.append(f"    pingMode        : {ping_mode}")
				lines.append(f"    offlineLogic    : {offline_logic}")
				lines.append(f"    missedPings     : {missed_needed}   streak now: {streak}")
				lines.append(f"    offlineThreshold: {offline_thresh or '0'}  (effective: {eff_thresh}s)")
				lines.append(f"    suppressIpLog   : {suppress_ip}")
				lines.append(f"    logSeenToFile   : {log_seen}")
			else:
				lines.append(f"  Indigo    : no Indigo device")

			# --- on/off history ---
			history = entry.get("history", [])
			if history:
				lines.append(f"  History   : (newest first)")
				for h in reversed(history):
					lines.append(f"    {h.get('ts','?')}  →  {h.get('state','?')}")
			else:
				fallback = ""
				if dev:
					state_str   = "on" if dev.states.get("onOffState", False) else "off"
					last_change = dev.states.get("lastOnOffChange", "")
					fallback    = f"{state_str}  {last_change}" if last_change else state_str
				lines.append(f"  History   : {('(from device state)  ' + fallback) if fallback else 'none recorded yet'}")

			# --- IP change history ---
			ip_history = entry.get("ip_history", [])
			if ip_history:
				lines.append(f"  IP changes: (oldest → newest)")
				for ih in ip_history:
					src = ih.get("source", "scan")
					lines.append(f"    {ih.get('ts','?')}  {ih.get('old_ip','?')} → {ih.get('new_ip','?')}  [{src}]")
			else:
				lines.append(f"  IP changes: none recorded")

			lines.append(sep)

		self.indiLOG.log(20, "\n" + "\n".join(lines))


	def printIpChangedDevices(self, valuesDict=None, *args):
		"""Print only devices that have at least one recorded IP-address change."""
		with self._known_lock:
			snapshot = dict(self._known)

		changed = {mac: e for mac, e in snapshot.items() if e.get("ip_history")}
		sep   = "─" * 110
		lines = [sep]
		if not changed:
			lines.append("No devices have changed IP address since the plugin started.")
			lines.append(sep)
			self.indiLOG.log(20, "\n" + "\n".join(lines))
			return

		lines.append(f"Devices with IP address changes  ({len(changed)} device(s))")
		lines.append(sep)

		dev_by_mac = {}
		for dev in indigo.devices.iter(PLUGIN_ID):
			m = dev.states.get("MACNumber", "").lower()
			if m:
				dev_by_mac[m] = dev

		for mac, entry in sorted(changed.items()):
			ip        = entry.get("ip", "—")
			vendor    = entry.get("vendor", "Unknown")
			dev       = dev_by_mac.get(mac)
			dev_label = dev.name if dev else "no Indigo device"
			lines.append(f"  {mac}  current IP: {ip}  |  {vendor}  |  {dev_label}")
			for ih in entry["ip_history"]:
				src = ih.get("source", "scan")
				lines.append(f"    {ih.get('ts','?')}  {ih.get('old_ip','?')} → {ih.get('new_ip','?')}  [{src}]")
			lines.append(sep)

		self.indiLOG.log(20, "\n" + "\n".join(lines))

	def addDefaultExternalDevices(self, valuesDict, *args):
		"""Button callback (PluginConfig): create checked externalDevice entries.

		Each checkbox key extDev_<key> maps to (device-name, host).
		Only checked entries that don't already exist (by host) are created.
		Devices are placed in the same Device Folder as Net_* devices.
		"""
		_ALL = {
			"extDev_google":    ("Ping-google",    "www.google.com"),
			"extDev_yahoo":     ("Ping-yahoo",      "www.yahoo.com"),
			"extDev_microsoft": ("Ping-microsoft",  "www.microsoft.com"),
			"extDev_cnn":       ("Ping-cnn",        "www.cnn.com"),
			"extDev_att":       ("Ping-att",        "www.att.com"),
			"extDev_siemens":   ("Ping-siemens",    "www.siemens.com"),
		}

		# Determine which providers the user checked
		selected = [
			(dev_name, host)
			for key, (dev_name, host) in _ALL.items()
			if valuesDict.get(key, False)
		]

		# Add custom host if provided
		custom_host = valuesDict.get("customHost", "").strip().lower()
		if custom_host:
			label = custom_host[4:] if custom_host.startswith("www.") else custom_host
			custom_name = f"Ping-{label}"
			selected.append((custom_name, custom_host))

		if not selected:
			valuesDict["extDevMsg"] = "Nothing selected — check at least one provider above or enter a custom host."
			return valuesDict

		# Build a set of hosts already registered so we never create duplicates
		existing_hosts = {
			dev.pluginProps.get("host", "").lower()
			for dev in indigo.devices.iter(PLUGIN_ID)
			if dev.deviceTypeId == EXT_DEVICE_TYPE_ID
		}

		# Resolve the Device Folder (same folder used for Net_* devices)
		folder_id = self._get_or_create_folder()

		created = []
		skipped = []
		for dev_name, host in selected:
			if host.lower() in existing_hosts:
				skipped.append(dev_name)
				continue
			try:
				props = {
					"host":            host,
					"pingInterval":    "60",
					"pingMissedCount": kDefaultPluginPrefs.get("pingMissedCount", "1"),
					"address":         host,
				}
				kw = dict(
					protocol     = indigo.kProtocol.Plugin,
					name         = dev_name,
					pluginId     = PLUGIN_ID,
					deviceTypeId = EXT_DEVICE_TYPE_ID,
					props        = props,
				)
				if folder_id:
					kw["folder"] = folder_id
				new_dev = indigo.device.create(**kw)
				new_dev.updateStatesOnServer([{"key": "host", "value": host}])
				created.append(dev_name)
				self.indiLOG.log(20, f"Created external device '{dev_name}' ({host})")
			except Exception as e:
				self.indiLOG.log(30, f"Could not create external device '{dev_name}': {e}")

		parts = []
		if created: parts.append(f"Created: {', '.join(created)}")
		if skipped: parts.append(f"Already exist: {', '.join(skipped)}")
		msg = "  ".join(parts) if parts else "Nothing to do."

		# ── Auto-create "NetworkScanner Internet" aggregate device ────────────
		# Collect up to 3 external devices (newly created + pre-existing) and
		# wire them into an externalDevicesOffline aggregate device so the user
		# gets an instant internet up/down indicator without any extra steps.
		_INTERNET_DEV_NAME = "Ping-NetworkScanner Internet"
		internet_dev_exists = any(
			d.name == _INTERNET_DEV_NAME
			for d in indigo.devices.iter(PLUGIN_ID)
			if d.deviceTypeId == ONLINE
		)
		if not internet_dev_exists:
			all_ext = sorted(
				[d for d in indigo.devices.iter(PLUGIN_ID) if d.deviceTypeId == EXT_DEVICE_TYPE_ID],
				key=lambda d: d.name.lower(),
			)[:3]
			if len(all_ext) >= 1:
				agg_props = {f"watchDevice{i+1}": str(d.id) for i, d in enumerate(all_ext)}
				# Address column: watched hostnames without "www." prefix and TLD, joined by " · "
				# e.g. "www.google.com" → "google",  "www.welt.de" → "welt"
				def _short(h):
					h = h.lower()
					if h.startswith("www."):
						h = h[4:]
					# strip last .xxx TLD if present
					dot = h.rfind(".")
					if dot > 0:
						h = h[:dot]
					return h
				agg_props["address"] = " · ".join(
					_short(d.pluginProps.get("host", d.name)) for d in all_ext
				)
				try:
					kw = dict(
						protocol     = indigo.kProtocol.Plugin,
						name         = _INTERNET_DEV_NAME,
						pluginId     = PLUGIN_ID,
						deviceTypeId = ONLINE,
						props        = agg_props,
					)
					if folder_id:
						kw["folder"] = folder_id
					indigo.device.create(**kw)
					msg += f"  |  Created '{_INTERNET_DEV_NAME}' watching {len(all_ext)} device(s)."
					self.indiLOG.log(20, f"Created aggregate device '{_INTERNET_DEV_NAME}' "
					                     f"watching: {', '.join(d.name for d in all_ext)}")
				except Exception as e:
					self.indiLOG.log(30, f"Could not create '{_INTERNET_DEV_NAME}': {e}")

		valuesDict["extDevMsg"] = msg

		# ── Ping every selected host in the background and log results ────────
		# Give Indigo a moment to finish registering the newly created devices
		# before we try to push state updates onto them.
		hosts_to_ping = [host for _, host in selected]
		if hosts_to_ping:
			def _ping_all(hosts):
				time.sleep(2.0)   # wait for deviceStartComm to complete on new devices
				for h in hosts:
					try:
						alive, ip, detail, ms = self._ping_custom_host(h)
						status = "ONLINE" if alive else "OFFLINE"
						ip_str = f"  ({ip})" if ip and ip != h else ""
						self.indiLOG.log(20, f"Ping {h}{ip_str}  →  {status}  [{detail}]  {ms} ms")
						label = h if (h and h != ip) else ip
						self._update_ping_device_variable(alive, ip=label, ms=ms)
						# Push result directly onto the matching External Device
						h_lower = h.lower()
						for dev_id, info in list(self._ext_devices.items()):
							if info.get("host", "").lower() == h_lower:
								try:
									dev = indigo.devices[dev_id]
									self._ext_update_state(dev, info, h, ip, alive,
									                       ms if ms else None)
								except Exception:
									pass
								break
					except Exception as e:
						self.indiLOG.log(30, f"Ping {h} error: {e}")
			import threading
			threading.Thread(target=_ping_all, args=(hosts_to_ping,), daemon=True).start()

		return valuesDict

	def turnOffAllDeviceLogging(self, valuesDict, *args):
		"""Button callback (PluginConfig debug section): set logSeenToFile=False on every managed device."""
		disabled = 0
		for dev in indigo.devices.iter(PLUGIN_ID):
			try:
				if dev.pluginProps.get("logSeenToFile", False):
					props = dict(dev.pluginProps)
					props["logSeenToFile"] = False
					dev.replacePluginPropsOnServer(props)
					disabled += 1
			except Exception as e:
				self.indiLOG.log(30, f"Could not clear logSeenToFile on {dev.name}: {e}")
		msg = f"Turned off per-device logging on {disabled} device(s)." if disabled else "No devices had per-device logging enabled."
		self.indiLOG.log(20, msg)
		valuesDict["deviceLogMsg"] = msg
		return valuesDict

	# ------------------------------------------------------------------
	# Ping custom host  (menu item + action)
	# ------------------------------------------------------------------

	def _ping_custom_host(self, host: str) -> tuple[bool, str, str, int]:
		"""Resolve host → IP, ICMP ping, TCP fallback.  Returns (alive, ip, detail, ms)."""
		host = host.strip()
		if not host:
			return False, "", "no host specified", 0
		# Resolve DNS → IP
		try:
			ip = socket.gethostbyname(host)
		except socket.gaierror as e:
			return False, "", f"DNS resolution failed: {e}", 0
		# ICMP ping
		t0    = time.time()
		alive = _ping(ip, timeout=5.0)
		ms    = int((time.time() - t0) * 1000)
		detail = "ICMP ok"
		if not alive:
			# TCP fallback
			t0   = time.time()
			port = _curl_check(ip, timeout=5.0)
			ms   = int((time.time() - t0) * 1000)
			if port is not None:
				alive  = True
				detail = f"TCP port {port} ok"
			else:
				detail = "no reply"
		return alive, ip, detail, ms

	def _update_ping_device_variable(self, alive: bool, ip: str = "", ms: int = 0):
		"""Write '<ip> <ms>ms on/off' to the networkScanner_pingDevice variable."""
		state = "on" if alive else "off"
		parts = []
		if ip:  parts.append(ip)
		if ms:  parts.append(f"{ms}ms")
		parts.append(state)
		value = " ".join(parts)
		var_name = "networkScanner_pingDevice"
		try:
			if var_name in indigo.variables:
				indigo.variable.updateValue(indigo.variables[var_name].id, value=value)
			else:
				folder_id = self._get_or_create_variable_folder()
				kwargs = {"value": value}
				if folder_id:
					kwargs["folder"] = folder_id
				indigo.variable.create(var_name, **kwargs)
		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Could not update variable {var_name}: {e}")

	def pingCustomHostButton(self, valuesDict, typeId="", devId=0):
		"""Button callback inside the 'Ping a Device' menu dialog."""
		host  = valuesDict.get("host", "").strip()
		alive, ip, detail, ms = self._ping_custom_host(host)
		status = "ONLINE" if alive else "OFFLINE"
		ip_str = f"  ({ip})" if ip and ip != host else ""
		msg    = f"Ping {host}{ip_str}  →  {status}  [{detail}]  {ms} ms"
		self.indiLOG.log(20, msg)
		label = host if (host and host != ip) else ip
		self._update_ping_device_variable(alive, ip=label, ms=ms)
		valuesDict["result"] = msg
		return valuesDict

	def pingCustomHostAction(self, action):
		"""Action callback: ping the configured host and update the variable."""
		return self.pingCustomHostButton(action.props)

	def forceRescan(self):
		"""Trigger an immediate ARP sweep + ping check."""
		iface = self.pluginPrefs.get("networkInterface", kDefaultPluginPrefs["networkInterface"]).strip() or kDefaultPluginPrefs["networkInterface"]
		self.indiLOG.log(20, "Forcing immediate network rescan…")
		t = threading.Thread(
			target=self._scan_loop_once,
			args=(iface, self.pluginPrefs.get("arpSweepEnabled", kDefaultPluginPrefs["arpSweepEnabled"])),
			daemon=True,
		)
		t.start()

	def _scan_loop_once(self, iface: str, sweep_enabled: bool):
		if sweep_enabled:
			self._arp_sweep(iface)
		self._check_all_devices(iface)
		self._check_external_devices()
		self._save_state()
		self.indiLOG.log(20, "Forced rescan complete.")


	def printInstableDevices(self, valuesDict=None, *args):
		"""Menu: print devices that have frequent on off to enable better settings fr ping and threshold"""
		cutoff = float(valuesDict.get("cutoff", "60"))


		with self._known_lock:
			snapshot = dict(self._known)
			
		if not snapshot:
			self.indiLOG.log(20, "\nNo devices discovered yet.")
			return valuesDict

		lines   = []
		opposit = {"on": "off", "off": "on"}

		for mac in snapshot:
			history = snapshot[mac]["history"]
			if len(history) < 4: continue

			dt      = {"on": list(), "off": list()}
			maxSec  = {"on": 0.,    "off": 0.}
			counter = {"on": 0,     "off": 0}

			for event in history:
				if dt["on"] == list() and event["state"] != "on": continue
				if event["state"] == "on": dt["on"].append([event["ts"], "", 0])
				else: dt["on"][-1][1] = event["ts"]

			for event in history:
				if dt["off"] == list() and event["state"] != "off": continue
				if event["state"] == "off": dt["off"].append([event["ts"], "", 0])
				else: dt["off"][-1][1] = event["ts"]

			for onoff in dt:
				for event in dt[onoff]:
					if event[1] == "": continue
					deltaSecs = _date_diff_in_Seconds(event[0], event[1])
					if deltaSecs > cutoff: continue
					maxSec[onoff]  = max(maxSec[onoff], deltaSecs)
					counter[onoff] += 1
				if counter[onoff] < 3: continue
				try:
					dev      = indigo.devices[snapshot[mac]["indigo_device_id"]]
					pingMode = dev.pluginProps["pingMode"]
				except: pingMode = "       "
				lines.append(
					f"{snapshot[mac]['name'][:30]:30}  transition:{onoff} → {opposit[onoff]};"
					f"  max time:{maxSec[onoff]:3} secs; number of events:{counter[onoff]:2};"
					f" pingMode used:{pingMode};"
					f" suggestion: increase  \"Offline Threshold\" to {int(maxSec[onoff]*1.7)//60:3} minutes"
				)

		if lines:
			self.indiLOG.log(20, "\n" + "\n".join(lines))
		else:
			self.indiLOG.log(20, "\nNo unstable devices found within the selected cutoff.")

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
			m = dev.states.get("MACNumber", "").lower()
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
		"""Menu: read README.md and print it to plugin.log as plain text."""
		import re as _re
		readme = self._readme_path
		try:
			with open(readme, encoding="utf-8") as _f:
				raw = _f.read()
			lines   = []
			in_code = False
			for line in raw.splitlines():
				# toggle fenced code blocks — keep content, strip the fence markers
				if line.startswith("```"):
					in_code = not in_code
					if in_code:
						lines.append("")   # blank line before code
					continue
				if in_code:
					lines.append("  " + line)  # indent code lines
					continue
				# strip Markdown heading markers  (## Foo → FOO  /  # Bar → BAR)
				m = _re.match(r"^(#{1,6})\s+(.*)", line)
				if m:
					depth = len(m.group(1))
					text  = m.group(2).strip()
					if depth == 1:
						lines.append("=" * 72)
						lines.append(text.upper())
						lines.append("=" * 72)
					elif depth == 2:
						lines.append("")
						lines.append("── " + text + " " + "─" * max(0, 68 - len(text)))
					else:
						lines.append("")
						lines.append(text)
					continue
				# strip horizontal rules
				if _re.match(r"^---+$", line.strip()):
					continue
				# strip inline code backticks, bold/italic markers
				line = _re.sub(r"`([^`]+)`", r"\1", line)
				line = _re.sub(r"\*\*([^*]+)\*\*", r"\1", line)
				line = _re.sub(r"\*([^*]+)\*",   r"\1", line)
				# convert Markdown table rows  | a | b | c |  →  a  b  c
				if line.startswith("|"):
					cells = [c.strip() for c in line.strip("|").split("|")]
					# skip separator rows  |---|---|
					if all(_re.match(r"^[-: ]+$", c) for c in cells if c):
						continue
					line = "  " + "   ".join(c for c in cells if c)
				lines.append(line)
			# Print one log entry per section so Indigo never truncates a large block
			section = []
			for ln in lines:
				if ln.startswith("──") and section:
					self.indiLOG.log(20, "\n".join(section))
					section = [ln]
				else:
					section.append(ln)
			if section:
				self.indiLOG.log(20, "\n".join(section))
			self.indiLOG.log(20, f"For a properly formatted version open:\n{readme}")
		except Exception as e:
			self.indiLOG.log(30, f"Could not read README.md: {e}")

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
			# Resolve the live device — dev_id may be stale if the device was deleted
			# and recreated (e.g. by the ARP scanner) while the port scan was running.
			dev = None
			try:
				dev = indigo.devices[dev_id]
			except Exception:
				pass
			if dev is None:
				# Fall back: find the current device for this IP via _known
				with self._known_lock:
					for entry in self._known.values():
						if entry.get("ip") == ip:
							current_id = entry.get("indigo_device_id")
							if current_id and current_id != dev_id:
								try:
									dev = indigo.devices[current_id]
								except Exception:
									pass
							break
			if dev is None:
				return   # device was deleted and not recreated yet — nothing to update

			mac        = dev.states.get("MACNumber", "")
			vendor     = dev.states.get("hardwareVendor", "")
			local_name = self._known.get(mac.lower(), {}).get("local_name", "") if mac else ""
			# Update openPorts state
			dev.updateStateOnServer("openPorts", value=port_str)
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
			mac    = dev.states.get("MACNumber", "").lower()
			ip     = dev.states.get("ipNumber",  "")
			vendor = dev.states.get("hardwareVendor", "Unknown")
			if not mac or mac in pending: continue
			items.append((mac, f"{_ip_for_notes(ip)}   {mac}   {vendor}"))
		items.sort(key=lambda x: x[1])
		return items

	def getIgnoredDeviceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""List of currently ignored devices — shown in bottom panel."""
		pending = self._dialog_ignored(valuesDict)
		items   = []
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac    = dev.states.get("MACNumber", "").lower()
			ip     = dev.states.get("ipNumber",  "")
			vendor = dev.states.get("hardwareVendor", "Unknown")
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
		mac   = dev.states.get("MACNumber", "")
		ip    = dev.states.get("ipNumber",  "")
		iface = self.pluginPrefs.get("networkInterface", kDefaultPluginPrefs["networkInterface"]).strip() or kDefaultPluginPrefs["networkInterface"]

		if not ip:
			self.indiLOG.log(20, f"No IP known for {dev.name}; cannot ping.")
			return

		online = _arp_ping(ip, iface)
		vendor = self._known.get(mac, {}).get("vendor", dev.states.get("hardwareVendor", "Unknown"))

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
			mac = dev.states.get("MACNumber", "")
			ip  = dev.states.get("ipNumber",  "")
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
			# Sync _known so known_devices.json stays consistent with Indigo state.
			mac = dev.states.get("MACNumber", "").lower()
			if mac:
				_state_to_known = {
					"ipNumber":    "ip",
					"localName":    "local_name",
					"hardwareVendor":   "vendor",
					"isApOrRouter": "is_ap_or_router",
				}
				known_key = _state_to_known.get(state_name)
				if known_key:
					with self._known_lock:
						self._known.setdefault(mac, {})[known_key] = new_value
					self._save_state()
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
		mac    = dev.states.get("MACNumber", "")
		vendor = dev.states.get("hardwareVendor", "")
		if vendor and vendor != "Unknown":
			safe_vendor = re.sub(r"[^A-Za-z0-9_\- ]", "", vendor)[:20].strip()
			new_name    = f"{safe_vendor}_{mac.replace(':','').upper()[-6:]}"
			try:
				safe_name = self._unique_device_name(new_name, exclude_id=dev.id)
				dev.name  = safe_name
				dev.replaceOnServer()
				self.indiLOG.log(20, f"Renamed device to '{safe_name}'")
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
