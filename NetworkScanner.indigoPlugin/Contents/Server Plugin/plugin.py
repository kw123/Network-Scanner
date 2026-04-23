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
import shutil
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
# Timing / probe constants
# ---------------------------------------------------------------------------
_STARTUP_WAIT_SECS      =  4     # seconds to wait before first sweep/sniff after startup
_PROBE_POOL_DEADLINE    =  8     # seconds — ThreadPoolExecutor hard deadline for one probe cycle
_CURL_USELESS_LIMIT     =  5     # suspend TCP fallback after this many consecutive all-port failures
_SWEEP_FRESHNESS_MARGIN = 10     # skip probe if device was seen within (sweep_interval - N) seconds

# pingOnly adaptive timing
_PING_ONLY_INTERVAL_ONLINE  = 60   # seconds between probes when device is online
_PING_ONLY_INTERVAL_OFFLINE = 15   # seconds between probes when device is offline (faster recovery)
# For pingOnly devices: TCP is tried alongside ICMP to guard against router ICMP proxy.
# Once TCP has confirmed a device online at least once (ping_only_tcp_confirmed=True in
# _known), a TCP failure on a subsequent probe is treated as "likely router proxy" and
# the probe is marked failed.  If TCP has never worked (IoT device with no open ports),
# ping_only_tcp_fail_streak increments; once it reaches this limit we stop wasting time
# on TCP and trust ICMP alone for that device.
_PING_ONLY_TCP_SKIP_THRESHOLD = 8  # consecutive TCP failures before assuming IoT (ICMP-only)

# pingOnly quick-retry on failure (OR logic only)
_PING_RETRY_COUNT    = 2   # additional ICMP pings after first failure
_PING_RETRY_INTERVAL = 3   # seconds between retries  (total extra wait = count × interval)

# Auto-promote a device to pingOnly when it has been offline-but-responds-to-ping
# for this many seconds without any passive (ARP / tcpdump) confirmation
_PING_AUTO_PROMOTE_SECS = 120   # 2 minutes

# How long to wait before creating a synthetic-MAC device for a ping-only IP
# that has no ARP entry — gives tcpdump / ARP time to find the real MAC first.
# Must be long enough to span several scan cycles and a full tcpdump/DHCP cycle.
_PING_ONLY_NEW_DEVICE_DELAY   = 300   # seconds (5 minutes)
# Minimum number of consecutive sweeps an IP must be seen without ARP before a
# synthetic MAC is created — prevents ARP timing glitches from creating devices.
_PING_ONLY_MIN_SWEEPS         = 5

# ARP timeout — adaptive: starts at MIN, doubles on timeout, capped at MAX (seconds)
_ARP_TIMEOUT_MIN = 15
_ARP_TIMEOUT_MAX = 40

# Rate-limit for synthetic MAC device creation — at most one new device per interval
_SYNTHETIC_MAC_CREATE_INTERVAL = 10   # seconds

# ── Debug / emulation ────────────────────────────────────────────────────────
# Set to True to bypass the /sbin/ping verification and force ping_ran=True /
# ping_ok=True for ALL ping-only candidates.  Lets you test synthetic device
# creation without needing a real unreachable host.  MUST be False in production.
_DEBUG_FORCE_PING_OK = False

# Set to True to log every step of the ping-only / synthetic-device pipeline:
# verification ping result, double-check outcome, ARP re-check, etc.
# MUST be False in production.
_DEBUG_PING_ONLY_1 = False
_DEBUG_PING_ONLY_2 = False
_DEBUG_PING_ONLY_3 = False
_DEBUG_PING_ONLY_4 = False

_DEBUG_PASSIVE = False
# Link-local address prefix bytes (169.254.x.x / RFC 3927 APIPA)
_LINK_LOCAL_BYTE1 = 0xA9   # 169
_LINK_LOCAL_BYTE2 = 0xFE   # 254


#  before this time  expires no device will be set to off 
_startupGracePeriod = 45

# ---------------------------------------------------------------------------
# Plugin config defaults
# Indigo ignores defaultValue= in PluginConfig.xml for prefs already saved,
# so we apply these ourselves in __init__ for any key that is missing.
# ---------------------------------------------------------------------------
kDefaultPluginPrefs = {
	"networkInterface":		"",   # blank = auto-detect (prefers Ethernet over Wi-Fi)
	"scanInterval":			"60",
	"arpSweepEnabled":		True,
	"sniffEnabled":			True,
	"mdnsQueryEnabled":		True,
	"offlineThreshold":		"180",
	"autoCreateDevices":		True,
	"syntheticDevicesEnabled":	False,
	"flipAddressNotes":		False,  # swap Address (MAC) and Notes (IP) columns for Network Devices
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
	"debugIpChange":		True,
	"debugSeen":			False,
	"debugSweep":			False,
	"debugIgnored":			False,
	"debugPing":			False,
	"debugTcpdumpArp":		False,   # log every ARP reply captured by tcpdump (before throttle)
	"debugArpSweepEntries":	False,   # log every entry parsed from  arp -a  during sweep
	"debugTrackedDevice":	"",      # MAC or IP to trace in full detail (leave blank to disable)
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



_IP_RECVTTL = getattr(socket, 'IP_RECVTTL', 24)   # 24 on macOS, 12 on Linux

def _ping_extended(ip: str, timeout: float = 1.0) -> tuple:
	"""Like _ping() but also returns RTT (ms) and TTL from the ICMP reply.

	Returns (ok: bool, ms: float|None, ttl: int|None).

	Uses IP_RECVTTL + socket.recvmsg() to read TTL without root.
	Falls back to plain recv() (ms only, no TTL) if recvmsg is unavailable.
	TTL fingerprint: 128 → Windows, 64 → Linux/macOS/iOS, 255 → router/network gear.
	"""
	icmp_id  = os.getpid() & 0xFFFF
	header   = struct.pack('!BBHHH', 8, 0, 0, icmp_id, 1)
	payload  = b'NS'
	checksum = _icmp_checksum(header + payload)
	packet   = struct.pack('!BBHHH', 8, 0, checksum, icmp_id, 1) + payload
	s = None
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
		s.settimeout(timeout)
		try:
			s.setsockopt(socket.IPPROTO_IP, _IP_RECVTTL, 1)
			use_recvmsg = callable(getattr(s, 'recvmsg', None))
		except OSError:
			use_recvmsg = False
		t0 = time.monotonic()
		s.sendto(packet, (ip, 0))
		if use_recvmsg:
			_data, ancdata, _flags, _addr = s.recvmsg(1024, socket.CMSG_SPACE(1))
			ms  = round((time.monotonic() - t0) * 1000, 1)
			ttl = None
			for cmsg_level, cmsg_type, cmsg_data in ancdata:
				if cmsg_level == socket.IPPROTO_IP and cmsg_type == _IP_RECVTTL:
					ttl = cmsg_data[0] if cmsg_data else None
					break
		else:
			s.recv(1024)
			ms  = round((time.monotonic() - t0) * 1000, 1)
			ttl = None
		return (True, ms, ttl)
	except Exception:
		return (False, None, None)
	finally:
		if s:
			try: s.close()
			except: pass


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


def _active_ifaces() -> list:
	"""Return a list of (name, ip, type) for every active non-loopback interface.

	Parses  ifconfig -a  output.  Each interface block is examined for:
	  • UP flag and a usable IPv4 address (not 127.x or 169.254.x)
	  • type derived from the  media:  line:
	      Ethernet  — media line contains a physical speed (1000baseT, 100baseTX, Gbps …)
	      Wi-Fi     — interface contains no speed info (autoselect only)
	      Other     — everything else (USB adapters without speed info, VPN, etc.)
	Virtual / tunnel interfaces (utun, gif, stf, awdl, llw, p2p …) are skipped.
	Returns list sorted Ethernet first, then Wi-Fi, then Other.
	"""
	_SKIP = re.compile(r'^(lo|utun|gif|stf|awdl|llw|bridge|p2p|ptp|ipsec|anpi|ap)\d*$')
	_SPEED = re.compile(r'media:.*?(?:baseT|Gbps|baseTX|full-duplex|half-duplex)', re.I)
	result: list = []
	try:
		out = subprocess.check_output(["/sbin/ifconfig", "-a"],
		                              text=True, stderr=subprocess.DEVNULL, timeout=5)
		for block in re.split(r'\n(?=[a-z])', out):
			m = re.match(r'^(\w+):', block)
			if not m:
				continue
			name = m.group(1)
			if _SKIP.match(name):
				continue
			if "UP" not in block:
				continue
			inet_m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)', block)
			if not inet_m:
				continue
			ip = inet_m.group(1)
			if ip.startswith(("127.", "169.254.")):
				continue
			kind = "Ethernet" if _SPEED.search(block) else "Wi-Fi"
			result.append((name, ip, kind))
	except Exception:
		pass
	# Sort: Ethernet first, then Wi-Fi, then Other
	_order = {"Ethernet": 0, "Wi-Fi": 1}
	result.sort(key=lambda t: _order.get(t[2], 2))
	return result


def _auto_detect_iface() -> str:
	"""Return the best active interface: first Ethernet, then Wi-Fi, then 'en0'."""
	ifaces = _active_ifaces()
	return ifaces[0][0] if ifaces else "en0"


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

def _send_mdns_query(iface: str = "") -> None:
	"""Send a single mDNS PTR query for _services._dns-sd._udp.local to 224.0.0.251:5353.

	This prompts every mDNS-capable device on the subnet to announce itself,
	including devices hidden behind proxy-ARP APs whose MAC never appears in the
	ARP cache.  The responses arrive as normal UDP packets on port 5353 and are
	picked up automatically by the existing tcpdump sniff thread — no extra
	parsing needed.

	One tiny UDP packet (~50 bytes) is sent; the responses are small DNS answers.
	Total extra traffic per sweep cycle is negligible.
	"""
	MDNS_ADDR = "224.0.0.251"
	MDNS_PORT = 5353

	# DNS message header: ID=0, QR=Query, QDCOUNT=1, all other counts=0
	header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)

	# QNAME: _services._dns-sd._udp.local  (label-encoded)
	qname = (b'\x09_services'
	         b'\x07_dns-sd'
	         b'\x04_udp'
	         b'\x05local'
	         b'\x00')

	# QTYPE=PTR(12), QCLASS=IN(1) with QU bit set (0x8001) for mDNS unicast-preferred
	footer = struct.pack("!HH", 12, 0x8001)

	packet = header + qname + footer

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		if iface:
			# Bind to the correct outgoing interface by its IP
			subnet_info = _local_subnet(iface)
			if subnet_info:
				local_ip = socket.inet_ntoa(struct.pack("!I",
				    struct.unpack("!I", socket.inet_aton(subnet_info[0]))[0]))
				s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
				             socket.inet_aton(local_ip))
		s.sendto(packet, (MDNS_ADDR, MDNS_PORT))
	except Exception:
		pass
	finally:
		try:
			s.close()
		except Exception:
			pass


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

	###----------------------------------------------------------###
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

		# Device property/state cache — avoids repeated indigo.devices[dev_id] IPC calls
		# in hot loops (_offline_watchdog every 15 s, _check_one every scan interval,
		# _recalc_group_device on every state change).
		# Schema: dev_id → {"states": dict, "pluginProps": dict, "enabled": bool,
		#                    "name": str, "description": str}
		# Written by _cache_put; patched by _cache_patch_states / _cache_patch_props /
		# _cache_set_description; invalidated by _cache_drop.
		self._dev_cache: dict       = {}
		self._dev_cache_lock        = threading.Lock()

		self._triggers: dict = {}   # unused; kept so existing pickled state doesn't break

		self._sniff_thread     = None
		self._dhcp_thread      = None
		self._mdns_thread      = None
		self._scan_thread      = None
		self._sniff_thread2    = None   # second interface — only created when networkInterface2 is set
		self._dhcp_thread2     = None
		self._sweep_thread2    = None
		self._stop_event       = threading.Event()
		self._sniff_proc       = None   # tcpdump Popen — killed immediately on stop
		self._sniff_proc2      = None   # tcpdump Popen for second interface
		self._dhcp_proc        = None   # DHCP tcpdump Popen (primary)
		self._dhcp_proc2       = None   # DHCP tcpdump Popen (secondary)
		self._startup_time     = time.time()   # overwritten in startup(); guards offline grace
		self.in_grace_period   = True          # True until runConcurrentThread clears it

		# Track the last-saved flipAddressNotes value so closedPrefsConfigUi can detect
		# a change even though Indigo updates self.pluginPrefs before that callback fires.
		_raw_flip = self.pluginPrefs.get("flipAddressNotes", False)
		self._flip_address_notes_prev: bool = (_raw_flip is True) or (str(_raw_flip).lower() == "true")

		# IPs that responded to ping but had no ARP entry: ip → first_detected_time.
		# Device creation is delayed by _PING_ONLY_NEW_DEVICE_DELAY seconds to give
		# tcpdump / ARP sweep a chance to find the real MAC first.
		self._ping_only_pending:          dict  = {}
		self._last_synthetic_created_at:  float = 0.0   # rate-limit: max 1 synthetic MAC per _SYNTHETIC_MAC_CREATE_INTERVAL
		self._sbin_ping_missing_logged:   bool  = False  # log missing ping only once per session
		# Offline requests queued by background threads (e.g. ghost removal) for
		# the main Indigo thread (runConcurrentThread) to process via IPC.
		# Each entry: (dev_id, mac, ip, source)
		self._pending_offline_requests:   list  = []
		self._pending_offline_lock:       object = threading.Lock()

		# HOME_AWAY off-delay: dev_id → timestamp when all participants first went offline.
		# Cleared immediately if any participant comes back.  Key absent = not pending.
		self._home_away_pending_off: dict = {}

		# Resolved executable paths — set to canonical defaults here; _check_executables()
		# overwrites with the shutil.which()-discovered path at startup if it differs.
		self._exe_ping    = "/sbin/ping"
		self._exe_arp     = "/usr/sbin/arp"
		self._exe_tcpdump = "/usr/sbin/tcpdump"
		self._exe_dns_sd  = "/usr/bin/dns-sd"

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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _trace_targets(self) -> list:
		"""Return the list of normalised (lowercase) MACs/IPs currently being traced.
		The pluginPref stores a comma-separated string; empty entries are ignored.
		"""
		raw = self.pluginPrefs.get("debugTrackedDevice", "").strip()
		if not raw:
			return []
		return [t.strip().lower() for t in raw.split(",") if t.strip()]

	###----------------------------------------------------------###
	def _trace_log(self, mac: str, ip: str, context: str, msg: str) -> None:
		"""Log a verbose trace entry when mac or ip matches any entry in debugTrackedDevice.

		Set 'Track Specific Device' in the plugin config debug section to one or more
		comma-separated MAC addresses (aa:bb:cc:dd:ee:ff) or IP addresses (192.168.1.5).
		Every event touching a matching device is printed to plugin.log at DEBUG level.
		Leave blank to disable — very verbose when active.
		"""
		targets = self._trace_targets()
		if not targets:
			return
		mac_norm = mac.lower()
		ip_norm  = ip.lower() if ip else ""
		for target in targets:
			if target == mac_norm or (ip_norm and target == ip_norm):
				self.indiLOG.log(10, f"[TRACE {target}] {context}: {msg}")
				break   # one log line per call is enough even if mac and ip both match

	# ------------------------------------------------------------------
	# Lifecycle
	# ------------------------------------------------------------------

	# ------------------------------------------------------------------
	# Offline watchdog
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
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
			if self.in_grace_period:
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
					# Use cache — avoids an IPC round-trip for every online device every 15 s
					if not self._cache_enabled(dev_id):
						continue   # device disabled in Indigo — skip offline check
					dev_thresh = int(self._cache_props(dev_id).get("offlineThreshold", 0) or 0)
					if dev_thresh > 0:
						threshold = dev_thresh

				if now - last_seen > threshold:
					with self._known_lock:
						self._known[mac]["online"] = False
						# Reset the probe timer so the very next _check_all_devices
						# call fires a recovery ping immediately, rather than waiting
						# for the online-interval timer (ping_only_next_probe = now+60)
						# that was set during the last successful online probe.
						self._known[mac]["ping_only_next_probe"] = 0
					self._update_indigo_device(mac, entry.get("ip", ""), False,
					                           source="timeout")


	# ------------------------------------------------------------------
	# Device property/state cache
	# ------------------------------------------------------------------
	# Indigo IPC (indigo.devices[dev_id]) is expensive: every call crosses a
	# process boundary.  The cache stores a lightweight snapshot so hot loops
	# (_offline_watchdog, _check_one, _recalc_group_device, sniff thread) can
	# read props/states/enabled without an IPC round-trip.
	# The cache is populated at startup, refreshed on deviceStartComm /
	# deviceStopComm / closedDeviceConfigUi, and patched in-place after every
	# updateStatesOnServer / replacePluginPropsOnServer / replaceOnServer call.

	###----------------------------------------------------------###
	def _cache_put(self, dev) -> None:
		"""Snapshot a live Indigo device object into the cache."""
		with self._dev_cache_lock:
			self._dev_cache[dev.id] = {
				"states":       dict(dev.states),
				"pluginProps":  dict(dev.pluginProps),
				"enabled":      dev.enabled,
				"name":         dev.name,
				"description":  dev.description,
				"deviceTypeId": dev.deviceTypeId,
			}

	###----------------------------------------------------------###
	def _cache_drop(self, dev_id: int) -> None:
		"""Remove a device from the cache (called on deviceStopComm)."""
		with self._dev_cache_lock:
			self._dev_cache.pop(dev_id, None)

	###----------------------------------------------------------###
	def _cache_props(self, dev_id: int) -> dict:
		"""Return cached pluginProps for dev_id, or {} if not cached."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["pluginProps"] if entry else {}

	###----------------------------------------------------------###
	def _cache_states(self, dev_id: int) -> dict:
		"""Return cached states for dev_id, or {} if not cached."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["states"] if entry else {}

	###----------------------------------------------------------###
	def _cache_enabled(self, dev_id: int) -> bool:
		"""Return cached enabled flag for dev_id.  Defaults to True (safe: unknown = process it)."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["enabled"] if entry is not None else True

	###----------------------------------------------------------###
	def _cache_name(self, dev_id: int) -> str:
		"""Return cached device name, or empty string if not cached."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["name"] if entry else ""

	###----------------------------------------------------------###
	def _cache_patch_states(self, dev_id: int, updates) -> None:
		"""Apply a list of state-update dicts (or a single dict) to cached states."""
		if not updates:
			return
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
			if entry:
				if isinstance(updates, dict):
					updates = [updates]
				for u in updates:
					key = u.get("key")
					if key:
						entry["states"][key] = u["value"]

	###----------------------------------------------------------###
	def _cache_patch_props(self, dev_id: int, new_props: dict) -> None:
		"""Replace cached pluginProps with new_props."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
			if entry:
				entry["pluginProps"] = dict(new_props)

	###----------------------------------------------------------###
	def _cache_set_description(self, dev_id: int, desc: str) -> None:
		"""Update cached description (Notes column)."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
			if entry:
				entry["description"] = desc

	###----------------------------------------------------------###
	def _cache_description(self, dev_id: int) -> str:
		"""Return cached description (Notes column), or empty string if not cached."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["description"] if entry else ""

	###----------------------------------------------------------###
	def _cache_type(self, dev_id: int) -> str:
		"""Return cached deviceTypeId, or empty string if not cached."""
		with self._dev_cache_lock:
			entry = self._dev_cache.get(dev_id)
		return entry["deviceTypeId"] if entry else ""

	###----------------------------------------------------------###
	# Binaries used via subprocess.  Each entry is (bare_name, canonical_path).
	# _check_executables() calls shutil.which(bare_name) at startup; if it
	# finds the binary at a *different* path than canonical_path it logs an
	# INFO note so the hardcoded call-sites can be updated if needed.
	# (name, canonical_path) — all are required; missing one logs a level-40 warning
	_REQUIRED_EXECUTABLES = [
		("ping",    "/sbin/ping"),
		("arp",     "/usr/sbin/arp"),
		("tcpdump", "/usr/sbin/tcpdump"),
		("dns-sd",  "/usr/bin/dns-sd"),
	]

	# Map bare name → instance-variable attribute name
	_EXE_ATTR = {
		"ping":    "_exe_ping",
		"arp":     "_exe_arp",
		"tcpdump": "_exe_tcpdump",
		"dns-sd":  "_exe_dns_sd",
	}

	# Search path for shutil.which() — Indigo daemon has a minimal PATH that
	# omits /sbin and /usr/sbin, so we supply an expanded list explicitly.
	_EXE_SEARCH_PATH = os.pathsep.join([
		"/sbin", "/usr/sbin", "/bin", "/usr/bin",
		"/usr/local/bin", "/usr/local/sbin",
		"/opt/homebrew/bin", "/opt/homebrew/sbin",
	])

	def _check_executables(self):
		"""Locate each required binary and store its real path for subprocess calls.

		Strategy: try the canonical path directly first (fast, works in daemon context).
		If not there, fall back to shutil.which() with an expanded search path covering
		standard macOS dirs plus Homebrew prefixes.
		"""
		for name, canonical in self._REQUIRED_EXECUTABLES:
			attr = self._EXE_ATTR.get(name)

			# 1. Try canonical path directly
			if os.path.isfile(canonical) and os.access(canonical, os.X_OK):
				found = canonical
			else:
				# 2. Search expanded PATH (covers Homebrew and non-standard installs)
				found = shutil.which(name, path=self._EXE_SEARCH_PATH)

			if found is None:
				self.indiLOG.log(40,
					f"Executable '{name}' not found — some plugin features will not work  (looked in: {canonical}, then {self._EXE_SEARCH_PATH})"
				)
				# keep canonical default in self._exe_* so the call fails with a
				# clear FileNotFoundError rather than a cryptic AttributeError
			else:
				if attr:
					setattr(self, attr, found)   # use real path in all subprocess calls
				note = "  (requires sudo for BPF capture — configure password in plugin prefs)" if name == "tcpdump" else ""
				if found != canonical:
					self.indiLOG.log(20,
						f"Executable '{name}' found at {found}  (canonical was {canonical}) — using found path{note}"
					)
				else:
					self.indiLOG.log(10, f"Executable '{name}' OK at {found}{note}")

	def startup(self):
		self.indiLOG.log(20, f"Network Scanner starting up…  (offline ignore period: {_startupGracePeriod} s)")
		self._check_executables()
		self._startup_time = time.time()
		self._stop_event.clear()
		# Always clear per-device tracking on startup — it is a temporary diagnostic tool
		# and should never silently stay on across plugin restarts.
		if self.pluginPrefs.get("debugTrackedDevice", ""):
			self.indiLOG.log(20, "[TRACK] Device tracking cleared on restart.")
			self.pluginPrefs["debugTrackedDevice"] = ""
		self._ensure_plugin_variables()
		# Pre-populate device cache so hot loops have cached props/states immediately.
		# Also initialise ping_only_last_ping_ok for pingOnly devices so the offline
		# threshold starts fresh from startup rather than from a stale JSON timestamp.
		_startup_now = time.time()
		for _dev in indigo.devices.iter(PLUGIN_ID):
			self._cache_put(_dev)
			if _dev.deviceTypeId != DEVICE_TYPE_ID:
				continue
			if _dev.pluginProps.get("pingMode") != "pingOnly":
				continue
			_mac = _dev.states.get("MACNumber", "").lower()
			if not _mac:
				continue
			with self._known_lock:
				_entry = self._known.get(_mac)
				if _entry is not None:
					# If the device is currently online, give it a fresh baseline so
					# the first failed probe doesn't fire the threshold immediately.
					# If it's already offline, leave at 0 so the clock starts on the
					# first successful probe.
					if _entry.get("online", False):
						_entry["ping_only_last_ping_ok"] = _startup_now
		self._rename_and_move_net_devices()       # single pass: rename + move
		#self.indiLOG.log(20, f"startup: rename/move done  ")
		self._backfill_history_from_devices()
		#self.indiLOG.log(20, f"startup: backfill done ")
		self._start_threads()
		self.indiLOG.log(20, f"Network Scanner active")

	###----------------------------------------------------------###
	def _getPrefixName(self):
		return self.pluginPrefs.get("prefixName",kDefaultPluginPrefs["prefixName"]).strip()

	###----------------------------------------------------------###
	def _is_auto_name(self, name: str, mac: str) -> bool:
		"""Return True if name was auto-generated (starts with prefix+MAC).
		Returns False when mac is empty — an empty MAC would match every device name.
		"""
		if not mac:
			return False
		return name.startswith(self._getPrefixName() + mac.upper())

	###----------------------------------------------------------###
	def _kill_tcpdump(self):
		"""Kill all tcpdump subprocesses (sniff + DHCP, primary + secondary)."""
		for attr in ("_sniff_proc", "_sniff_proc2", "_dhcp_proc", "_dhcp_proc2"):
			proc = getattr(self, attr, None)
			if proc:
				setattr(self, attr, None)   # clear first so thread won't re-enter
				try: proc.kill()
				except Exception: pass
				try: proc.stdout.close()
				except Exception: pass
				try: proc.wait(timeout=2)
				except Exception: pass

	###----------------------------------------------------------###
	def _update_passive_info(self, mac: str, **kwargs):
		"""Update passive discovery fields (dhcp_hostname, mdns_services, mdns_model,
		os_hint) in _known and push any changed values to Indigo.

		Called from DHCP/mDNS background threads — safe to call with _known_lock NOT held.
		"""
		_KEY_TO_STATE = {
			"dhcp_hostname":  "dhcpHostname",
			"mdns_services":  "mdnsServices",
			"mdns_model":     "mdnsModel",
			"os_hint":        "osHint",
			"mdns_name":      "mdnsName",     # mDNS SRV hostname
			"arp_name":       "arpHostname",  # arp -a hostname
			"device_type":    "deviceType",
			"apple_model":    "appleModel",   # mDNS TXT am= (e.g. "iPhone15,3")
			"os_version":     "osVersion",    # mDNS TXT osxvers= (e.g. "21.6.0")
			"dhcp_os_fp":     "dhcpOsFingerprint",  # DHCP option 55 fingerprint
			"network_iface":  "networkInterface",   # arp -a "on enX"
			"ping_ms":        "pingMs",       # ICMP RTT from probe
		}

		# mDNS service type → human-readable device category.
		# Checked in order; first match wins.
		# More-specific identifiers must come before broad ones:
		#   _apple-mobdev2 / _companion-link → iPhone/iPad/Mac (advertised alongside _airplay)
		#   _afpovertcp                       → Mac file sharing (Macs also do _airplay on macOS 12+)
		#   _airplay / _raop                  → only reaches here if none of the above matched
		#                                       → HomePod, Apple TV, AirPort Express
		_SVC_TYPE_MAP = [
			("_apple-mobdev2._tcp",   "Apple Mobile"),       # iPhone / iPad — USB/WiFi sync
			("_companion-link._tcp",  "Apple Mobile"),       # iPhone / iPad — Handoff / Continuity
			("_afpovertcp._tcp",      "Mac"),                # Mac AFP file sharing
			("_airplay._tcp",         "Smart Speaker / AV"), # HomePod, Apple TV (after mobile/Mac ruled out)
			("_raop._tcp",            "Smart Speaker / AV"), # AirPlay audio (older AirPort Express etc.)
			("_googlecast._tcp",      "Chromecast"),
			("_spotify-connect._tcp", "Smart Speaker"),
			("_homekit._tcp",         "HomeKit Accessory"),
			("_hap._tcp",             "HomeKit Accessory"),
			("_ipp._tcp",             "Printer"),
			("_pdl-datastream._tcp",  "Printer"),
			("_printer._tcp",         "Printer"),
			("_ssh._tcp",             "Computer"),
			("_sftp-ssh._tcp",        "Computer"),
			("_smb._tcp",             "Computer / NAS"),
			("_rfb._tcp",             "Computer (VNC)"),
			("_daap._tcp",            "Music Server"),
			("_sleep-proxy._udp",     "Apple Device"),
			("_device-info._tcp",     "Apple Device"),
			("_http._tcp",            "Web Server"),
			("_https._tcp",           "Web Server"),
		]
		changed_states = {}
		dev_id = None
		with self._known_lock:
			entry = self._known.get(mac)
			if entry is None:
				return
			dev_id = entry.get("indigo_device_id")
			old_values = {}   # _known values before this call — used for log
			for key, val in kwargs.items():
				if key not in _KEY_TO_STATE:
					continue
				val = (val or "").strip()
				if not val:
					continue
				old_val = entry.get(key, "")
				# mdns_services: accumulate — never shrink, only add new service types.
				# mDNS browse sees different subsets on each pass; replacing the whole
				# string causes oscillation.  Merge new services into the existing set.
				if key == "mdns_services" and old_val:
					existing = {s.strip() for s in old_val.split(",") if s.strip()}
					incoming = {s.strip() for s in val.split(",")     if s.strip()}
					merged   = existing | incoming
					if merged == existing:
						continue   # nothing new — skip update
					val = ", ".join(sorted(merged))
				if old_val == val:
					continue
				# pingMs: only update when RTT differs by > 40% AND > 20 ms —
				# suppresses jitter noise while still catching genuine latency changes.
				if key == "ping_ms":
					try:
						new_ms = float(val.rstrip("ms").strip())
						old_ms = float(old_val.rstrip("ms").strip()) if old_val else 0.0
						if old_ms > 0:
							if abs(new_ms - old_ms) / old_ms < 0.40 or abs(new_ms - old_ms) <= 20:
								continue   # delta < 40% or ≤ 20 ms — skip update
					except (ValueError, ZeroDivisionError):
						pass   # unparseable — fall through and update anyway
				old_values[_KEY_TO_STATE[key]] = old_val   # snapshot before overwrite
				entry[key] = val
				changed_states[_KEY_TO_STATE[key]] = val
				if key == "mdns_name":
					# mDNS name also becomes the canonical local_name for device naming
					entry["local_name"]        = val
					entry["local_name_source"] = "mdns"

			# Derive deviceType from apple_model and/or mDNS services.
			# Re-evaluate whenever either field changes so corrections propagate.
			#
			# Priority:
			#   1. apple_model (mDNS TXT am=) — definitive hardware identifier
			#   2. mDNS service map — fallback when model code is absent
			#
			# apple_model prefixes → device type (case-insensitive prefix match):
			_APPLE_MODEL_MAP = [
				("iphone",         "Apple Mobile"),
				("ipad",           "Apple Mobile"),
				("ipod",           "Apple Mobile"),
				("macbook",        "Mac"),
				("imac",           "Mac"),
				("macpro",         "Mac"),
				("macmini",        "Mac"),
				("macstudio",      "Mac"),
				("xserve",         "Mac"),
				("audioaccessory", "Smart Speaker / AV"),   # HomePod
				("appletv",        "Smart Speaker / AV"),
				("airport",        "Smart Speaker / AV"),   # AirPort Express with AirPlay
			]
			if "mdnsServices" in changed_states or "appleModel" in changed_states:
				# Use the most up-to-date values: prefer the just-changed value,
				# fall back to what is already stored in the entry.
				apple_model = (changed_states.get("appleModel") or entry.get("apple_model") or "").lower()
				svc_str     = (changed_states.get("mdnsServices") or entry.get("mdns_services") or "").lower()

				new_type = None
				# Step 1 — apple_model prefix match (most specific)
				for prefix, label in _APPLE_MODEL_MAP:
					if apple_model.startswith(prefix):
						new_type = label
						break
				# Step 2 — service map fallback
				if new_type is None and svc_str:
					for svc_key, label in _SVC_TYPE_MAP:
						if svc_key in svc_str:
							new_type = label
							break

				if new_type and entry.get("device_type") != new_type:
					entry["device_type"] = new_type
					changed_states["deviceType"] = new_type

		if not changed_states or not dev_id:
			return
		updates = [{"key": k, "value": v} for k, v in changed_states.items()]
		try:
			dev = indigo.devices[dev_id]
			dev.updateStatesOnServer(updates)
			with self._dev_cache_lock:
				if dev_id in self._dev_cache:
					self._dev_cache[dev_id]["states"].update(changed_states)
			if not self.in_grace_period:
				parts = [
					f"{k}: {old_values.get(k, '') or '—'}  →  {v}"
					for k, v in changed_states.items()
				]
				if _DEBUG_PASSIVE: self.indiLOG.log(10, f"passive-info {mac}: " + "  |  ".join(parts))
		except Exception as e:
			self.indiLOG.log(20, f"_update_passive_info {mac}: {e}")

	###----------------------------------------------------------###
	def runConcurrentThread(self):
		"""Indigo's cooperative loop – sleep in 1 s steps so stop is near-instant."""
		try:
			while True:
				self.sleep(1)

				# Process offline requests queued by background threads.
				# IPC (updateStatesOnServer, replacePluginPropsOnServer) is safe here.
				with self._pending_offline_lock:
					pending = self._pending_offline_requests[:]
					self._pending_offline_requests.clear()
				for _dev_id, _mac, _ip, _src in pending:
					try:
						self._update_indigo_device(_mac, _ip, False,
						                           source=_src, dev_id=_dev_id)
					except Exception as _e:
						self.indiLOG.log(20, f"pending offline for dev {_dev_id}: {_e}")

				if self.in_grace_period:
					was = self.in_grace_period
					self.in_grace_period = (time.time() - self._startup_time) < _startupGracePeriod
					if was and not self.in_grace_period:
						self.indiLOG.log(20, f"startup finished, offline ignore period ended")
					
					

		except self.StopThread:
			pass

	# ------------------------------------------------------------------
	# Preferences
	# ------------------------------------------------------------------

	def _apply_flip_address_notes(self, flip):
		"""Immediately rewrite Address (pluginProps["address"]) and Notes (description)
		for all plugin devices when the flipAddressNotes preference is toggled.
		Called on the main thread from closedPrefsConfigUi so IPC is safe.

		networkDevice:         flip OFF → Address=MAC, Notes=IP
		                       flip ON  → Address=IP,  Notes=MAC
		networkDevicesHomeAway:flip OFF → Address=MACs, Notes=IPs
		                       flip ON  → Address=IPs,  Notes=MACs
		externalDevice:        flip OFF → Address=host, Notes=IP
		                       flip ON  → Address=IP,   Notes=host
		"""
		updated = 0
		for dev in indigo.devices.iter(PLUGIN_ID):
			try:
				if dev.deviceTypeId == DEVICE_TYPE_ID:
					# ── networkDevice ────────────────────────────────────────
					mac = dev.states.get("MACNumber", "")
					ip  = dev.states.get("ipNumber",  "")
					if not mac:
						continue
					_padded_ip = _ip_for_notes(ip) if ip else ""
					_addr_val  = _padded_ip if flip else mac
					_note_val  = mac        if flip else _padded_ip

					props = dict(dev.pluginProps)
					if _addr_val and props.get("address", "") != _addr_val:
						props["address"] = _addr_val
						dev.replacePluginPropsOnServer(props)
						self._cache_patch_props(dev.id, props)

					if _note_val and dev.description != _note_val:
						dev.description = _note_val
						dev.replaceOnServer()
						self._cache_set_description(dev.id, _note_val)

					updated += 1

				elif dev.deviceTypeId == HOME_AWAY:
					# ── networkDevicesHomeAway ────────────────────────────────
					# _recalc_group_device already reads pluginPrefs["flipAddressNotes"]
					# (updated by closedPrefsConfigUi before this method is called).
					self._recalc_group_device(dev)
					updated += 1

				elif dev.deviceTypeId == EXT_DEVICE_TYPE_ID:
					# ── externalDevice ────────────────────────────────────────
					# flip OFF: Address = host,        Notes = resolved IP
					# flip ON:  Address = resolved IP, Notes = host
					host       = dev.pluginProps.get("host", "").strip()
					props      = dict(dev.pluginProps)
					resolved   = dev.states.get("ipNumber", "")
					_padded_ip = _ip_for_notes(resolved) if resolved else ""

					# Fallback: when ipNumber state is empty, the IP may already be
					# visible in the column that was holding it before the toggle.
					# OFF→ON: IP was in description;  ON→OFF: IP was in address prop.
					if flip and not _padded_ip:
						_prev_desc = (dev.description or "").strip()
						if _prev_desc and _prev_desc.count(".") == 3:
							try:
								parts = _prev_desc.split(".")
								parts[-1] = str(int(parts[-1]))   # strip zero-padding
								resolved   = ".".join(parts)
								_padded_ip = _ip_for_notes(resolved)
							except Exception:
								pass
					elif not flip and not _padded_ip:
						_prev_addr = (props.get("address", "") or "").strip()
						if _prev_addr and _prev_addr.count(".") == 3:
							try:
								parts = _prev_addr.split(".")
								parts[-1] = str(int(parts[-1]))   # strip zero-padding
								resolved   = ".".join(parts)
								_padded_ip = _ip_for_notes(resolved)
							except Exception:
								pass

					if flip and not _padded_ip:
						continue   # genuinely no IP known yet — wait for next ping

					_addr_val = _padded_ip if flip else host
					_note_val = host       if flip else _padded_ip

					if _addr_val and props.get("address", "") != _addr_val:
						props["address"] = _addr_val
						dev.replacePluginPropsOnServer(props)
						self._cache_patch_props(dev.id, props)

					if _note_val and dev.description != _note_val:
						dev.description = _note_val
						dev.replaceOnServer()
						self._cache_set_description(dev.id, _note_val)

					updated += 1

			except Exception as e:
				self.indiLOG.log(20, f"_apply_flip_address_notes: error updating {dev.name}: {e}")

		self.indiLOG.log(20,
			f"flipAddressNotes → {'IP=Address / MAC=Notes' if flip else 'MAC=Address / IP=Notes'}"
			f"  ({updated} devices updated)"
		)

	###----------------------------------------------------------###
	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			# Indigo updates self.pluginPrefs with the new values BEFORE calling this
			# callback, so we cannot compare valuesDict against pluginPrefs to detect
			# a change.  Instead we track the previous value in _flip_address_notes_prev
			# (set in __init__ and updated here after each save).
			_raw          = valuesDict.get("flipAddressNotes", False)
			_new_flip     = (_raw is True) or (str(_raw).lower() == "true")
			_flip_changed = _new_flip != self._flip_address_notes_prev
			self._flip_address_notes_prev = _new_flip   # update for next save

			self.setLogFromPrefs(valuesDict)
			self._ensure_plugin_variables()
			# If the Address/Notes flip setting changed, immediately update all
			# networkDevice devices so the columns reflect the new layout at once.
			if _flip_changed:
				self._apply_flip_address_notes(_new_flip)
			# Signal all threads to stop
			self._stop_event.set()
			self._kill_tcpdump()
			# Join with short timeout — scan/sniff threads check stop_event every 0.1–0.2 s
			# so they should exit well within 1 second.  Never block the main thread longer.
			for t in (self._scan_thread, self._sniff_thread,
			          self._dhcp_thread, self._mdns_thread,
			          self._sniff_thread2, self._dhcp_thread2, self._sweep_thread2):
				if t and t.is_alive():
					t.join(timeout=1.0)
			self._stop_event.clear()
			self._start_threads()

	# ------------------------------------------------------------------
	# Device lifecycle
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def deviceStartComm(self, dev):
		# Refresh the cache entry for this device — called both at startup (for every
		# existing device) and when a device is enabled/created at runtime.
		self._cache_put(dev)

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

			# Respect flipAddressNotes:
			#   OFF (default): Address = host,        Notes = resolved IP
			#   ON:            Address = resolved IP,  Notes = host
			_flip_sc  = self.pluginPrefs.get("flipAddressNotes", False)
			_flip_sc  = (_flip_sc is True) or (str(_flip_sc).lower() == "true")
			if _flip_sc:
				# Address should be the resolved IP; leave it alone if no IP is known
				# yet — the first ping will set it correctly via the live update path.
				_resolved = dev.states.get("ipNumber", "")
				_padded   = _ip_for_notes(_resolved) if _resolved else ""
				if _padded and props.get("address", "") != _padded:
					props["address"] = _padded
					props_changed    = True
				# Notes (description) should be the host name
				try:
					if host and dev.description != host:
						dev.description = host
						dev.replaceOnServer()
						self._cache_set_description(dev.id, host)
				except Exception:
					pass
			else:
				# Address = host (default behaviour)
				if host and props.get("address", "") != host:
					props["address"] = host
					props_changed    = True

			if props_changed:
				try:
					dev.replacePluginPropsOnServer(props)
					self._cache_patch_props(dev.id, props)   # keep cache in sync
				except Exception:
					pass

			# Sync host into device state
			if host and dev.states.get("host", "") != host:
				dev.updateStateOnServer("host", value=host)
				self._cache_patch_states(dev.id, [{"key": "host", "value": host}])
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

	###----------------------------------------------------------###
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
		# Remove from device cache
		self._cache_drop(dev.id)

	###----------------------------------------------------------###
	def deviceDeleted(self, dev):
		"""Called by Indigo when a device is permanently deleted.

		For synthetic-MAC devices (00:00:00:00:00:XX) we remove the entire _known
		entry so the IP can be rediscovered cleanly on the next sweep.
		For real devices we only clear the indigo_device_id so the MAC entry
		(history, IP, vendor) survives for re-association if the device is recreated.
		"""
		super().deviceDeleted(dev)
		if dev.deviceTypeId != DEVICE_TYPE_ID:
			self._cache_drop(dev.id)
			return
		mac = dev.states.get("MACNumber", "").lower()
		if not mac:
			self._cache_drop(dev.id)
			return
		is_synthetic = mac.startswith("00:00:00:00:00:")
		with self._known_lock:
			if is_synthetic:
				# Remove entirely — synthetic MACs are ephemeral; we want a clean
				# rediscovery (fresh pending entry, fresh ping checks) rather than
				# re-registering against a stale entry with a dead device ID.
				self._known.pop(mac, None)
				self.indiLOG.log(20, f"Synthetic device deleted: removed {mac} from known-devices cache")
			else:
				entry = self._known.get(mac, {})
				if entry.get("indigo_device_id") == dev.id:
					entry.pop("indigo_device_id", None)
		self._cache_drop(dev.id)

	###----------------------------------------------------------###
	def deviceUpdated(self, origDev, newDev):
		"""Called by Indigo when any device attribute changes externally (name, folder, etc.).
		Refresh the cache so cached name/description/props stay current.
		enabled changes are handled by deviceStartComm/deviceStopComm instead.
		"""
		super().deviceUpdated(origDev, newDev)
		# Only cache our own plugin's devices
		with self._dev_cache_lock:
			if newDev.id in self._dev_cache:
				entry = self._dev_cache[newDev.id]
				entry["name"]        = newDev.name
				entry["description"] = newDev.description
				entry["enabled"]     = newDev.enabled
				entry["pluginProps"] = dict(newDev.pluginProps)  # refresh on any prop change

	###----------------------------------------------------------###
	def getActiveIfaceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list for primary interface.
		Value '_auto' = auto-detect (prefer Ethernet over Wi-Fi).
		Excludes whichever interface is already selected as secondary.
		"""
		other = (valuesDict or {}).get("networkInterface2", "_none").strip()
		items = [("_auto", "— auto-detect (prefer Ethernet) —")]
		ifaces = _active_ifaces()
		for name, ip, kind in ifaces:
			if name == other:
				continue  # already chosen as secondary
			items.append((name, f"{name}   ({kind}   {ip})"))
		if len(ifaces) == 0:
			items.append(("_auto", "  (no active interfaces found — check cables / Wi-Fi)"))
		return items

	###----------------------------------------------------------###
	def getActiveIfaceList2(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list for secondary interface.
		Value '_none' = disabled (default — no second interface).
		Excludes whichever interface is already selected as primary.
		"""
		other = (valuesDict or {}).get("networkInterface", "_auto").strip()
		# resolve auto-detect to the actual interface name so we can exclude it
		if not other or other == "_auto":
			other = _auto_detect_iface()
		items = [("_none", "— none  (second interface disabled) —")]
		for name, ip, kind in _active_ifaces():
			if name == other:
				continue  # already chosen as primary
			items.append((name, f"{name}   ({kind}   {ip})"))
		return items

	###----------------------------------------------------------###
	def getExternalDeviceList(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list callback: returns all externalDevice entries for trigger menus."""
		items = [("0", "— not used —")]
		for dev in sorted(indigo.devices.iter(PLUGIN_ID), key=lambda d: d.name.lower()):
			if dev.deviceTypeId == EXT_DEVICE_TYPE_ID:
				host = dev.pluginProps.get("host", "")
				label = f"{dev.name}  ({host})" if host else dev.name
				items.append((str(dev.id), label))
		return items

	###----------------------------------------------------------###
	def getNetworkDeviceListForTrigger(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Dynamic list callback: returns all networkDevice entries for trigger menus."""
		items = [("0", "— not used —")]
		for dev in sorted(indigo.devices.iter(PLUGIN_ID), key=lambda d: d.name.lower()):
			if dev.deviceTypeId == DEVICE_TYPE_ID:
				ip = dev.states.get("ipNumber", "")
				label = f"{dev.name}  ({ip})" if ip else dev.name
				items.append((str(dev.id), label))
		return items

	###----------------------------------------------------------###
	def getDeviceConfigUiValues(self, pluginProps, typeId=None, devId=None):
		"""Pre-populate device edit fields with current live values."""
		theDictList = super(Plugin, self).getDeviceConfigUiValues(pluginProps, typeId, devId)
		if typeId == DEVICE_TYPE_ID and devId:
			try:
				dev = indigo.devices[devId]
				theDictList[0]["manualIpOverride"]     = dev.states.get("ipNumber", "")
				theDictList[0]["isApOrRouterOverride"] = dev.states.get("isApOrRouter", False)
				theDictList[0]["currentMac"]           = dev.states.get("MACNumber", "(not set)")
				theDictList[0]["macOverride"]          = ""   # always blank — user must type to change
			except Exception:
				pass
		return theDictList

	###----------------------------------------------------------###
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		"""Validate device edit fields before the dialog is closed.

		Currently validates:
		  macOverride — if filled in, must be exactly aa:bb:cc:dd:ee:ff format.
		"""
		errorsDict = indigo.Dict()

		if typeId == DEVICE_TYPE_ID:
			new_mac = valuesDict.get("macOverride", "").strip()
			if new_mac:
				if not self._is_valid_mac(new_mac):
					errorsDict["macOverride"] = (
						"Invalid MAC address — format must be aa:bb:cc:dd:ee:ff "
						"(six pairs of hex digits separated by colons)."
					)

		if errorsDict:
			return (False, valuesDict, errorsDict)
		return (True, valuesDict)

	###----------------------------------------------------------###
	def closedDeviceConfigUi(self, valuesDict, userCancelled, typeId, devId):
		"""Sync pluginProps → device states whenever the dialog is saved."""
		if userCancelled:
			return
		try:
			dev     = indigo.devices[devId]
			# Refresh cache with the new props from the dialog.
			# indigo.devices[devId].pluginProps still holds the PRE-save values at
			# this call site — Indigo writes them after closedDeviceConfigUi returns.
			# Use valuesDict directly so the cache reflects what the user just saved.
			with self._dev_cache_lock:
				entry = self._dev_cache.get(dev.id)
				if entry:
					entry["pluginProps"] = dict(valuesDict)
				else:
					# Device not in cache yet — build a fresh entry using valuesDict for
					# pluginProps (dev.pluginProps is still pre-save at this call site).
					self._dev_cache[dev.id] = {
						"states":       dict(dev.states),
						"pluginProps":  dict(valuesDict),
						"enabled":      dev.enabled,
						"name":         dev.name,
						"description":  dev.description,
						"deviceTypeId": dev.deviceTypeId,
					}
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
				self._cache_patch_states(devId, state_updates)
				# Address column
				if dev.pluginProps.get("address", "") != host:
					props = dict(dev.pluginProps)
					props["address"] = host
					dev.replacePluginPropsOnServer(props)
					self._cache_patch_props(devId, props)
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
					_flip_now = self.pluginPrefs.get("flipAddressNotes", False)
					_mac_now  = dev.states.get("MACNumber", "")
					_did      = devId
					# When flipped: Notes = MAC, Address = padded IP.
					# When normal:  Notes = padded IP, Address = MAC.
					_new_note = _mac_now if _flip_now else _ip_for_notes(manual_ip)
					_new_addr = _ip_for_notes(manual_ip) if _flip_now else _mac_now
					def _deferred_notes(did, note_val, addr_val):
						time.sleep(1.0)
						try:
							d = indigo.devices[did]
							changed = False
							if d.description != note_val:
								d.description = note_val
								changed = True
							_props = dict(d.pluginProps)
							if _props.get("address", "") != addr_val:
								_props["address"] = addr_val
								d.replacePluginPropsOnServer(_props)
							if changed:
								d.replaceOnServer()
						except Exception as _e:
							if f"{_e}".find("None") == -1:
								self.indiLOG.log(30, f"Could not update Notes: {_e}")
					threading.Thread(target=_deferred_notes, args=(_did, _new_note, _new_addr),
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

				# ── Manual MAC override ─────────────────────────────────────────────
				new_mac = valuesDict.get("macOverride", "").strip().lower()
				if new_mac:
					_mac_re = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
					if not _mac_re.match(new_mac):
						self.indiLOG.log(30, f"{dev.name}: invalid MAC format '{new_mac}' — must be aa:bb:cc:dd:ee:ff; not applied")
					else:
						old_mac = dev.states.get("MACNumber", "").lower()
						# Reject if the target MAC is already owned by a different device
						conflict = None
						for d in indigo.devices.iter(PLUGIN_ID):
							if d.id != devId and d.deviceTypeId == DEVICE_TYPE_ID:
								if d.states.get("MACNumber", "").lower() == new_mac:
									conflict = d.name
									break
						if conflict:
							self.indiLOG.log(30,
								f"{dev.name}: MAC '{new_mac}' already used by '{conflict}' — not applied")
						else:
							# Move _known entry from old_mac → new_mac
							with self._known_lock:
								entry = dict(self._known.pop(old_mac, {}))
								entry["mac"]              = new_mac
								entry["indigo_device_id"] = devId
								self._known[new_mac]      = entry
							# Update device state and address column
							dev.updateStateOnServer("MACNumber", value=new_mac.upper())
							# Vendor lookup for new MAC
							vendor = ""
							if self.M2V:
								try:
									vendor = self.M2V.get_manuf(new_mac) or ""
								except Exception:
									pass
							if vendor:
								dev.updateStateOnServer("hardwareVendor", value=vendor)
							# Rename device if it still has an auto-generated name
							if self._is_auto_name(dev.name, old_mac):
								prefix    = self._getPrefixName()
								new_name  = self._unique_device_name(f"{prefix}{new_mac.upper()}")
								try:
									dev.name = new_name
									dev.replaceOnServer()
								except Exception as _re:
									self.indiLOG.log(30, f"Could not rename device: {_re}")
							# Address column = MAC
							try:
								if dev.address != new_mac.upper():
									dev.address = new_mac.upper()
									dev.replaceOnServer()
							except Exception:
								pass
							self._cache_put(dev)
							self._save_state()
							self.indiLOG.log(20,
								f"{dev.name}: MAC manually changed  {old_mac or '(none)'} → {new_mac}"
								+ (f"  vendor: {vendor}" if vendor else ""))

		# ── Aggregate group devices: recalculate immediately after participant list changes ──
			elif typeId in (HOME_AWAY, ONLINE):
				self._recalc_group_device(dev)

		except Exception as e:
			if f"{e}".find("None") == -1:
				self.indiLOG.log(30, f"Could not update states for device {devId}: {e}")

	# ------------------------------------------------------------------
	# Internal: thread management
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def _start_threads(self):
		iface = self.pluginPrefs.get("networkInterface", "_auto").strip()
		if not iface or iface == "_auto":
			iface = _auto_detect_iface()
			self.indiLOG.log(20, f"Network interface auto-detected: {iface}")
		# "_none" or blank = second interface disabled
		raw2  = self.pluginPrefs.get("networkInterface2", "_none").strip()
		iface2 = "" if (not raw2 or raw2 == "_none") else raw2
		sniff_on = self.pluginPrefs.get("sniffEnabled",      kDefaultPluginPrefs["sniffEnabled"])
		sweep_on = self.pluginPrefs.get("arpSweepEnabled",   kDefaultPluginPrefs["arpSweepEnabled"])
		password = self.pluginPrefs.get("sudoPassword",      kDefaultPluginPrefs["sudoPassword"]).strip()

		# ── Primary interface threads ─────────────────────────────────────────
		if sniff_on:
			self._sniff_thread = threading.Thread(
				target=self._sniff_loop, args=(iface, password), daemon=True, name="NS-Sniff"
			)
			self._sniff_thread.start()
			self.indiLOG.log(20, f"traffic sniffer (tcpdump) started on {iface}")
		else:
			self.indiLOG.log(20, "Passive ARP sniffing disabled.")

		self._dhcp_thread = threading.Thread(
			target=self._dhcp_sniff_loop, args=(iface, password), daemon=True, name="NS-DHCP"
		)
		self._dhcp_thread.start()
		self.indiLOG.log(20, "DHCP passive sniffer started.")

		self._mdns_thread = threading.Thread(
			target=self._mdns_browse_loop, daemon=True, name="NS-mDNS"
		)
		self._mdns_thread.start()
		self.indiLOG.log(20, "mDNS browse loop started.")

		self._scan_thread = threading.Thread(
			target=self._scan_loop, args=(iface, sweep_on), daemon=True, name="NS-Scan"
		)
		self._scan_thread.start()
		self.indiLOG.log(20, "Device scan loop started.")

		# ── Secondary interface threads (only when networkInterface2 is set) ──
		if iface2:
			if sniff_on:
				self._sniff_thread2 = threading.Thread(
					target=self._sniff_loop, args=(iface2, password, True),
					daemon=True, name="NS-Sniff2"
				)
				self._sniff_thread2.start()
				self.indiLOG.log(20, f"traffic sniffer (tcpdump) started on {iface2} [secondary]")

			self._dhcp_thread2 = threading.Thread(
				target=self._dhcp_sniff_loop, args=(iface2, password, True),
				daemon=True, name="NS-DHCP2"
			)
			self._dhcp_thread2.start()
			self.indiLOG.log(20, f"DHCP sniffer started on {iface2} [secondary]")

			# Sweep only — per-device probing is handled by the primary scan loop
			self._sweep_thread2 = threading.Thread(
				target=self._sweep_only_loop, args=(iface2, sweep_on),
				daemon=True, name="NS-Sweep2"
			)
			self._sweep_thread2.start()
			self.indiLOG.log(20, f"ARP sweep started on {iface2} [secondary]")
		else:
			had_secondary = any([self._sniff_thread2, self._dhcp_thread2, self._sweep_thread2])
			self._sniff_thread2 = None
			self._dhcp_thread2  = None
			self._sweep_thread2 = None
			if had_secondary:
				self.indiLOG.log(20, "Second network interface disabled — stopped listening on secondary interface.")

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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _sniff_loop(self, iface: str, password: str = "", secondary: bool = False):
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
			# Use cache — this inner function is called for every captured packet
			if self._cache_props(dev_id).get("logSeenToFile", False):
				self.indiLOG.log(10, f"tcpdump [{iface}]  [{mac}]: {line}")

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
					shell_cmd = f"echo {shlex.quote(password)} | sudo -S {self._exe_tcpdump} -i {iface} -n -e -l '{_BPF}'"
				else:
					shell_cmd = f"{self._exe_tcpdump} -i {iface} -n -e -l '{_BPF}'"
				log_cmd = shell_cmd.replace(shlex.quote(password), "***") if password else shell_cmd
				self.indiLOG.log(20, f"tcpdump launch: {log_cmd}")
				proc = subprocess.Popen(
					shell_cmd, shell=True,
					stdout=subprocess.PIPE,
					stderr=subprocess.DEVNULL,
				)
				if secondary:
					self._sniff_proc2 = proc
				else:
					self._sniff_proc  = proc

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
							self.indiLOG.log(10, f"tcpdump [{iface}] first chunk {len(chunk)} bytes: {repr(chunk[:200])}")
					buf += chunk
					while b"\n" in buf:
						raw, buf = buf.split(b"\n", 1)
						line = raw.decode("utf-8", errors="replace")
						now = time.time()
						if False and line.find("ff:ff:ff:ff:ff:ff") == -1 and line.find("00:00:00:00:00:00") == -1:
							self.indiLOG.log(10, f" >>>  {len(line)} line: {line}")

						# ── Raw-line trace: log complete tcpdump output for tracked devices ──
						# Checked BEFORE any parsing or throttle so nothing is missed.
						# Uses a simple substring match so it catches the device regardless
						# of which field (src MAC, dst MAC, ARP payload IP, etc.) it appears in.
						_trk_targets = self._trace_targets()
						if _trk_targets:
							_line_lower = line.lower()
							for _trk in _trk_targets:
								if _trk in _line_lower:
									self.indiLOG.log(10, f"[TRACE {_trk}] raw-tcpdump [{iface}]: {line}")
									break   # one raw log line per packet even if two targets match

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
									self.indiLOG.log(10, f"ARP reply [{iface}]  mac={mac}  ip={ip}"
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
								self._trace_log(mac, ip, "sniff-ARP-reply",
									f"line={line[:140]!r}")
								self._register_device(mac, ip, source="traffic observed (tcpdump)")
							continue

					# ── ARP Announcement (Gratuitous ARP): "I am at <IP>" ──────
					# tcpdump reports these as "Announcement <IP>" rather than
					# "Reply <IP> is-at <MAC>".  The source MAC in the ethernet
					# header IS the announcing device — register immediately.
					if "Announcement " in line:
						mm = _src_mac_re.match(line)
						if mm:
							ann_mac = mm.group(1).lower()
							if ann_mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") \
									and not (int(ann_mac[:2], 16) & 1):
								ma = re.search(r'\bAnnouncement\s+([\d.]+)', line, re.I)
								if ma:
									ann_ip = ma.group(1)
									key = (ann_mac, ann_ip)
									if now - _throttle.get(key, 0) >= _THROTTLE_SECS:
										_throttle[key] = now
										_throttle[ann_mac] = now
										self._trace_log(ann_mac, ann_ip, "sniff-ARP-announce",
											f"line={line[:140]!r}")
										self._register_device(ann_mac, ann_ip,
											source="traffic observed (tcpdump)")
						continue

					# ── mDNS: register device + parse PTR/SRV/A records ────────
					if ".5353 >" in line:
						mm = _src_mac_re.match(line)
						if mm:
							mdns_mac = mm.group(1).lower()
							if not (mdns_mac == "ff:ff:ff:ff:ff:ff" or (int(mdns_mac[:2], 16) & 1)):
								# IPv4: try ethernet-header src first (IPv4 mDNS),
								# then fall back to the mDNS A record in the payload
								# (IPv6 mDNS — src is link-local, real IP is in A record).
								mi = _src_ip_re.search(line)
								mdns_ip = mi.group(1) if mi else ""
								if not mdns_ip or mdns_ip.startswith("169.254."):
									ma_rec = re.search(
										r'(?<!\w)A\s+(\d{1,3}(?:\.\d{1,3}){3})\b', line)
									if ma_rec:
										mdns_ip = ma_rec.group(1)
								# Register device to keep last_seen fresh
								if mdns_ip and not mdns_ip.startswith("169.254.") \
										and mdns_ip != "0.0.0.0":
									if now - _throttle.get(mdns_mac, 0) >= _THROTTLE_SECS:
										_throttle[mdns_mac] = now
										self._register_device(mdns_mac, mdns_ip,
											source="traffic observed (tcpdump)")

								# Only parse records from RESPONSES, not queries.
								# Queries contain "(QM)?" — responses do not.
								is_response = "(QM)?" not in line
								passive = {}

								# Hostname from SRV record: "SRV hostname.local.:port"
								srv_m = re.search(r'\bSRV\s+([\w\-]+)\.local\.', line)
								if srv_m:
									passive["mdns_name"] = srv_m.group(1)

								if is_response:
									# Service types from PTR records (responses only)
									svc_types = []
									for m_ptr in re.finditer(
											r'PTR\s+(\S*?_[^.]+\._(tcp|udp)\.local\.)', line):
										full  = m_ptr.group(1).rstrip(".")
										parts = full.split(".")
										# instance._svc._proto.local → _svc._proto
										# _svc._proto.local          → _svc._proto
										if len(parts) >= 3:
											svc_types.append(f"{parts[-3]}.{parts[-2]}")
										elif len(parts) == 2:
											svc_types.append(full)
									if svc_types:
										with self._known_lock:
											entry    = self._known.get(mdns_mac, {})
											existing = set(entry.get("mdns_services_set", []))
										new_svcs = set(svc_types) - existing
										if new_svcs:
											all_svcs = existing | new_svcs
											with self._known_lock:
												if mdns_mac in self._known:
													self._known[mdns_mac]["mdns_services_set"] = list(all_svcs)
											passive["mdns_services"] = ", ".join(sorted(all_svcs))

									# OS hint from Apple-exclusive service types.
									# These only appear on iOS/macOS — strong signal.
									_APPLE_SVCS = {
										"_asquic._udp", "_companion-link._tcp",
										"_rdlink._tcp",  "_apple-mobdev2._tcp",
										"_airplay._tcp", "_raop._tcp",
										"_homekit._tcp", "_sleep-proxy._udp",
										"_device-info._tcp",
									}
									if set(svc_types) & _APPLE_SVCS:
										passive["os_hint"] = "Apple (iOS/macOS)"

								if passive:
									self._update_passive_info(mdns_mac, **passive)
						continue   # ← inside the mDNS if-block; only skips mDNS lines

					# ── All other frames: src MAC + src IP (IPv4 only) ──────────
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
					self._trace_log(mac, ip, "sniff-frame",
						f"ip={ip}  line={line[:140]!r}")
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
	# DHCP passive sniff — hostname (opt 12), vendor class (opt 60), TTL
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def _dhcp_sniff_loop(self, iface: str, password: str = "", secondary: bool = False):
		"""Dedicated tcpdump -vv capture for DHCP packets (ports 67/68).

		Extracts per-device:
		  • dhcp_hostname  — DHCP option 12 (most reliable hostname source)
		  • os_hint        — vendor class option 60 (MSFT→Windows, android→Android …)
		Multi-line packets are accumulated between timestamp-leading lines.
		secondary=True stores the Popen handle in self._dhcp_proc2 so _kill_tcpdump
		can terminate it immediately when the second interface is disabled.
		"""
		BPF      = "(udp port 67 or udp port 68)"
		proc_attr = "_dhcp_proc2" if secondary else "_dhcp_proc"
		if password:
			cmd = (f"echo {shlex.quote(password)} | sudo -S "
			       f"{self._exe_tcpdump} -i {iface} -n -e -vv -l '{BPF}'")
		else:
			cmd = f"{self._exe_tcpdump} -i {iface} -n -e -vv -l '{BPF}'"

		_ts_re = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d")

		while not self._stop_event.is_set():
			try:
				proc = subprocess.Popen(cmd, shell=True,
				                        stdout=subprocess.PIPE,
				                        stderr=subprocess.DEVNULL)
				setattr(self, proc_attr, proc)
				fd  = proc.stdout.fileno()
				buf = b""
				pkt_lines: list = []

				while not self._stop_event.is_set():
					try:
						ready, _, _ = select.select([proc.stdout], [], [], 0.2)
					except Exception:
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
					buf += chunk
					while b"\n" in buf:
						raw, buf = buf.split(b"\n", 1)
						line = raw.decode("utf-8", errors="replace")
						if _ts_re.match(line):
							if pkt_lines:
								self._parse_dhcp_packet("\n".join(pkt_lines))
							pkt_lines = [line]
						else:
							pkt_lines.append(line)

				try:
					proc.terminate()
				except Exception:
					pass
			except Exception as e:
				if "None" not in f"{e}":
					self.indiLOG.log(30, f"DHCP sniff [{iface}] error: {e}")
			if not self._stop_event.is_set():
				self._stop_event.wait(15)

	###----------------------------------------------------------###
	def _parse_dhcp_packet(self, text: str):
		"""Parse one accumulated DHCP packet block and call _update_passive_info."""
		# Client-Ethernet-Address is authoritative (works through relay agents)
		m = re.search(r'Client-Ethernet-Address\s+([0-9a-f:]{17})', text, re.I)
		if not m:
			m = re.search(r'^([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+>', text, re.I | re.M)
		if not m:
			return
		mac = m.group(1).lower()
		if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
			return

		updates = {}

		# Option 12 — hostname
		m = re.search(r'Hostname\s+Option\s+12[^:]*:\s+"?([^"\r\n]+)"?', text, re.I)
		if m:
			updates["dhcp_hostname"] = m.group(1).strip().strip('"')

		# Option 60 — vendor class → OS hint
		m = re.search(r'Vendor-Class\s+Option\s+60[^:]*:\s+"?([^"\r\n]+)"?', text, re.I)
		if m:
			vc = m.group(1).strip().strip('"')
			if "MSFT" in vc:
				updates["os_hint"] = "Windows"
			elif "android" in vc.lower():
				updates["os_hint"] = "Android"
			elif "dhcpcd" in vc.lower() or "udhcp" in vc.lower():
				updates["os_hint"] = "Linux"
			else:
				updates["os_hint"] = vc[:30]

		# Option 55 — parameter request list → DHCP OS fingerprint
		# Each OS requests options in a characteristic order/set:
		#   Windows 10/11: contains 249 and 252
		#   macOS / iOS:   starts 1, 121, 3 … (router discovery = option 121 second)
		#   Linux:         contains 28 (broadcast addr) and 2 (time offset) early
		#   Android:       contains 33 (static route) and 26 (interface MTU)
		m = re.search(r'Parameter-Request\s+Option\s+55[^:]*:(.*?)(?=\n\S|\Z)', text, re.I | re.S)
		if m:
			nums = [int(x) for x in re.findall(r'\b(\d{1,3})\b', m.group(1))]
			if nums:
				ns = set(nums)
				if {249, 252}.issubset(ns):
					updates["dhcp_os_fp"] = "Windows"
				elif 249 in ns:
					updates["dhcp_os_fp"] = "Windows"
				elif len(nums) >= 2 and nums[1] == 121:
					updates["dhcp_os_fp"] = "Apple (macOS/iOS)"
				elif 28 in ns and 2 in ns:
					updates["dhcp_os_fp"] = "Linux"
				elif 33 in ns and 26 in ns:
					updates["dhcp_os_fp"] = "Android"

		# TTL-based OS hint — limited reliability for DHCP but still useful:
		#   TTL=128 → very likely Windows (no overlap with normal devices)
		#   TTL=64  → Linux or Android (but iOS/macOS also use 64 on some builds)
		#   TTL=255 → iOS/macOS link-local broadcast OR network gear (ambiguous — skip)
		# Only apply when vendor-class option 60 did not already set a more specific hint.
		if "os_hint" not in updates:
			m = re.search(r'\bttl\s+(\d+)\b', text, re.I)
			if m:
				ttl = int(m.group(1))
				if ttl == 128:
					updates["os_hint"] = "Windows"
				elif ttl == 64:
					updates["os_hint"] = "Linux / Android"
				# ttl=255 skipped — too ambiguous (iOS broadcast + network gear)

		if updates:
			self._update_passive_info(mac, **updates)

	# ------------------------------------------------------------------
	# mDNS service discovery via dns-sd
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def _mdns_browse_loop(self):
		"""Periodically discover mDNS services and map to known devices.
		Runs every 5 minutes; first scan delayed 45 s to let _known populate.
		"""
		self._stop_event.wait(45)
		while not self._stop_event.is_set():
			try:
				self._mdns_scan_once()
			except Exception as e:
				self.indiLOG.log(30, f"mDNS browse error: {e}")
			self._stop_event.wait(300)

	###----------------------------------------------------------###
	def _mdns_scan_once(self):
		"""Run dns-sd to enumerate all mDNS service types and instances on the LAN."""
		# ── Step 1: browse for all service types (10 s window) ──────────────
		try:
			proc = subprocess.Popen(
				[self._exe_dns_sd, "-B", "_services._dns-sd._udp", "local."],
				stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
			)
		except Exception as e:
			self.indiLOG.log(20, f"dns-sd not available: {e}")
			return

		_svc_re = re.compile(r'\bAdd\b.+?local\.\s+(\S+)\s+(\S+)')
		service_types = set()
		deadline = time.time() + 10
		while time.time() < deadline and not self._stop_event.is_set():
			try:
				ready, _, _ = select.select([proc.stdout], [], [], 0.5)
			except Exception:
				break
			if ready:
				line = proc.stdout.readline().decode("utf-8", errors="replace")
				m = _svc_re.search(line)
				if m:
					# m.group(1) = "_tcp.local."  m.group(2) = "_airplay"
					proto = m.group(1).split(".")[0].lstrip("_")   # "tcp" or "udp"
					prefix = m.group(2)                             # "_airplay"
					service_types.add(f"{prefix}._{proto}")
		try:
			proc.terminate()
		except Exception:
			pass

		# ── Step 2: for each service type resolve instances ──────────────────
		ip_services:    dict = {}   # ip → set of service types
		ip_model:       dict = {}   # ip → model string (md=)
		ip_apple_model: dict = {}   # ip → Apple model code (am=)
		ip_os_version:  dict = {}   # ip → macOS/iOS kernel version (osxvers=)
		for svc_type in service_types:
			if self._stop_event.is_set():
				return
			for _inst, ip, model, apple_model, os_version in self._mdns_browse_service(svc_type):
				if ip:
					ip_services.setdefault(ip, set()).add(svc_type)
					if model       and ip not in ip_model:       ip_model[ip]       = model
					if apple_model and ip not in ip_apple_model: ip_apple_model[ip] = apple_model
					if os_version  and ip not in ip_os_version:  ip_os_version[ip]  = os_version

		# ── Step 3: match IPs to _known MACs and push updates ───────────────
		with self._known_lock:
			snapshot = {mac: dict(e) for mac, e in self._known.items()}
		for mac, entry in snapshot.items():
			ip = entry.get("ip", "")
			if not ip:
				continue
			updates = {}
			svcs = ip_services.get(ip)
			if svcs:
				updates["mdns_services"] = ", ".join(sorted(svcs))
			if ip in ip_model:       updates["mdns_model"]   = ip_model[ip]
			if ip in ip_apple_model: updates["apple_model"]  = ip_apple_model[ip]
			if ip in ip_os_version:  updates["os_version"]   = ip_os_version[ip]
			if updates:
				self._update_passive_info(mac, **updates)

	###----------------------------------------------------------###
	def _mdns_browse_service(self, svc_type: str) -> list:
		"""Browse one mDNS service type; return list of (name, ip, model) tuples."""
		results = []
		try:
			proc = subprocess.Popen(
				[self._exe_dns_sd, "-B", svc_type, "local."],
				stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
			)
		except Exception:
			return results

		_inst_re = re.compile(r'\bAdd\b.+?local\.\s+\S+\s+(.+)')
		instances = []
		deadline = time.time() + 5
		while time.time() < deadline and not self._stop_event.is_set():
			try:
				ready, _, _ = select.select([proc.stdout], [], [], 0.5)
			except Exception:
				break
			if ready:
				line = proc.stdout.readline().decode("utf-8", errors="replace")
				m = _inst_re.search(line)
				if m:
					instances.append(m.group(1).strip())
		try:
			proc.terminate()
		except Exception:
			pass

		for instance in instances:
			if self._stop_event.is_set():
				break
			ip, model, apple_model, os_version = self._mdns_resolve(instance, svc_type)
			results.append((instance, ip, model, apple_model, os_version))
		return results

	###----------------------------------------------------------###
	def _mdns_resolve(self, instance: str, svc_type: str) -> tuple:
		"""Resolve a mDNS service instance; return (ip, model, apple_model, os_version).

		Extracted TXT record fields:
		  md=      → model (human name, e.g. "HomePod mini")
		  am=      → Apple internal model code (e.g. "iPhone15,3", "MacBookPro18,1")
		  osxvers= → macOS/iOS kernel version (e.g. "21.6.0")
		"""
		try:
			proc = subprocess.Popen(
				[self._exe_dns_sd, "-L", instance, svc_type, "local."],
				stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
			)
		except Exception:
			return ("", "", "", "")

		ip          = ""
		model       = ""
		apple_model = ""
		os_version  = ""
		deadline = time.time() + 3
		while time.time() < deadline and not self._stop_event.is_set():
			try:
				ready, _, _ = select.select([proc.stdout], [], [], 0.5)
			except Exception:
				break
			if ready:
				line = proc.stdout.readline().decode("utf-8", errors="replace").strip()
				ma = re.search(r'address\s*=\s*(\d+\.\d+\.\d+\.\d+)', line)
				if ma:
					ip = ma.group(1)
				mm = re.search(r'\bmd=([^\s=,]+)', line)
				if mm and not model:
					model = mm.group(1)
				am = re.search(r'\bam=([^\s=,]+)', line)
				if am and not apple_model:
					apple_model = am.group(1)
				ov = re.search(r'\bosxvers=([^\s=,]+)', line)
				if ov and not os_version:
					os_version = ov.group(1)
		try:
			proc.terminate()
		except Exception:
			pass
		return (ip, model, apple_model, os_version)

	# ------------------------------------------------------------------
	# Scan loop
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def _scan_loop(self, iface: str, sweep_enabled: bool):
		"""
		Periodically:
		  1. ARP-sweep the local subnet to find new devices.
		  2. Ping all known devices to update online/offline state.
		"""
		# Short startup pause so all deviceStartComm() calls complete before
		# the first sweep.  Uses stop_event so shutdown exits immediately.
		self._stop_event.wait(timeout=_STARTUP_WAIT_SECS)
		if self._stop_event.is_set():
			return

		while not self._stop_event.is_set():
			interval = int(self.pluginPrefs.get("scanInterval", kDefaultPluginPrefs["scanInterval"]))

			if sweep_enabled:
				self._arp_sweep(iface)

			self._check_all_devices(iface)
			self._check_external_devices()
			self._save_state()

			# Between ARP sweeps, run _check_all_devices every
			# _PING_ONLY_INTERVAL_OFFLINE seconds so that pingOnly / ping-enabled
			# devices are probed on their own schedule (60 s online, 15 s offline)
			# rather than being throttled to the much longer scan interval.
			# Per-device ping_only_next_probe gates and the sweep-freshness check
			# already prevent any redundant work for non-pingOnly devices.
			elapsed = 0
			while not self._stop_event.is_set():
				remaining = interval - elapsed
				if remaining <= 0:
					break
				sleep_secs = min(_PING_ONLY_INTERVAL_OFFLINE, remaining)
				steps = max(1, int(sleep_secs / 0.2))
				for _ in range(steps):
					if self._stop_event.is_set():
						break
					time.sleep(0.2)
				elapsed += sleep_secs
				if not self._stop_event.is_set() and elapsed < interval:
					self._check_all_devices(iface)

	###----------------------------------------------------------###
	def _sweep_only_loop(self, iface: str, sweep_enabled: bool):
		"""ARP sweep loop for a secondary interface.

		Runs _arp_sweep on the secondary interface every scan-interval.
		Per-device probing (_check_all_devices) is intentionally NOT duplicated
		here — pings are IP-based and already run from the primary scan loop,
		so running them again would waste CPU without providing new information.
		When sweep_enabled is False this loop exits immediately (no-op).
		"""
		if not sweep_enabled:
			return
		self._stop_event.wait(timeout=_STARTUP_WAIT_SECS)
		if self._stop_event.is_set():
			return
		while not self._stop_event.is_set():
			interval = int(self.pluginPrefs.get("scanInterval", kDefaultPluginPrefs["scanInterval"]))
			self._arp_sweep(iface)
			steps = int(interval / 0.2)
			for _ in range(steps):
				if self._stop_event.is_set():
					break
				time.sleep(0.2)

	###----------------------------------------------------------###
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
		now         = time.time()
		subnet_info = _local_subnet(iface)
		if not subnet_info:
			self.indiLOG.log(30, f"ARP sweep [{iface}]: could not determine local subnet; skipping.")
			return
		net_str, cidr = subnet_info
		if self.decideMyLog("Sweep"):
			self.indiLOG.log(10, f"ARP sweep [{iface}] (ping+arp) → {net_str}/{cidr}")

		# Optional active mDNS query: one 50-byte multicast packet prompts all
		# mDNS devices to announce themselves.  Responses arrive on port 5353 and
		# are processed automatically by the passive sniff thread — reveals devices
		# hidden behind proxy-ARP APs whose MAC never shows up in arp -a.
		if self.pluginPrefs.get("mdnsQueryEnabled", False):
			_send_mdns_query(iface)
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
					self.indiLOG.log(10, f"sweep [{iface}]  ping  {ip}  {'ok' if alive else 'fail'}")
				if not alive:
					# ICMP may be filtered (firewall, iOS privacy mode) — try TCP ports.
					# rst_counts_alive=False: some routers send TCP RST on behalf of all
					# subnet IPs, which would add an offline device to `responded` and cause
					# a false ON transition.  Only a full TCP handshake counts here.
					port  = _curl_check(ip, preferred_port=ip_to_curl_port.get(ip),
					                    rst_counts_alive=False)
					alive = port is not None
					if log_ping and port is not None:
						self.indiLOG.log(10, f"sweep [{iface}]  probe {ip}  ok port {port}")
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
				deadline = time.time() + _PROBE_POOL_DEADLINE
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
			arp_timeout = max(_ARP_TIMEOUT_MIN,
			                  int(self.pluginPrefs.get("arpTimeout", _ARP_TIMEOUT_MIN)))
			result = None
			for _arp_attempt in range(2):
				try:
					result = subprocess.run(
						[
							self._exe_arp,
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
			arp_iface:  dict = {}   # mac → network interface name (e.g. "en0", "en1")
			log_arp_sweep = self.decideMyLog("ArpSweepEntries")
			for line in result.stdout.splitlines():
				m = arp_re.search(line)
				if not m:
					continue
				raw_name, ip, mac = m.group(1), m.group(2), m.group(3).lower()
				if mac == "ff:ff:ff:ff:ff:ff":
					continue
				# Extract "on enX" interface name — first occurrence per MAC wins
				if mac not in arp_iface:
					iface_m = re.search(r'\bon\s+(en\d+)\b', line)
					if iface_m:
						arp_iface[mac] = iface_m.group(1)
				# Log every raw arp -a entry (plugin config: Log ARP Sweep Entries)
				replied_flag = ip in responded
				if log_arp_sweep:
					self.indiLOG.log(10, f"arp -a [{iface}]  mac={mac}  ip={ip}  name={raw_name}"
					                     f"{'  [replied]' if replied_flag else '  [cache-only]'}")
				# Detailed trace for the specifically-watched device
				self._trace_log(mac, ip, "arp-a",
					f"name={raw_name!r}  replied={replied_flag}")
				if raw_name == "?" or re.match(r"^\d+\.\d+\.\d+\.\d+$", raw_name):
					local_name = ""
				else:
					local_name = raw_name.rstrip(".")
				replied    = replied_flag   # already computed above (ip in responded)
				try:
					# 169.254.0.0/16 is the IANA link-local block (RFC 3927) — assigned
					# automatically by the OS when DHCP fails (APIPA / self-assigned).
					# These addresses are temporary and not routable, so deprioritised.
					link_local = (socket.inet_aton(ip)[0] == _LINK_LOCAL_BYTE1 and socket.inet_aton(ip)[1] == _LINK_LOCAL_BYTE2)
				except OSError:
					link_local = False
				if mac not in arp_by_mac:
					arp_by_mac[mac] = (ip, local_name, replied, False)
				else:
					cur_ip, cur_name, cur_replied, _ = arp_by_mac[mac]
					try:
						cur_ll = (socket.inet_aton(cur_ip)[0] == _LINK_LOCAL_BYTE1 and socket.inet_aton(cur_ip)[1] == _LINK_LOCAL_BYTE2)
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
				# Push network interface name (e.g. en0 = WiFi, en1 = Ethernet)
				if mac in arp_iface:
					self._update_passive_info(mac, network_iface=arp_iface[mac])

			# ── Ping-only devices: responded to ICMP but have no ARP entry ───
			# These devices don't participate in normal LAN ARP traffic (e.g. a
			# device on a different VLAN reachable via routing, or one that blocks
			# ARP responses).  Create / refresh them with a synthetic MAC so they
			# get an Indigo device, and immediately set pingMode=pingOnly since
			# passive ARP/tcpdump will never see them.
			#
			# Creation is intentionally delayed by _PING_ONLY_NEW_DEVICE_DELAY
			# seconds to give tcpdump / ARP a chance to discover the real MAC first.
			# The IP is held in self._ping_only_pending until the delay expires.
			# Skipped entirely during the startup grace period — ARP/tcpdump have not
			# had time to populate _known yet, so all responding IPs would look "new".
			ips_with_mac = {ip for (ip, _, _, _) in arp_by_mac.values()}
			ping_only_n  = 0

			if not self.in_grace_period:
				# Purge pending entries whose IP is now in arp_by_mac (real MAC found)
				# or is now tracked under a real MAC in _known (tcpdump found it).
				with self._known_lock:
					real_mac_ips = {e.get("ip") for m, e in self._known.items()
					                if e.get("ip") and not m.startswith("00:00:00:00:00:")}
				stale_cutoff = now - _PING_ONLY_NEW_DEVICE_DELAY * 10

				# _ping_only_pending values are (first_seen_ts, sweep_count) tuples.
				# Accept plain floats left over from older code and convert them.
				cleaned = {}
				for ip, val in self._ping_only_pending.items():
					if ip in ips_with_mac or ip in real_mac_ips:
						continue   # real MAC appeared — drop it
					if isinstance(val, tuple):
						ts, sc = val
					else:
						ts, sc = float(val), 0   # legacy scalar — treat sweep_count as 0
					if ts <= stale_cutoff:
						continue   # too old — drop
					cleaned[ip] = (ts, sc)
				self._ping_only_pending = cleaned

				for ip in list(responded):
					if ip in ips_with_mac:
						continue   # already handled via arp_by_mac

					# Check if this IP is tracked under a synthetic MAC already
					existing_synth = None
					with self._known_lock:
						for m, e in self._known.items():
							if e.get("ip") == ip and m.startswith("00:00:00:00:00:"):
								existing_synth = m
								break

					if existing_synth:
						# Known synthetic device — verify with a real ping before refreshing.
						# If the ping fails the IP is a ghost (proxy-ARP false positive): remove
						# the synthetic entry from _known so it stops being retried every sweep.
						# If the ping command itself fails (exception), skip silently — do not
						# refresh, do not delete; try again next sweep.
						_syn_ping_ok  = False
						_syn_ping_ran = False
						try:
							_syn_verify = subprocess.run(
								[self._exe_ping, "-c", "1", "-t", "2", "-q", ip],
								stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
								timeout=5, text=True
							)
							_syn_ping_ran = True
							_syn_ping_ok  = (_syn_verify.returncode == 0)
						except Exception:
							pass   # command failed — leave entry alone, retry next sweep
						if _DEBUG_FORCE_PING_OK:   # emulate: pretend ping succeeded
							_syn_ping_ran = True
							_syn_ping_ok  = True
						if not _syn_ping_ran:
							if not self._sbin_ping_missing_logged:
								self._sbin_ping_missing_logged = True
								self.indiLOG.log(30, f"/sbin/ping could not run  bad install ping is not installed or wrong place? ")
							continue   # ping command error — skip silently
						if not _syn_ping_ok:
							# Ghost IP — remove from _known and queue an offline update
							# for the main thread (runConcurrentThread).  IPC must not
							# run directly from this background thread.
							with self._known_lock:
								_ghost_entry = self._known.get(existing_synth, {})
								_ghost_id    = _ghost_entry.get("indigo_device_id")
								_ghost_ip    = _ghost_entry.get("ip", ip)
								self._known.pop(existing_synth, None)
							if _ghost_id:
								with self._pending_offline_lock:
									self._pending_offline_requests.append(
										(_ghost_id, existing_synth, _ghost_ip, "proxy-ARP ghost")
									)
							self.indiLOG.log(10,
								f"Synthetic device {existing_synth} at {ip}: ping failed — "
								f"removing (proxy-ARP ghost)"
							)
							continue
						self._register_device(existing_synth, ip, source="ping-only (no ARP)")
						continue

					# Check whether the IP is already tracked under a real MAC.
					# Also check ip_history — covers devices whose IP changed since last save.
					with self._known_lock:
						known_by_real = any(
							not m.startswith("00:00:00:00:00:") and (
								e.get("ip") == ip
								or any(
									r.get("new_ip") == ip or r.get("old_ip") == ip
									for r in e.get("ip_history", [])
								)
							)
							for m, e in self._known.items()
						)
					if known_by_real:
						# Real MAC device exists — remove from pending if present
						self._ping_only_pending.pop(ip, None)
						continue

					# Also check the device cache: an Indigo device may carry this IP
					# in its ipNumber state even if _known hasn't linked it yet (e.g.
					# after a plugin reload where _known was partially repopulated).
					with self._dev_cache_lock:
						ip_in_cache = any(
							s.get("ipNumber") == ip
							for s in (v.get("states", {}) for v in self._dev_cache.values())
						)
					if ip_in_cache:
						self._ping_only_pending.pop(ip, None)
						continue

					# Update / start the pending entry for this IP.
					# Each sweep increments sweep_count so we know how many consecutive
					# sweeps have seen this IP without any ARP reply.
					if ip in self._ping_only_pending:
						first_seen_ts, sweep_count = self._ping_only_pending[ip]
						sweep_count += 1
						self._ping_only_pending[ip] = (first_seen_ts, sweep_count)
					else:
						# First time seeing this IP without ARP — start the counter.
						first_seen_ts, sweep_count = now, 1
						self._ping_only_pending[ip] = (first_seen_ts, sweep_count)
						continue

					# Both conditions must be met before creating a synthetic device:
					#   1. IP has been pending for at least _PING_ONLY_NEW_DEVICE_DELAY seconds
					#   2. IP has been seen in at least _PING_ONLY_MIN_SWEEPS consecutive sweeps
					time_ready   = (now - first_seen_ts) >= _PING_ONLY_NEW_DEVICE_DELAY
					sweeps_ready = sweep_count >= _PING_ONLY_MIN_SWEEPS
					if not (time_ready and sweeps_ready):
						continue   # still within the waiting window

					# Both thresholds met.
					#
					# Step 1 — opt-in gate (cheapest check first).
					# If synthetic device creation is disabled there is no point running
					# any ping or ARP checks — skip immediately.
					if not self.pluginPrefs.get("syntheticDevicesEnabled", kDefaultPluginPrefs["syntheticDevicesEnabled"]):
						continue

					# Step 2 — verification ping.
					# Send 3 ICMP probes exactly as a user would from a terminal.
					# The ARP sweep uses a fast broadcast-like flood that some routers
					# (e.g. Draytek proxy-ARP) answer on behalf of the whole subnet, but
					# a direct single-host ping to a ghost IP fails in a terminal and
					# fails here too — that is the definitive real/ghost test.
					#   • ping fails  → ghost IP, discard permanently, never retried
					#   • ping passes → confirmed real device, proceed to next steps
					ping_ok  = False
					ping_ran = False
					try:
						verify = subprocess.run(
							[self._exe_ping, "-c", "3", "-t", "6", "-q", ip],
							stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
							timeout=10, text=True
						)
						ping_ran = True
						ping_ok  = (verify.returncode == 0)
					except Exception:
						pass   # command error — ping_ran stays False
					if _DEBUG_FORCE_PING_OK:   # emulate: pretend ping succeeded
						ping_ran = True
						ping_ok  = True

					if not ping_ran:
						# /sbin/ping could not run (permission error, missing binary, etc.).
						# We don't know if the device is real — leave the entry in pending
						# and retry next sweep.  Do NOT create a device.
						if not self._sbin_ping_missing_logged:
							self._sbin_ping_missing_logged = True
							self.indiLOG.log(40, f"/sbin/ping could not run ..   bad ping install..  is not installed or differnt directory, do a \"which ping\"  to get the proper path and contact author? ")
						continue

					if not ping_ok:
						# Ping ran but got no response — confirmed ghost.
						# Delete from pending permanently so it is never retried.
						self._ping_only_pending.pop(ip, None)
						if _DEBUG_PING_ONLY_4:
							self.indiLOG.log(10,
								f"Ping-only candidate at {ip}: verification ping failed — discarding (ghost / proxy-ARP false positive)"
							)
						continue

					# Step 2b — double-check ping after 1 second.
					# A single successful ping could be a stray reply or a transient
					# proxy-ARP echo.  Wait 1 s then ping once more; both must succeed.
					self._stop_event.wait(1)
					if self._stop_event.is_set():
						continue
					ping2_ok  = False
					ping2_ran = False
					try:
						verify2 = subprocess.run(
							[self._exe_ping, "-c", "1", "-t", "3", ip],
							stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
							timeout=6, text=True
						)
						ping2_ran = True
						ping2_ok  = (verify2.returncode == 0)
					except Exception:
						pass
					if _DEBUG_FORCE_PING_OK:
						ping2_ran = True
						ping2_ok  = True

					if not ping2_ran:
						continue   # binary problem — leave entry pending, retry next sweep

					if not ping2_ok:
						self._ping_only_pending.pop(ip, None)
						if _DEBUG_PING_ONLY_2:
							self.indiLOG.log(20,
								f"Ping-only candidate at {ip}: first ping passed but double-check ping (1 s later) failed — discarding as  transient/proxy-ARP false positive"
							)
						continue

					if _DEBUG_PING_ONLY_3:
						self.indiLOG.log(10,
							f"Ping-only candidate at {ip}: double-check ping confirmed — {verify2.stdout.strip()}"
						)

					# Step 3 — final targeted ARP check.
					# After the ping the kernel may have added an ARP entry.  If a real
					# unicast MAC appears here, register it as a normal device instead of
					# creating a synthetic one.
					# Use "arp -a" (dump all — no root needed).  "arp -n <ip>" writes to
					# the routing socket and fails with EPERM without sudo on macOS.
					real_mac_found = None
					try:
						arp_result = subprocess.run(
							[self._exe_arp, "-a"],
							stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
							timeout=3, text=True
						)
						for _arpl in arp_result.stdout.splitlines():
							if ip in _arpl:
								m = re.search(r'at\s+([0-9a-f:]{17})', _arpl, re.IGNORECASE)
								if m:
									real_mac_found = m.group(1).lower()
									break
					except Exception:
						pass

					self._ping_only_pending.pop(ip, None)

					if real_mac_found and real_mac_found != "ff:ff:ff:ff:ff:ff":
						if _DEBUG_PING_ONLY_1:
							self.indiLOG.log(10,
								f"Ping-only candidate at {ip}: ARP found real MAC {real_mac_found} after verification ping — registering normally"
							)
						self._register_device(real_mac_found, ip, source="ping-only (no ARP)")
						continue

					# Step 4 — rate-limit: at most one synthetic MAC per interval.
					if now - self._last_synthetic_created_at < _SYNTHETIC_MAC_CREATE_INTERVAL:
						self._ping_only_pending[ip] = (first_seen_ts, sweep_count)   # put back
						continue

					synth_mac = self._next_synthetic_mac()
					self.indiLOG.log(20,
						f"Ping-only device at {ip}: no ARP/tcpdump after "
						f"{int(now - first_seen_ts)}s / {sweep_count} sweeps — "
						f"creating with synthetic MAC {synth_mac}"
					)
					self._register_device(synth_mac, ip, source="ping-only (no ARP)")
					self._last_synthetic_created_at = now
					# pingMode=pingOnly is set in _create_indigo_device for synthetic MACs
					ping_only_n += 1

			if self.decideMyLog("Sweep"):
				self.indiLOG.log(10,
					f"ARP sweep complete on {net_str}/{cidr}: "
					f"{seen_n} device(s) replied to ping (online), "
					f"{discov_n} in ARP cache but no ping reply (likely offline / stale)"
					+ (f", {ping_only_n} new ping-only (no ARP)" if ping_only_n else "")
				)

			# ── Flush the ARP cache immediately after reading it ─────────────
			# macOS keeps ARP entries for ~20 minutes by default.  Entries for
			# powered-off or Indigo-disabled devices persist long after the device
			# has left the network, causing them to appear in every subsequent
			# arp -a result as cache-only (stale) entries.
			# Running  sudo arp -d -a  right after the sweep deletes all current
			# entries; the kernel will re-populate the cache naturally as live
			# devices exchange traffic or respond to the next ARP sweep.
			# Requires root; uses the configured sudo password when present.
			_arp_flush_password = self.pluginPrefs.get("sudoPassword", "").strip()
			if _arp_flush_password:
				try:
					_flush_cmd = (
						f"echo {shlex.quote(_arp_flush_password)} | "
						f"sudo -S {self._exe_arp} -d -a"
					)
					subprocess.run(
						_flush_cmd, shell=True, timeout=5,
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
					)
					if self.decideMyLog("Sweep"):
						self.indiLOG.log(10, "ARP cache flushed (arp -d -a)")
				except Exception:
					pass   # best-effort — failure is silent

				# ── Re-seed ARP entries for pingOnly devices ──────────────────
				# After arp -d -a the cache is empty.  A fresh ARP request for a
				# pingOnly device's IP is intercepted by the router (proxy-ARP),
				# so the subsequent ping reaches the router instead of the real
				# device.  Re-planting the known MAC with  arp -s  makes the ping
				# behave exactly like a terminal ping typed while the device was
				# still connected — it goes directly to the device's real MAC,
				# and if the device is off there is no answer.
				try:
					with self._known_lock:
						_seed_list = [
							(m, d.get("ip", ""), d.get("indigo_device_id"))
							for m, d in self._known.items()
							if d.get("ip") and not m.startswith("00:00:00:")
						]
					for _smac, _sip, _sdev_id in _seed_list:
						if not _sdev_id:
							continue
						if self._cache_props(_sdev_id).get("pingMode") != "pingOnly":
							continue
						try:
							_seed_cmd = (
								f"echo {shlex.quote(_arp_flush_password)} | "
								f"sudo -S {self._exe_arp} -s {_sip} {_smac}"
							)
							subprocess.run(
								_seed_cmd, shell=True, timeout=2,
								stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
							)
							if self.decideMyLog("Sweep"):
								self.indiLOG.log(10,
									f"ARP re-seeded for pingOnly device: {_sip} → {_smac}")
						except Exception:
							pass
				except Exception:
					pass
		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"ARP sweep error: {e}", exc_info=True)

	###----------------------------------------------------------###
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
		in_grace_period = self.in_grace_period

		with self._known_lock:
			snapshot = dict(self._known)

		results      = {}   # mac → (online, new_last_seen, new_streak) — written by worker threads
		results_lock = threading.Lock()

		# Build MAC → device name lookup once from cache; worker threads only read it (no lock needed)
		with self._dev_cache_lock:
			names_by_mac = {
				entry["states"].get("MACNumber", "").lower(): entry["name"]
				for entry in self._dev_cache.values()
				if entry["states"].get("MACNumber", "")
			}

		
		log_ping = self.decideMyLog("Ping")

		sweep_interval = int(self.pluginPrefs.get("scanInterval", kDefaultPluginPrefs["scanInterval"]))
		sweep_enabled  = self.pluginPrefs.get("arpSweepEnabled", True)

		probe_source: dict = {}   # mac → "ping(ICMP)" or "tcp:<port>" — set by _do_probe, read by _check_one
		probe_ms:     dict = {}   # mac → "N.Nms"  — RTT from successful ICMP ping
		probe_ttl:    dict = {}   # mac → int       — TTL from ICMP reply (for OS hint)

		def _do_probe(ip, mac, entry, ping_only=False, was_offline=False):
			"""Ping first; if blocked fall back to TCP socket probe (unless ping_only=True).
			Updates _known[mac]['curlPort']. Logs results if Log Ping is enabled.
			Sets probe_source[mac] to "ping(ICMP)" or "tcp:<port>" when the probe succeeds.
			Stores RTT in probe_ms[mac] and TTL in probe_ttl[mac] on ICMP success.

			was_offline=True: device was marked offline before this probe cycle.
			  When the first ICMP ping succeeds for a previously-offline device, a TCP
			  probe is required as confirmation — routers do not proxy TCP.
			"""
			dev_name = names_by_mac.get(mac, mac)
			if ping_only:
				# Use /sbin/ping subprocess — identical to typing ping in a terminal.
				# The raw-socket _ping_extended() path is affected by ARP cache state
				# (proxy-ARP after arp -d -a); the ping binary goes through the same
				# ARP stack but behaves identically to an interactive terminal ping.
				ping_ms_val  = None
				ping_ttl_val = None
				try:
					_pr = subprocess.run(
						[self._exe_ping, "-c", "1", "-W", "1", "-q", ip],
						stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
						timeout=3, text=True)
					ping_ok = (_pr.returncode == 0)
					if ping_ok:
						# Parse RTT from quiet output: "min/avg/max/stddev = X/X/X/X ms"
						_m = re.search(r"=\s*([\d.]+)/", _pr.stdout)
						if _m:
							ping_ms_val = float(_m.group(1))
							probe_ms[mac] = f"{ping_ms_val}ms"

						# Verify the ping was not answered by router proxy-ARP.
						# The ping itself triggers ARP resolution; the ARP cache
						# now holds whatever MAC answered.  If it is not the
						# device's own MAC the router intercepted the request.
						# Use "arp -a" (dump all — no root required on macOS) and
						# search for this IP.  "arp -n <ip>" writes to the routing
						# socket and fails with "Operation not permitted" without sudo.
						# Skip for synthetic MACs (00:00:00:…) and for IPs that
						# are genuinely on a different subnet (arp returns nothing).
						if not mac.startswith("00:00:00:"):
							try:
								_ac = subprocess.run(
									[self._exe_arp, "-a"],
									capture_output=True, timeout=2, text=True)
								_am = None
								for _aline in _ac.stdout.splitlines():
									if ip in _aline:
										_am = re.search(
											r'\bat\s+([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b',
											_aline, re.IGNORECASE)
										if _am:
											break
								if _am and _am.group(1).lower() != mac.lower():
									ping_ok = False
									if log_ping:
										self.indiLOG.log(10,
											f"ping  {dev_name} ({ip})  "
											f"proxy-ARP ({_am.group(1)} ≠ {mac})"
											f" → offline")
							except Exception:
								pass   # if ARP read fails, trust the ping result
				except Exception:
					ping_ok = False
			else:
				ping_ok, ping_ms_val, ping_ttl_val = _ping_extended(ip)
				if ping_ok:
					if ping_ms_val  is not None: probe_ms[mac]  = f"{ping_ms_val}ms"
					if ping_ttl_val is not None: probe_ttl[mac] = ping_ttl_val
			if log_ping:
				ms_str  = f"  {ping_ms_val}ms"      if ping_ms_val  is not None else ""
				ttl_str = f"  ttl={ping_ttl_val}"   if ping_ttl_val is not None else ""
				self.indiLOG.log(10, f"ping  {dev_name} ({ip})  {'ok' if ping_ok else 'fail'}{ms_str}{ttl_str}")
			if ping_ok and (was_offline or ping_only):
				# Guard against false-positive ICMP from router ICMP proxy.
				# Many WiFi APs answer ICMP on behalf of recently-disconnected clients
				# at the MAC level (even arp -s / direct-MAC pings are answered by the
				# AP).  Routers do NOT proxy TCP, so a TCP reply proves the device's own
				# stack is running.
				#
				# For pingOnly this check runs on EVERY probe (not just recovery) because
				# the router proxy keeps ICMP alive for ~2 min after disconnect, preventing
				# the offline threshold from being reached.
				#
				# Adaptive behaviour for pingOnly:
				#   ping_only_tcp_confirmed=True (TCP has worked, e.g. iPhone):
				#     TCP failure → router proxy assumed → probe fails.
				#   ping_only_tcp_confirmed=False AND fail_streak < threshold:
				#     TCP failure → possible IoT (no open ports) → trust ICMP, bump streak.
				#   fail_streak >= _PING_ONLY_TCP_SKIP_THRESHOLD:
				#     skip TCP entirely, trust ICMP (established IoT device).
				#
				# Non-pingOnly: was_offline recovery only, curlUseless/double-ICMP path.
				if ping_only:
					tcp_confirmed   = entry.get("ping_only_tcp_confirmed",   False)
					tcp_fail_streak = entry.get("ping_only_tcp_fail_streak", 0)
					skip_tcp = (not tcp_confirmed
					            and not mac.startswith("00:00:00:")  # never skip TCP for synthetic MACs
					            and tcp_fail_streak >= _PING_ONLY_TCP_SKIP_THRESHOLD)
					if skip_tcp:
						confirm_ok = True
						detail     = "TCP=skipped(IoT)"
					else:
						# rst_counts_alive=False: router RST-proxying for a recently-disconnected
						# client must not count as online confirmation.
						confirm_port = _curl_check(ip, preferred_port=entry.get("curlPort"),
						                           timeout=1.0, rst_counts_alive=False)
						if confirm_port is not None:
							confirm_ok = True
							detail     = f"TCP=port {confirm_port}"
							with self._known_lock:
								_e2 = self._known.setdefault(mac, {})
								_e2["ping_only_tcp_confirmed"]   = True
								_e2["ping_only_tcp_fail_streak"] = 0
						elif tcp_confirmed or mac.startswith("00:00:00:"):
							# tcp_confirmed: TCP worked before, so failure now = proxy-ARP
							# synthetic MAC: no ARP cross-check possible, require TCP always
							confirm_ok = False
							detail     = "TCP=no-response(proxy?)"
						else:
							confirm_ok = True
							detail     = "TCP=no-response(IoT?)"
							with self._known_lock:
								_e2 = self._known.setdefault(mac, {})
								_e2["ping_only_tcp_fail_streak"] = tcp_fail_streak + 1
					if log_ping:
						self.indiLOG.log(10,
							f"ping  {dev_name} ({ip})  tcp-confirm [{detail}] "
							f"{'→ online' if confirm_ok else '→ offline (proxy suppressed)'}"
						)
					self._trace_log(mac, ip, "pingonly-tcp",
						f"ICMP=ok  {detail}  tcp_ever={tcp_confirmed}  "
						f"streak={tcp_fail_streak}  result={'online' if confirm_ok else 'FAIL'}")
				else:
					# Non-pingOnly was_offline recovery: curlUseless / double-ICMP
					use_tcp = entry.get("curlUseless", 0) < _CURL_USELESS_LIMIT
					if use_tcp:
						# rst_counts_alive=False: a TCP RST may come from the router on behalf
						# of an offline client (the router still has the client in its ARP/NAT
						# table for ~60 s after disconnect and sends RST to inbound connections).
						# Only a full TCP handshake (SYN-ACK) proves the device's own stack is
						# running.  With rst_counts_alive=True short offline thresholds trigger
						# false-positive confirmations while the router is still "RST-proxying".
						confirm_port = _curl_check(ip, preferred_port=entry.get("curlPort"),
						                           timeout=1.0, rst_counts_alive=False)
						confirm_ok   = confirm_port is not None
						detail       = f"TCP={'port ' + str(confirm_port) if confirm_port else 'no-response'}"
					elif entry.get("curlPort") is not None:
						# TCP has worked before (curlPort is set) but curlUseless hit the
						# limit — TCP was failing because the device was offline, not
						# because it has no ports.  Do NOT fall back to a second ICMP ping:
						# proxy-ARP routers answer ICMP for offline clients, making a
						# second ICMP unreliable.  TCP failure IS the offline confirmation.
						confirm_ok = False
						detail     = "TCP=no-response(port-known,offline)"
					else:
						# TCP has genuinely never worked for this device (no open ports).
						# Second ICMP is the only fallback; accept the proxy-ARP limitation
						# for pure IoT devices — those should use pingOnly or none mode.
						time.sleep(1.0)
						confirm_ok = _ping(ip)
						detail     = f"2nd-ICMP={'ok' if confirm_ok else 'FAIL'}"
					if log_ping:
						self.indiLOG.log(10,
							f"ping  {dev_name} ({ip})  offline-reconfirm [{detail}] "
							f"{'→ confirmed online' if confirm_ok else '→ kept offline (false-positive suppressed)'}"
						)
					self._trace_log(mac, ip, "ping-recheck",
						f"was_offline=True  ICMP=ok  {detail}  result={'online' if confirm_ok else 'FAIL'}")
				ping_ok = confirm_ok
			if ping_ok:
				probe_source[mac] = "ping(ICMP)"
				with self._known_lock:
					e = self._known.setdefault(mac, {})
					e.setdefault("curlPort", None)
					e["curlUseless"]      = 0
					e["curlPingMismatch"] = 0   # ping works → reset mismatch counter
				return True
			if ping_only:
				return False
			# When was_offline=True the confirmation block above already ran TCP (or
			# double-ICMP) to determine the result.  Return now — falling through to
			# the secondary TCP probe would wrongly increment curlUseless every time
			# the device is genuinely offline, eventually flipping the confirmation
			# fallback to a second ICMP ping which proxy-ARP can fake.
			if was_offline:
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
					# ping failed but TCP succeeded — could be a router answering on behalf
					# of the device (e.g. Draytek proxy-TCP). Track consecutive mismatches.
					mismatch = e.get("curlPingMismatch", 0) + 1
					e["curlPingMismatch"] = mismatch
					if mismatch >= _CURL_USELESS_LIMIT:
						# TCP keeps responding when ping fails — suspend TCP for this device
						e["curlUseless"] = _CURL_USELESS_LIMIT
						self.indiLOG.log(20,
							f"probe {dev_name} ({ip})  TCP suspended: ping/TCP mismatch "
							f"{mismatch}× in a row — router likely answering on device's behalf"
						)
						return False
				else:
					e["curlPingMismatch"] = 0   # TCP also failed → not a proxy issue
			if port is not None:
				probe_source[mac] = f"tcp:{port}"
			return port is not None

		def _check_one(mac, entry):
			if self._stop_event.is_set():
				return
			ip        = entry.get("ip", "")
			last_seen = entry.get("last_seen", 0)
			if not ip:
				# Manually created devices may have an IP set in the Indigo
				# ipNumber state (via "Set IP Address" in device edit) but no
				# entry in _known yet because the device has never been seen by
				# ARP/sniff.  Look it up from the device cache so pingOnly and
				# other active-probe modes can still fire.
				dev_id_early = entry.get("indigo_device_id")
				if dev_id_early:
					# Read from _dev_cache directly under _dev_cache_lock — do NOT
					# call _cache_states() here because that acquires _dev_cache_lock
					# and then we'd acquire _known_lock immediately after.  The correct
					# lock order in this codebase is always _dev_cache_lock FIRST,
					# _known_lock SECOND.  Acquiring them in the opposite order (or
					# nesting) from two different threads causes a deadlock.
					with self._dev_cache_lock:
						_cached_ip = self._dev_cache.get(dev_id_early, {}).get("states", {}).get("ipNumber", "")
					if _cached_ip:
						ip = _cached_ip
						with self._known_lock:
							self._known.setdefault(mac, {})["ip"] = ip
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
				# Use cache — avoids an IPC round-trip for every known device every scan interval
				if not self._cache_enabled(dev_id):
					return   # device disabled in Indigo — skip probe entirely
				props         = self._cache_props(dev_id)
				ping_mode     = props.get("pingMode",         "none")
				offline_logic = props.get("pingOfflineLogic", "and")
				missed_needed = max(1, int(props.get("pingMissedCount", kDefaultPluginPrefs.get("pingMissedCount", "1") )))
				dev_thresh    = int(props.get("offlineThreshold", kDefaultPluginPrefs.get("offlineThreshold", "180") ) )
				if dev_thresh > 0:
					offline_threshold = dev_thresh
				offline_check_interval = int(props.get("offlineCheckInterval", "0") or "0")
				online_check_interval  = int(props.get("onlineCheckInterval",  "0") or "0")
			else:
				offline_check_interval = 0
				online_check_interval  = 0
			# "pingOnly" mode: ICMP-only (no TCP fallback).
			# Kept as its own mode string ("_pingOnly") so it gets dedicated
			# 60 s / 15 s adaptive timing instead of falling into the "both" path.
			if ping_mode == "pingOnly":
				ping_only = True
				ping_mode = "_pingOnly"

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

			# ── sweep-freshness skip ─────────────────────────────────────────
			# The active ARP sweep already confirmed this device within the last
			# (sweep_interval - _SWEEP_FRESHNESS_MARGIN) seconds — no need to probe it again.
			# Only skip when sweep is enabled, the device is currently online,
			# and it was seen recently enough that the sweep result is still fresh.
			# pingOnly devices are excluded: their last_seen is set by ping (not ARP)
			# and they have their own ping_only_next_probe timer below — using the
			# ARP-based freshness window would prevent them from being probed at the
			# correct 60 s / 15 s interval when _check_all_devices runs mid-cycle.
			if (sweep_enabled
					and not ping_only
					and entry.get("online", True)
					and silent_secs < max(sweep_interval - _SWEEP_FRESHNESS_MARGIN, 5)):
				with results_lock:
					results[mac] = (True, last_seen, 0)
				return

			# Whether device is currently offline — passed to _do_probe so it can
			# apply the false-positive double-check when an offline device starts
			# responding to ICMP (some routers proxy ICMP for their ARP-cache neighbours).
			was_offline = not entry.get("online", True)

			# ── per-device offline check interval ────────────────────────────
			# When the device is offline and a custom interval is set, rate-limit
			# probes so we don't hammer the network every scanInterval seconds.
			# _pingOnly has its own adaptive timer; skip this block for that mode.
			if was_offline and offline_check_interval > 0 and ping_mode != "_pingOnly":
				next_probe = entry.get("ping_only_next_probe", 0)
				if now < next_probe:
					with results_lock:
						results[mac] = (False, last_seen, current_streak)
					return

			# ── per-device online ping interval (non-pingOnly modes) ─────────
			# _pingOnly handles its own online timing via ping_only_next_probe.
			# For other active ping modes, when onlineCheckInterval is set, gate
			# online probes via online_check_next_probe so the mid-cycle
			# _check_all_devices calls don't ping a stable device every 15 s.
			if not was_offline and online_check_interval > 0 and ping_mode != "_pingOnly":
				next_online_probe = entry.get("online_check_next_probe", 0)
				if now < next_online_probe:
					with results_lock:
						results[mac] = (True, last_seen, 0)
					return

			# ── pingOnly adaptive mode ────────────────────────────────────────
			# Timing:  60 s when online,  15 s when offline (check more often to
			#          catch recovery quickly).
			# On→Off:  only after offline_threshold expires — one failed ping is
			#          never enough to take the device offline.
			# Off→On:  immediately on the first successful ping.
			if ping_mode == "_pingOnly":
				currently_online = not was_offline
				next_probe = entry.get("ping_only_next_probe", 0)
				if now < next_probe:
					# Not time to probe yet — preserve current state unchanged
					with results_lock:
						results[mac] = (currently_online, last_seen, current_streak)
					return

				# If the ARP sweep already pinged this device within the last
				# _SWEEP_FRESHNESS_MARGIN seconds, skip the dedicated probe — the
				# sweep confirmation counts as the ping for this cycle.  Push the
				# next_probe timer forward so the device is pinged again at the
				# correct interval rather than immediately on the next mid-cycle call.
				if (sweep_enabled and currently_online
						and silent_secs < _SWEEP_FRESHNESS_MARGIN):
					_next = online_check_interval if online_check_interval > 0 else _PING_ONLY_INTERVAL_ONLINE
					with self._known_lock:
						self._known.setdefault(mac, {})["ping_only_next_probe"] = now + _next
					with results_lock:
						results[mac] = (True, last_seen, 0)
					return

				# ── ARP cache seed ───────────────────────────────────────────
				# The sweep calls arp -d -a before every scan, which wipes the
				# entire ARP cache.  A subsequent ping triggers a fresh ARP
				# resolution; the router (which still has the device IP in its
				# own table) answers with proxy-ARP and the ICMP reaches the
				# router instead of the real device — giving a false "ok".
				#
				# Fix: before pinging, plant the device's known real MAC back
				# into the local ARP cache with arp -s.  The ping then goes
				# directly to that MAC on the wire, exactly like a terminal ping
				# typed after the device was last seen.  If the device is off,
				# nothing on the LAN has that MAC and there is no reply.
				# Synthetic MACs (00:00:00:…) have no real L2 address, so skip.
				# The ARP cache is re-seeded with the device's real MAC by
				# _arp_sweep immediately after arp -d -a, so this ping goes
				# to the real device (just like a terminal ping) — no extra
				# ARP manipulation needed here.
				ping_ok = _do_probe(ip, mac, entry, ping_only=True, was_offline=was_offline)

				# Quick-retry on failure — only when OR logic is configured.
				# With AND (default), offline_threshold must also expire before the
				# device can go offline, so a single failed ping is already safe and
				# retrying adds latency with no benefit.
				# With OR, streak alone can trigger offline, so 2 retries 3 s apart
				# confirm the failure before counting it (~6 s total).
				if not ping_ok and currently_online and offline_logic == "or":
					dev_name = names_by_mac.get(mac, mac)
					for _r in range(_PING_RETRY_COUNT):
						if self._stop_event.is_set():
							break
						time.sleep(_PING_RETRY_INTERVAL)
						retry_ok = _ping(ip)
						if log_ping:
							self.indiLOG.log(10,
								f"ping-retry {_r+1}/{_PING_RETRY_COUNT}  {dev_name} ({ip})"
								f"  {'ok' if retry_ok else 'fail'}"
							)
						if retry_ok:
							ping_ok = True
							break

				if ping_ok:
					# Success → online immediately regardless of prior state
					new_online    = True
					new_last_seen = now
					new_streak    = 0
					next_interval = online_check_interval if online_check_interval > 0 else _PING_ONLY_INTERVAL_ONLINE
				else:
					new_streak = current_streak + 1
					if currently_online:
						# Was online, ping failed.
						# Do NOT use timed_out / last_seen here — the ARP sweep can reset
						# last_seen via proxy-ARP even when the device is offline, making the
						# threshold never expire.  Instead track our own probe-success timestamp
						# (ping_only_last_ping_ok) that is only written on a successful dedicated
						# probe, and measure the offline threshold against that.
						# At startup (field missing or 0) default to now so the device doesn't
						# immediately go offline before we've had a chance to probe it.
						last_ping_ok_ts = entry.get("ping_only_last_ping_ok", 0) or now
						ping_probe_timed_out = (now - last_ping_ok_ts) > offline_threshold
						new_online    = not ping_probe_timed_out
						new_last_seen = last_seen
					else:
						# Was already offline, still failing: stay offline
						new_online    = False
						new_last_seen = last_seen
					next_interval = _PING_ONLY_INTERVAL_OFFLINE

				with self._known_lock:
					_e3 = self._known.setdefault(mac, {})
					_e3["ping_only_next_probe"] = now + next_interval
					if ping_ok:
						_e3["ping_only_last_ping_ok"] = now
				with results_lock:
					results[mac] = (new_online, new_last_seen, new_streak)
				return

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
				# timed_out=True: ARP has expired.  Pass was_offline=True so _do_probe
				# runs TCP confirmation after ICMP — ICMP alone is unreliable here
				# because a router doing proxy-ARP can answer for an offline device and
				# macOS does not always cache the proxy ARP entry, making ARP-table
				# checks ineffective.  TCP is never proxied, so a TCP failure is a
				# reliable indicator that the device is genuinely offline.
				ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only, was_offline=True)
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
				with self._known_lock:
					_known_mac = self._known.setdefault(mac, {})
					if was_offline and offline_check_interval > 0:
						_known_mac["ping_only_next_probe"] = now + offline_check_interval
					if not was_offline and online_check_interval > 0 and online:
						_known_mac["online_check_next_probe"] = now + online_check_interval
					if not online:
						# Reset curlUseless so the next offline→online transition uses TCP
						# rather than the second-ICMP fallback (proxy-ARP can fake ICMP).
						_known_mac["curlUseless"] = 0
				with results_lock:
					results[mac] = (online, new_last_seen, new_streak)
				return

			# ── online-only mode ─────────────────────────────────────────────
			# Ping success → online; failure never causes offline.
			if ping_mode == "online":
				ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only, was_offline=was_offline)
				new_online    = True if ping_ok else entry.get("online", True)
				new_last_seen = now  if ping_ok else last_seen
				new_streak    = 0    if ping_ok else current_streak
				with self._known_lock:
					_known_mac = self._known.setdefault(mac, {})
					if was_offline and offline_check_interval > 0:
						_known_mac["ping_only_next_probe"] = now + offline_check_interval
					if not was_offline and online_check_interval > 0 and new_online:
						_known_mac["online_check_next_probe"] = now + online_check_interval
				with results_lock:
					results[mac] = (new_online, new_last_seen, new_streak)
				return

			# ── both / offline modes ─────────────────────────────────────────
			# Ping success always resets streak.
			# Ping failure increments streak; offline decision depends on logic + streak.
			ping_ok = _do_probe(ip, mac, entry, ping_only=ping_only, was_offline=was_offline)

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

			with self._known_lock:
				_known_mac = self._known.setdefault(mac, {})
				if was_offline and offline_check_interval > 0:
					_known_mac["ping_only_next_probe"] = now + offline_check_interval
				if not was_offline and online_check_interval > 0 and online:
					_known_mac["online_check_next_probe"] = now + online_check_interval
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
			deadline = time.time() + _PROBE_POOL_DEADLINE
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
				# Read IP from live _known — _check_one may have populated it from
				# the Indigo ipNumber state for devices with no ARP/sniff history.
				# Fall back to the pre-probe snapshot only when _known has nothing.
				ip = self._known[mac].get("ip", "") or snapshot[mac].get("ip", "")
			# Use the device ID from the snapshot (consistent with what _check_one
			# probed), not from the live _known which a concurrent ARP/sniff thread
			# may have just updated to a different device with the same MAC.
			snap_dev_id = snapshot[mac].get("indigo_device_id")
			src = probe_source.get(mac, "") if online else "probe"
			self._update_indigo_device(mac, ip, online, source=src, dev_id=snap_dev_id)

			# Push ping RTT and TTL-derived OS hint gathered during the probe
			passive = {}
			if mac in probe_ms:
				passive["ping_ms"] = probe_ms[mac]
			if mac in probe_ttl:
				ttl = probe_ttl[mac]
				ttl_os = ("Windows" if ttl == 128
				          else "Linux / Android" if ttl == 64
				          else None)
				if ttl_os:
					# Only set os_hint from TTL when no higher-confidence source has set it
					with self._known_lock:
						existing = self._known.get(mac, {}).get("os_hint", "")
					if not existing:
						passive["os_hint"] = ttl_os
			if passive:
				self._update_passive_info(mac, **passive)

		# ── Auto-promote to pingOnly ────────────────────────────────────────
		# A device that was offline before this cycle and was brought back by
		# a probe (not by passive ARP/tcpdump traffic) is a candidate.
		# If this pattern has persisted for _PING_AUTO_PROMOTE_SECS without any
		# passive confirmation, promote the device to Ping Only mode.
		for mac, (online, _, _) in results.items():
			was_prev_offline = not snapshot[mac].get("online", True)
			if not (online and was_prev_offline and probe_source.get(mac)):
				continue  # not a probe-based revival — skip
			dev_id = snapshot[mac].get("indigo_device_id")
			if dev_id:
				cached_mode = self._cache_props(dev_id).get("pingMode", "confirm")
				if cached_mode in ("pingOnly", "none"):
					continue  # already pingOnly or probing disabled
			with self._known_lock:
				entry = self._known.setdefault(mac, {})
				if entry.get("ping_found_offline_at", 0) == 0:
					entry["ping_found_offline_at"] = now
				elif now - entry["ping_found_offline_at"] >= _PING_AUTO_PROMOTE_SECS:
					entry["ping_auto_promote"] = True

		# Execute any pending promotions in the main thread (Indigo IPC must be main-thread)
		for mac in list(self._known.keys()):
			with self._known_lock:
				should_promote = self._known.get(mac, {}).pop("ping_auto_promote", False)
			if should_promote:
				self._auto_promote_ping_only(mac)

	###----------------------------------------------------------###
	def _auto_promote_ping_only(self, mac: str):
		"""Set pingMode=pingOnly on the Indigo device for mac.

		Called when a device has been offline-but-responds-to-ping for
		_PING_AUTO_PROMOTE_SECS without any passive ARP/tcpdump confirmation,
		indicating it does not participate in normal LAN traffic.
		"""
		with self._known_lock:
			entry      = self._known.get(mac, {})
			dev_id     = entry.get("indigo_device_id")
			first_seen = entry.get("ping_found_offline_at", 0)
			elapsed    = (time.time() - first_seen) if first_seen else 0
			entry["ping_found_offline_at"] = 0   # reset timer
		if not dev_id:
			return
		try:
			dev      = indigo.devices[dev_id]
			props    = dict(dev.pluginProps)
			old_mode = props.get("pingMode", "confirm")
			if old_mode in ("pingOnly", "none"):
				return   # already correct or user disabled probing
			props["pingMode"] = "pingOnly"
			dev.replacePluginPropsOnServer(props)
			self.indiLOG.log(20,
				f"Auto-set Ping Only: {dev.name} ({mac}) — offline but responded to "
				f"ping for {int(elapsed)}s with no ARP/tcpdump traffic. "
				f"Ping mode: {old_mode!r} → 'pingOnly'."
			)
		except Exception as e:
			self.indiLOG.log(30, f"_auto_promote_ping_only failed for {mac}: {e}")

	###----------------------------------------------------------###
	def _next_synthetic_mac(self) -> str:
		"""Return the lowest unused 00:00:00:00:00:XX MAC address.

		Used when a device responds to ping during an ARP sweep but has no
		ARP entry (and is therefore unknown by a real hardware MAC address).
		"""
		with self._known_lock:
			used = {
				int(mac.rsplit(":", 1)[-1], 16)
				for mac in self._known
				if mac.startswith("00:00:00:00:00:")
			}
		n = 1
		while n in used:
			n += 1
		return f"00:00:00:00:00:{n:02x}"

	# ------------------------------------------------------------------
	# Device registry
	# ------------------------------------------------------------------

	# ------------------------------------------------------------------
	# ------------------------------------------------------------------
	# Aggregate group devices  (HOME_AWAY / ONLINE)
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
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
		if not self._cache_enabled(dev.id):
			return   # aggregate device disabled in Indigo — skip recalc

		typeId    = self._cache_type(dev.id) or dev.deviceTypeId
		slots     = 6 if typeId == HOME_AWAY else 3
		count_key = "ParticipantsHome" if typeId == HOME_AWAY else "ParticipantsOnline"
		props     = self._cache_props(dev.id) or dev.pluginProps

		participants = [
			props.get(f"watchDevice{i}", "").strip()
			for i in range(1, slots + 1)
		]
		participants = [p for p in participants if p and p not in ("", "0")]

		online_count   = 0
		participant_names = []
		for pid in participants:
			try:
				pid_int = int(pid)
				# Use cache for onOffState and name — avoids IPC on every group recalc
				cached_states = self._cache_states(pid_int)
				if cached_states:
					participant_names.append(self._cache_name(pid_int) or pid)
					if bool(cached_states.get("onOffState", False)):
						online_count += 1
				else:
					# Fallback to live IPC if not cached (e.g. non-plugin device in list)
					pdev = indigo.devices[pid_int]
					participant_names.append(pdev.name)
					if bool(pdev.states.get("onOffState", False)):
						online_count += 1
			except Exception:
				participant_names.append(pid)   # fallback: show raw ID if device not found

		raw_online = online_count > 0   # True = at least one home/online
		prev_state = self._cache_states(dev.id).get("onOffState", None)

		# ── Off-delay logic (HOME_AWAY only) ─────────────────────────────────
		# When all participants are offline and offDelay > 0, hold the OFF
		# transition until the delay has expired.  Any participant coming back
		# online during the delay cancels the pending OFF immediately.
		if typeId == HOME_AWAY:
			off_delay = int(props.get("offDelay", 0) or 0)
			_now = time.time()
			if raw_online:
				# Someone is home → cancel any pending off and go ON immediately
				self._home_away_pending_off.pop(dev.id, None)
				new_state = True
			elif off_delay <= 0:
				# No delay configured — apply OFF immediately
				self._home_away_pending_off.pop(dev.id, None)
				new_state = False
			else:
				# All offline — start or check the pending-off countdown
				pending_ts = self._home_away_pending_off.get(dev.id)
				if pending_ts is None:
					# First cycle all-offline: start the countdown, keep current state
					self._home_away_pending_off[dev.id] = _now
					new_state = bool(prev_state) if prev_state is not None else False
				elif (_now - pending_ts) >= off_delay:
					# Countdown expired — apply OFF and clear entry
					self._home_away_pending_off.pop(dev.id, None)
					new_state = False
				else:
					# Still within delay window — keep current state
					new_state = bool(prev_state) if prev_state is not None else False
		else:
			new_state = raw_online

		# ── Call 1: critical states (onOffState + lastOnOffChange) ──────────
		# These always exist — safe to batch together.
		if prev_state is None or bool(prev_state) != new_state:
			ts = _now_str()
			_u1 = [
				{"key": "onOffState",      "value": new_state,
				 "uiValue": f"{'on' if new_state else 'off'}  {ts}"},
				{"key": "lastOnOffChange", "value": ts},
			]
			try:
				dev.updateStatesOnServer(_u1)
				self._cache_patch_states(dev.id, _u1)   # keep cache in sync
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"Group device state update failed for {dev.name}: {e}")

		# ── Call 2: count + participants states ─────────────────────────────
		# Silently skipped if states are not yet registered (device hasn't
		# restarted since the plugin was last upgraded).
		participants_str     = ",".join(participants)
		_cached_dev_states   = self._cache_states(dev.id)
		count_changed        = _cached_dev_states.get(count_key,     -1)  != online_count
		participants_changed = _cached_dev_states.get("participants", "") != participants_str
		if count_changed or participants_changed:
			updates2 = []
			if count_changed:
				updates2.append({"key": count_key,      "value": online_count})
			if participants_changed:
				updates2.append({"key": "participants", "value": participants_str})
			try:
				dev.updateStatesOnServer(updates2)
				self._cache_patch_states(dev.id, updates2)   # keep cache in sync
			except Exception:
				pass   # states not yet defined — will appear after next plugin restart

		# ── Address + Notes columns for HOME_AWAY ───────────────────────────────
		# Respects the flipAddressNotes pref:
		#   OFF (default): Address = MACs,  Notes = "prefix - last-octets"
		#   ON:            Address = IPs,   Notes = MACs (space-separated)
		# Updated on every recalc so both columns always reflect current state.
		# ONLINE devices have watched hosts in Address; their Notes are left to the user.
		if typeId == HOME_AWAY and participants:
			_flip_cols = self.pluginPrefs.get("flipAddressNotes", False)
			_flip_cols = (_flip_cols is True) or (str(_flip_cols).lower() == "true")
			try:
				macs = []
				ips  = []
				for pid in participants:
					try:
						pid_int = int(pid)
						cached  = self._cache_states(pid_int)
						mac_val = cached.get("MACNumber", "") if cached else indigo.devices[pid_int].states.get("MACNumber", "")
						ip_val  = cached.get("ipNumber",  "") if cached else indigo.devices[pid_int].states.get("ipNumber",  "")
						if mac_val:
							macs.append(mac_val)
						if ip_val and ip_val not in ("0.0.0.0", ""):
							ips.append(ip_val)
					except Exception:
						pass

				# Helper: compress a list of IPs to "prefix last1 last2 …" when all share
				# the same /24 prefix, otherwise fall back to space-separated full IPs.
				def _compress_ips(ip_list):
					parts    = [ip.rsplit(".", 1) for ip in ip_list]
					prefixes = [p[0] + "." for p in parts if len(p) == 2]
					if prefixes and len(set(prefixes)) == 1:
						octets = " ".join(p[1] for p in parts if len(p) == 2)
						return f"{prefixes[0]} {octets}"
					return "  ".join(ip_list)

				# Address column
				if _flip_cols:
					addr_desired = _compress_ips(ips) if ips else ""
				else:
					addr_desired = "  ".join(macs)
				current_addr = self._cache_props(dev.id).get("address", "")
				if addr_desired and addr_desired != current_addr:
					new_props = dict(props)
					new_props["address"] = addr_desired
					dev.replacePluginPropsOnServer(new_props)
					self._cache_patch_props(dev.id, new_props)

				# Notes (description) column
				if _flip_cols:
					_desc = "  ".join(macs)
				else:
					if ips:
						parts    = [ip.rsplit(".", 1) for ip in ips]
						prefixes = [p[0] + "." for p in parts if len(p) == 2]
						prefix   = prefixes[0] if len(set(prefixes)) == 1 else ""
						octets   = " ".join(p[1] for p in parts if len(p) == 2)
						_desc    = f"{prefix} - {octets}" if prefix else octets
					else:
						_desc = ""
				if _desc and _desc != self._cache_description(dev.id).strip():
					dev.description = _desc
					dev.replaceOnServer()
					self._cache_set_description(dev.id, _desc)
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"Could not update address/notes for {dev.name}: {e}")

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _check_external_devices(self):
		"""Ping (+ TCP fallback) all registered externalDevice entries and update their onOffState."""
		now = time.time()
		for dev_id, info in list(self._ext_devices.items()):
			if self._stop_event.is_set():
				break
			host = info.get("host", "").strip()
			if not host:
				continue

			# Honour per-device ping interval — read from cache, no IPC needed for skip decision
			interval = int(self._cache_props(dev_id).get("pingInterval", 60))
			if now - info.get("last_ping", 0) < interval:
				continue
			info["last_ping"] = now

			# Only fetch live device now that we know we're going to ping and potentially write
			try:
				dev = indigo.devices[dev_id]
			except Exception:
				continue

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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _internet_address_loop(self, dev_id: int, stop_ev: threading.Event):
		"""Background loop: fetch public IP, sleep, repeat until stop_ev is set."""
		# Fetch immediately on start
		self._update_internet_address_device(dev_id)
		while True:
			# Use cache — avoids IPC on every wait-cycle iteration
			interval = int(self._cache_props(dev_id).get("checkInterval", "300") or 300)
			if stop_ev.wait(timeout=interval):
				break   # stop_ev set — device stopped or plugin shutting down
			self._update_internet_address_device(dev_id)

	###----------------------------------------------------------###
	def _update_internet_address_device(self, dev_id: int):
		"""Fetch the public IP and push any changed values to the Indigo device.
		All reads are local (cache). Live device object is only fetched at write time.
		"""
		if not self._cache_enabled(dev_id):
			return

		alive, ip  = _fetch_public_ip()
		now        = _now_str()
		_cs        = self._cache_states(dev_id)
		prev_ip    = _cs.get("publicIp",   "")
		was_online = bool(_cs.get("onOffState", None))

		state_updates = []

		onoff_str  = "on" if alive else "off"
		# IP to display: new IP when alive, otherwise last known IP
		display_ip = ip if (alive and ip) else prev_ip

		# Always stamp the appropriate timestamp regardless of other changes
		if alive:
			state_updates.append({"key": "lastSuccessfulUpdate", "value": now})
		else:
			state_updates.append({"key": "lastFailedUpdate", "value": now})

		# online/offline flip
		# IP changed (only meaningful when fetch succeeded)
		ip_changed = alive and bool(ip) and ip != prev_ip
		first_ip   = alive and not prev_ip and bool(ip)

		if ip_changed:
			if prev_ip:
				state_updates.append({"key": "previousIp", "value": prev_ip})
			state_updates.append({"key": "lastChanged", "value": now})
			self.indiLOG.log(20, f"Public IP changed: {prev_ip or '(none)'} → {ip}")

		# Write onOffState whenever online status or IP changes.
		# uiValue includes the current IP so the device-list State column shows
		# "on   203.0.113.42" / "off   203.0.113.42" alongside the on/off icon.
		if alive != was_online or ip_changed or first_ip:
			ui = f"{onoff_str}   {display_ip}" if display_ip else onoff_str
			state_updates.append({"key": "onOffState", "value": alive, "uiValue": ui})

		# publicIp: bare IP value for triggers/scripts; written whenever IP changes.
		if (ip_changed or first_ip) and display_ip:
			state_updates.append({"key": "publicIp", "value": display_ip})

		# Fetch live device only now — purely for writing
		try:
			dev = indigo.devices[dev_id]
		except Exception:
			return
		try:
			dev.updateStatesOnServer(state_updates)
			self._cache_patch_states(dev_id, state_updates)
			# Keep Address column and Notes in sync with the current public IP
			if alive and ip:
				props_changed = False
				new_props = dict(dev.pluginProps)
				if new_props.get("address", "") != ip:
					new_props["address"] = ip
					props_changed = True
				if props_changed:
					dev.replacePluginPropsOnServer(new_props)
					self._cache_patch_props(dev_id, new_props)
				if self._cache_description(dev_id) != ip:
					dev.description = ip
					dev.replaceOnServer()
					self._cache_set_description(dev_id, ip)
		except Exception as e:
			if "None" not in str(e):
				self.indiLOG.log(30, f"internetAddress update failed for {self._cache_name(dev_id)}: {e}")

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _ext_update_state(self, dev, info: dict, host: str,
	                      resolved_ip: str, alive: bool, ms):
		"""Apply ping result to one externalDevice: update fail streak, flip state if needed."""
		# All reads from cache — no IPC snapshot reads
		_cached_s     = self._cache_states(dev.id)
		_cached_p     = self._cache_props(dev.id)
		missed_needed = int(_cached_p.get("pingMissedCount", kDefaultPluginPrefs.get("pingMissedCount", "1")))
		if alive:
			info["fail_streak"] = 0
		else:
			info["fail_streak"] = info.get("fail_streak", 0) + 1

		prev_online = bool(_cached_s.get("onOffState", False))
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
				self.indiLOG.log(10, f"{self._cache_name(dev.id)} ({host}) is now {status}")
			updates += [
				{"key": "onOffState",     "value": new_online,
				 "uiValue": f"{'on' if new_online else 'off'}  {_now_str()}"},
				{"key": "lastOnOffChange","value": _now_str()},
			]

		if resolved_ip and _cached_s.get("ipNumber", "") != resolved_ip:
			updates.append({"key": "ipNumber", "value": resolved_ip})
			# Keep Address / Notes columns in sync when IP changes.
			# flipAddressNotes OFF (default): Address = host, Notes = IP
			# flipAddressNotes ON:            Address = IP,   Notes = host
			try:
				_flip_ext = self.pluginPrefs.get("flipAddressNotes", False)
				_flip_ext = (_flip_ext is True) or (str(_flip_ext).lower() == "true")
				_padded   = _ip_for_notes(resolved_ip)
				if _flip_ext:
					# Address column carries the IP — update it
					_eprops = dict(self._cache_props(dev.id))
					if _eprops.get("address", "") != _padded:
						_eprops["address"] = _padded
						dev.replacePluginPropsOnServer(_eprops)
						self._cache_patch_props(dev.id, _eprops)
				else:
					# Notes column carries the IP — update description
					if self._cache_description(dev.id) != _padded:
						dev.description = _padded
						dev.replaceOnServer()
						self._cache_set_description(dev.id, _padded)
			except Exception:
				pass

		ping_str = f"{ms} ms" if ms is not None else ("timeout" if not alive else "")
		if ping_str and _cached_s.get("pingMs", "") != ping_str:
			# Only push pingMs when RTT differs by > 40% AND > 20 ms.
			_old_ping = _cached_s.get("pingMs", "")
			_skip = False
			if ping_str not in ("", "timeout") and _old_ping not in ("", "timeout"):
				try:
					_new_ms = float(ping_str.rstrip(" ms"))
					_old_ms = float(_old_ping.rstrip(" ms"))
					if _old_ms > 0:
						if abs(_new_ms - _old_ms) / _old_ms < 0.40 or abs(_new_ms - _old_ms) <= 20:
							_skip = True
				except (ValueError, ZeroDivisionError):
					pass
			if not _skip:
				updates.append({"key": "pingMs", "value": ping_str})

		if updates:
			try:
				dev.updateStatesOnServer(updates)
				self._cache_patch_states(dev.id, updates)
			except Exception as e:
				if f"{e}".find("None") == -1:
					self.indiLOG.log(30, f"External device state update failed for {self._cache_name(dev.id)}: {e}")

		# ── Update aggregate ONLINE group devices ──────────────────────────
		if new_online != prev_online:
			self._update_group_devices(dev.id)

	# ------------------------------------------------------------------

	###----------------------------------------------------------###
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
			entry.setdefault("name",             "")    # backfill for entries added before name existed
			entry.setdefault("curlPort",         None)  # last curl port that responded
			entry.setdefault("curlUseless",      0)     # consecutive all-port curl failures
			entry.setdefault("curlPingMismatch", 0)     # consecutive ping-fail/TCP-success (router proxy detection)
			entry.setdefault("is_ap_or_router",  False) # True when device does proxy-ARP for others
			entry["ip"] = ip
			if clear_local_name:                    # proxy-ARP AP: mark and wipe stale client name
				entry["is_ap_or_router"] = True
				entry["local_name"]        = ""
				entry["arp_name"]          = ""
				entry["local_name_source"] = ""
			elif local_name:
				entry["arp_name"] = local_name
				# localName = mDNS name if known, else ARP name
				if not entry.get("mdns_name"):
					entry["local_name"]        = local_name
					entry["local_name_source"] = "arp"
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

	###----------------------------------------------------------###
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

		# ── pingOnly pre-check ────────────────────────────────────────────────
		# Lock ordering: _dev_cache_lock must be acquired BEFORE _known_lock.
		# We therefore read the device ID outside the main lock, then look up
		# the pingMode from the cache (which acquires _dev_cache_lock internally).
		# pingOnly devices own their own online / last_seen state; the ARP sweep
		# must NOT overwrite it or the offline threshold can never trigger.
		_pre_dev_id = None
		with self._known_lock:
			_pre_dev_id = self._known.get(mac, {}).get("indigo_device_id")
		is_ping_only_mac = False
		if _pre_dev_id:
			is_ping_only_mac = (self._cache_props(_pre_dev_id).get("pingMode") == "pingOnly")

		with self._known_lock:
			entry      = self._known.get(mac, {})
			entry.setdefault("history",         [])    # ensure key present on every entry
			entry.setdefault("ip_history",      [])    # list of IP changes: [{ts, old_ip, new_ip}]
			entry.setdefault("ip_change_times", [])    # epoch list for AP/router auto-detection
			entry.setdefault("local_name",       "")    # ensure key present on every entry
			entry.setdefault("name",             "")    # ensure key present on every entry
			entry.setdefault("curlPort",         None)  # last curl port that responded
			entry.setdefault("curlUseless",      0)     # consecutive all-port curl failures
			entry.setdefault("curlPingMismatch", 0)     # consecutive ping-fail/TCP-success (router proxy detection)
			entry.setdefault("last_indigo_push", 0)    # epoch of last _ensure_indigo_device call
			entry.setdefault("is_ap_or_router",  False) # True when device does proxy-ARP for others
			# Passive traffic confirmation resets the ping-revival timer — the device is
			# reachable via normal ARP/tcpdump, so auto-promote to pingOnly is not needed.
			if "tcpdump" in source or source == "sweep (arp)":
				entry.pop("ping_found_offline_at", None)
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
			if not is_ping_only_mac:
				# pingOnly devices manage their own online / last_seen state via
				# the dedicated ICMP probe.  The ARP sweep must not reset those
				# fields or the offline threshold can never trigger (router keeps
				# the IP in its ARP cache and answers ICMP on the phone's behalf).
				entry["last_seen"]     = now
				entry["last_seen_str"] = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
				entry["online"]        = True
			if clear_local_name:                  # proxy-ARP AP: mark and wipe stale client name
				entry["is_ap_or_router"] = True
				entry["local_name"]        = ""
				entry["arp_name"]          = ""
				entry["local_name_source"] = ""
			elif local_name:
				entry["arp_name"] = local_name
				if not entry.get("mdns_name"):
					entry["local_name"]        = local_name
					entry["local_name_source"] = "arp"
			if "vendor" not in entry:
				entry["vendor"] = self.get_vendor(mac)
			self._known[mac] = entry

		# Read per-device log options (dev may not exist yet for brand-new MACs)
		suppress_ip_log  = False
		log_seen_to_file = False
		dev_id = entry.get("indigo_device_id")
		if dev_id:
			# Use cache — this path is hit on every sniff/ARP packet for known devices
			cached_props     = self._cache_props(dev_id)
			suppress_ip_log  = bool(cached_props.get("suppressIpChangeLog", False))
			log_seen_to_file = bool(cached_props.get("logSeenToFile",        False))

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

		# Detailed trace for the specifically-watched device (placed here so skip_push is defined)
		self._trace_log(mac, ip, "_register_device",
			f"source={source!r}  changed_ip={changed_ip}  old_ip={old_ip!r}  "
			f"local_name={local_name!r}  skip_push={skip_push}")

		if not skip_push:
			with self._known_lock:
				self._known.setdefault(mac, {})["last_indigo_push"] = now  # record push time
			self._ensure_indigo_device(mac, ip, entry["vendor"], True,
			                           local_name=entry.get("local_name", ""),
			                           clear_local_name=clear_local_name,
			                           update_online=not is_ping_only_mac,
			                           source=source)

	###----------------------------------------------------------###
	def _ensure_indigo_device(self, mac: str, ip: str, vendor: str, online: bool, local_name: str = "", clear_local_name: bool = False, update_online: bool = True, source: str = ""):
		"""Create the Indigo device if it doesn't exist, then update its states.

		update_online=False: skip the onOffState update (used by _discover_device for
		stale ARP-cache entries that were NOT ping-confirmed — prevents ghost ON transitions).
		source: what set the device online ("sweep (arp)", "traffic observed (tcpdump)", "ping(ICMP)", "tcp:port"); stored in setOnBy state.
		"""
		dev_name = _mac_to_device_name(mac, vendor, local_name=local_name, prefixName = self._getPrefixName())

		# Fast path: look up cached device ID stored in _known.
		# If that ID is present in _dev_cache the device exists — no IPC needed.
		# Falls back to a full linear scan only for new MACs or after device recreation.
		existing_id = None
		with self._known_lock:
			existing_id = self._known.get(mac, {}).get("indigo_device_id")

		if existing_id:
			with self._dev_cache_lock:
				in_cache = existing_id in self._dev_cache
			if not in_cache:
				# Cache miss — device may have been recreated; repopulate and verify
				try:
					_dev = indigo.devices[existing_id]
					self._cache_put(_dev)
				except Exception:
					existing_id = None   # device was deleted externally
					# Also clear the stale ID from _known so the sentinel check below
					# does not mistake it for an in-progress creation and return early.
					with self._known_lock:
						entry = self._known.get(mac, {})
						if entry.get("indigo_device_id") not in (None, -1):
							entry.pop("indigo_device_id", None)

		if existing_id is None:
			# Fallback: scan all plugin devices (covers new MACs and deleted/re-created devices)
			for dev in indigo.devices.iter(PLUGIN_ID):
				if self._cache_states(dev.id).get("MACNumber", "").lower() == mac.lower() \
				   or dev.states.get("MACNumber", "").lower() == mac.lower():
					existing_id = dev.id
					self._cache_put(dev)
					with self._known_lock:
						self._known.setdefault(mac, {})["indigo_device_id"] = dev.id
					break

		if existing_id is None and self.pluginPrefs.get("autoCreateDevices", kDefaultPluginPrefs["autoCreateDevices"]):
			# Never create a synthetic-MAC device (00:00:00:00:00:XX) unless the user
			# has explicitly opted in.  This is the single authoritative gate — it
			# covers every code path (new creation, existing-synth refresh, etc.)
			# so that no synthetic device can be created regardless of how
			# _ensure_indigo_device was reached.
			is_synthetic = mac.lower().startswith("00:00:00:00:00:")
			synthetic_ok = self.pluginPrefs.get("syntheticDevicesEnabled", kDefaultPluginPrefs["syntheticDevicesEnabled"])
			if is_synthetic and not synthetic_ok:
				return   # synthetic devices disabled — do not create or update

			# Skip creating brand-new devices during the startup grace period.
			# ARP/tcpdump have not had enough time to populate _known from the saved
			# state; phantom MACs from proxy-ARP routers or one-shot probe frames
			# would otherwise get permanent Indigo devices.  Existing devices are
			# still updated above; only genuinely-new MACs are deferred until after
			# the grace period clears.
			if not self.in_grace_period:
				# Claim this MAC atomically before calling Indigo so a second
				# thread (e.g. secondary-interface sweep) racing here finds the
				# sentinel and exits without creating a duplicate device.
				_SENTINEL = -1
				with self._known_lock:
					if self._known.get(mac, {}).get("indigo_device_id") is not None:
						return   # another thread already created or is creating it
					self._known.setdefault(mac, {})["indigo_device_id"] = _SENTINEL
				new_dev = self._create_indigo_device(mac, ip, vendor, dev_name)
				if new_dev:
					existing_id = new_dev.id
					with self._known_lock:
						self._known.setdefault(mac, {})["indigo_device_id"] = new_dev.id
				else:
					# Creation failed — clear sentinel so next sweep can retry
					with self._known_lock:
						entry = self._known.get(mac, {})
						if entry.get("indigo_device_id") == _SENTINEL:
							entry.pop("indigo_device_id", None)

		if existing_id is not None:
			if not self._cache_enabled(existing_id):
				return   # device disabled in Indigo — leave all states untouched
			with self._known_lock:
				is_ap = bool(self._known.get(mac, {}).get("is_ap_or_router", False))
			self._update_indigo_device_states(existing_id, mac, ip, vendor, online, local_name=local_name,
			                                  clear_local_name=clear_local_name, is_ap_or_router=is_ap,
			                                  update_online=update_online, source=source)

	###----------------------------------------------------------###
	def _create_indigo_device(self, mac: str, ip: str, vendor: str, name: str):
		"""Create a brand-new Indigo networkDevice."""
		# Synthetic MACs (00:00:00:00:00:XX) are ping-only hosts with no ARP presence —
		# set pingMode at creation so the device is never probed as a normal ARP device.
		is_synthetic = mac.lower().startswith("00:00:00:00:00:")
		props = {
			"address":          mac,    # shows in Indigo device list Address column
			"pingMode":         "pingOnly" if is_synthetic else "confirm",
			"offlineThreshold": "0",    # 0 = use plugin-wide default
		}
		folder_id = self._get_or_create_folder()
		try:
			# Resolve any name collision — use indigo.devices.iter(filter="") to include
			# disabled devices, which Indigo still enforces uniqueness for.
			_all_names   = {d.name for d in indigo.devices.iter(filter="")}
			_create_name = name
			_suffix      = 0
			while _create_name in _all_names:
				_suffix     += 1
				_create_name = f"{name} ({_suffix})"
			try:
				_flip        = self.pluginPrefs.get("flipAddressNotes", False)
				_padded_ip   = _ip_for_notes(ip)
				new_dev = indigo.device.create(
					protocol     = indigo.kProtocol.Plugin,
					name         = _create_name,
					description  = mac if _flip else _padded_ip,   # Notes column
					pluginId     = PLUGIN_ID,
					deviceTypeId = DEVICE_TYPE_ID,
					props        = props,
					folder       = folder_id,
				)
			except ValueError as ve:
				if "NameNotUniqueError" not in str(ve):
					raise
				# Race condition or disabled-device blind spot: a device with this name
				# already exists.  Find it and reuse it rather than failing.
				new_dev = next(
					(d for d in indigo.devices.iter(filter="") if d.name == _create_name),
					None
				)
				if new_dev is None:
					raise   # genuinely can't find it — re-raise original error
				self.indiLOG.log(20,
					f"Device '{_create_name}' already existed (name collision) — reusing id {new_dev.id}"
				)
				with self._known_lock:
					self._known.setdefault(mac, {})["indigo_device_id"] = new_dev.id
				return new_dev
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

	###----------------------------------------------------------###
	def _update_indigo_device_states(self, dev_id: int, mac: str, ip: str, vendor: str, online: bool, local_name: str = "", clear_local_name: bool = False, is_ap_or_router: bool = False, update_online: bool = True, source: str = ""):
		"""Push only changed state values into an existing Indigo device.

		All reads come from the local cache — no IPC until we know something needs
		writing.  The live device object is fetched only if there are actual updates
		to push, making the common "nothing changed" path completely IPC-free.

		lastOnOffChange is only written when the online/offline value flips.
		last_seen (last ARP/ping ok epoch) lives only in _known — never pushed
		to Indigo, so routine scan hits produce zero device updates.
		localName is the mDNS/Bonjour hostname from arp -a; only updated when non-empty
		so a previously discovered name is never erased by a sniff-thread update.
		clear_local_name=True overrides that guard and explicitly blanks a stale name
		(used when a proxy-ARP AP's winner entry has no hostname of its own).
		"""
		# ── All change-detection reads come from the local cache (no IPC) ──
		cached          = self._cache_states(dev_id)
		prev_online     = cached.get("onOffState",     None)
		prev_ip         = cached.get("ipNumber",       "")
		prev_mac        = cached.get("MACNumber",      "")
		prev_vendor     = cached.get("hardwareVendor", "")
		prev_created    = cached.get("created",        "")
		prev_is_ap       = bool(cached.get("isApOrRouter", False))
		prev_arp_hostname = cached.get("arpHostname",    "")

		online_changed     = update_online and ((prev_online is None) or (bool(prev_online) != online))
		ip_changed         = prev_ip     != ip
		mac_changed        = prev_mac    != mac
		vendor_changed     = prev_vendor != vendor
		created_needed     = not prev_created
		local_name_changed = False   # localName removed as Indigo state; local_name is internal only
		# arp_name comes in via the local_name parameter when source is arp -a
		with self._known_lock:
			arp_name = self._known.get(mac, {}).get("arp_name", "")
		arp_hostname_changed = bool(arp_name) and arp_name != prev_arp_hostname

		# AP/router auto-detection is done in _register_device (before the throttle).
		# Here we just pick up whatever is_ap_or_router was passed in / already stored.
		ap_changed         = is_ap_or_router != prev_is_ap

		# lastOnMessage: throttled to once per minute while device is online.
		# Must be evaluated BEFORE the early-return guard so a "nothing else changed"
		# cycle doesn't silently skip the update.
		_now_epoch      = time.time()
		last_on_msg_due = (self._cache_type(dev_id) == DEVICE_TYPE_ID and online
		                   and (_now_epoch - self._last_on_msg_ts.get(dev_id, 0) >= 60))

		if not any([online_changed, ip_changed, mac_changed, vendor_changed, created_needed,
		            local_name_changed, arp_hostname_changed, ap_changed, last_on_msg_due]):
			return   # nothing to update — zero IPC calls

		dev_name = self._cache_name(dev_id)

		if online_changed and self.decideMyLog("StateChange"):
			status = "ONLINE" if online else "OFFLINE"
			if not online:
				entry         = self._known.get(mac, {})
				last_seen_str = entry.get("last_seen_str", "")
				last_seen_ts  = entry.get("last_seen", 0)
				ago           = f"  =  {int(time.time() - last_seen_ts)}s ago" if last_seen_ts else ""
				suffix        = f"  (last seen: {last_seen_str}{ago})" if last_seen_str else ""
				src_str       = f"  [{source}]" if source else ""
			else:
				suffix  = ""
				src_str = f"  via {source}" if source else ""
			self.indiLOG.log(10, f"{dev_name} ({ip}) is now {status}{suffix}{src_str}")

		# Detailed trace for any device that matches debugTrackedDevice
		self._trace_log(mac, ip, "_state_update",
			f"online_changed={online_changed}  online={online}  source={source!r}  "
			f"ip_changed={ip_changed}  mac={mac}")

		state_updates = []
		if online_changed:
			ts = _now_str()
			state_updates.append({
				"key":     "onOffState",
				"value":   online,
				"uiValue": f"{'on' if online else 'off'}  {ts}",
			})
			state_updates.append({"key": "lastOnOffChange", "value": ts})
			if online:
				state_updates.append({"key": "changeToOn",  "value": ts})
				if source:
					state_updates.append({"key": "setOnBy", "value": source})
			else:
				state_updates.append({"key": "changeToOff", "value": ts})
				if source:
					state_updates.append({"key": "setOffBy", "value": source})
			# Append to the rolling on/off history kept in _known (last 10 events).
			# This is stored in our own JSON state file, not in Indigo device states,
			# so it survives device deletions and plugin reinstalls.
			with self._known_lock:
				entry   = self._known.get(mac, {})
				history = entry.get("history", [])
				history.append({"ts": ts, "state": "on" if online else "off"})
				entry["history"] = history[-10:]   # cap at 10 entries
				entry["name"]    = dev_name        # keep _known name in sync with cache
				self._known[mac] = entry
		if ip_changed:
			state_updates.append({"key": "ipNumber",   "value": ip})
			# Build previousIps from ip_history — most-recent first, last 10 entries
			with self._known_lock:
				ip_hist = list(self._known.get(mac, {}).get("ip_history", []))
			if ip_hist:
				prev_str = "  |  ".join(
					f"{r['old_ip']}  ({r['ts'][:10]})"
					for r in reversed(ip_hist[-10:])
				)
				state_updates.append({"key": "previousIps", "value": prev_str})
		if mac_changed:
			state_updates.append({"key": "MACNumber",  "value": mac})
		if vendor_changed:
			state_updates.append({"key": "hardwareVendor",  "value": vendor})
		if created_needed:
			state_updates.append({"key": "created",     "value": _now_str()})
		if arp_hostname_changed:
			state_updates.append({"key": "arpHostname", "value": arp_name})
		if ap_changed:
			state_updates.append({"key": "isApOrRouter", "value": is_ap_or_router})

		# ── lastOnMessage + setOnBy: update when online, throttled to once per minute ──
		if last_on_msg_due:
			self._last_on_msg_ts[dev_id] = _now_epoch
			ts_short = time.strftime("%Y-%m-%d %H:%M", time.localtime(_now_epoch))
			state_updates.append({"key": "lastOnMessage", "value": ts_short})
			if source:
				state_updates.append({"key": "setOnBy", "value": source})

		# ── IPC write — only reached when something actually changed ──────
		try:
			dev = indigo.devices[dev_id]
		except Exception:
			return

		# Guard: Indigo raises "state value updating of plugin devices is private"
		# when updateStatesOnServer is called on a device owned by a different plugin
		# (e.g. a device originally created by fingscan that was imported/migrated).
		# Skip silently — we can only manage our own devices.
		if getattr(dev, "pluginId", None) != PLUGIN_ID:
			self.indiLOG.log(20,
				f"Skipping state update for {dev.name}: device belongs to "
				f"plugin {getattr(dev, 'pluginId', '?')!r}, not {PLUGIN_ID!r}"
			)
			return

		try:
			dev.updateStatesOnServer(state_updates)
			self._cache_patch_states(dev_id, state_updates)

			# Sync props only when relevant values changed
			new_props     = dict(self._cache_props(dev_id))   # read from cache, not dev.pluginProps
			_flip     = self.pluginPrefs.get("flipAddressNotes", False)
			_addr_val = _ip_for_notes(ip) if _flip else mac
			_note_val = mac              if _flip else _ip_for_notes(ip)

			props_changed = False
			if new_props.get("address")  != _addr_val:
				new_props["address"]  = _addr_val;  props_changed = True
			if new_props.get("ipNumber") != ip:
				new_props["ipNumber"] = ip;          props_changed = True
			if props_changed:
				dev.replacePluginPropsOnServer(new_props)
				self._cache_patch_props(dev_id, new_props)

			# Notes (description) — IP or MAC depending on flipAddressNotes
			if ip_changed or props_changed:
				if self._cache_description(dev_id) != _note_val:
					dev.description = _note_val
					try:
						dev.replaceOnServer()
						self._cache_set_description(dev_id, _note_val)
					except Exception as _re:
						if f"{_re}".find("None") == -1:
							self.indiLOG.log(30, f"replaceOnServer failed for {dev_name}: {_re}")

		except Exception as e:
			if f"{e}".find("None") == -1: self.indiLOG.log(40, f"State update failed for {dev_name}: {e}", exc_info=True)

		# ── Update aggregate HOME_AWAY group devices ──────────────────────
		if online_changed and prev_online is not None:
			self._update_group_devices(dev_id)


	###----------------------------------------------------------###
	def _update_indigo_device(self, mac: str, ip: str, online: bool, source: str = "", dev_id: int = None):
		"""Update an existing device's states from the scan loop thread.
		Reads device ID from _known; all state reads are local (cache).
		The live IPC fetch is deferred to _update_indigo_device_states and only
		happens if the cache shows something has actually changed.

		dev_id: when provided (passed from the probe results loop), skip the
		_known lookup so we update the exact device that _check_one probed,
		not whatever _known currently points to (which a concurrent ARP/sniff
		thread may have changed to a different device with the same MAC).
		"""
		with self._known_lock:
			entry = self._known.get(mac, {})
			if dev_id is None:
				dev_id = entry.get("indigo_device_id")
		if not dev_id:
			# Fallback scan — only when device ID is not yet known (e.g. after startup)
			for d in indigo.devices.iter(PLUGIN_ID):
				if d.states.get("MACNumber", "").lower() == mac.lower():
					dev_id = d.id
					self._cache_put(d)
					with self._known_lock:
						self._known.setdefault(mac, {})["indigo_device_id"] = d.id
					break
		if dev_id:
			vendor     = entry.get("vendor",     "Unknown")
			local_name = entry.get("local_name", "")
			self._update_indigo_device_states(dev_id, mac, ip, vendor, online, local_name=local_name, source=source)

	# ------------------------------------------------------------------
	# Folder helpers
	# ------------------------------------------------------------------

	###----------------------------------------------------------###
	def _rename_and_move_net_devices(self):
		"""Startup pass — renaming disabled: device names are set once at creation and never changed."""
		pass

	###----------------------------------------------------------###
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


	###----------------------------------------------------------###
	@staticmethod
	def isValidIP(ip0):
		ipx = ip0.split(".")
		if len(ipx) != 4:							return False
		for ip in ipx:
			try:
				if int(ip) < 0 or int(ip) > 255:	return False
			except:									return False
		return True

	###----------------------------------------------------------###
	def _unique_device_name(self, desired: str, exclude_id: int = 0) -> str:
		"""Return *desired* if no other device uses it, otherwise append *(1)*, *(2)* … until unique."""
		taken = {d.name for d in indigo.devices if d.id != exclude_id}
		if desired not in taken:
			return desired
		suffix = 1
		while f"{desired} ({suffix})" in taken:
			suffix += 1
		return f"{desired} ({suffix})"

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _update_vendor_files(self) -> bool:
		"""Retry building the table if the background download has completed."""
		if self.M2V is None:
			return False
		if self.waitForMAC2vendor:
			self.waitForMAC2vendor = not self.M2V.makeFinalTable(quiet=False)
			if not self.waitForMAC2vendor:
				self.indiLOG.log(20, "MAC2Vendor lookup table ready.")
		return not self.waitForMAC2vendor

	###----------------------------------------------------------###
	def get_vendor(self, mac: str) -> str:
		"""Return vendor/manufacturer name for a MAC, or 'Unknown'."""
		if not self._update_vendor_files():
			return "Unknown"
		try:
			result = self.M2V.getVendorOfMAC(mac)
			return result.strip() if result else "Unknown"
		except Exception:
			return "Unknown"

	###----------------------------------------------------------###
	def _load_ignored_macs(self) -> set:
		"""Load ignored MACs from pluginPrefs as a set of lowercase strings."""
		raw = self.pluginPrefs.get("ignoredMacs", "")
		return {m.strip().lower() for m in raw.split(",") if m.strip()}

	###----------------------------------------------------------###
	def _save_ignored_macs(self):
		"""Persist ignored MACs back to pluginPrefs as a comma-separated string."""
		self.pluginPrefs["ignoredMacs"] = ", ".join(sorted(self._ignored_macs))

	###----------------------------------------------------------###
	def _load_state(self):
		if os.path.exists(self.stateFile):
			try:
				with open(self.stateFile, "r") as f:
					self._known = json.load(f)
				# Backfill keys added in later versions so every entry is uniform.
				for entry in self._known.values():
					entry.setdefault("history",         [])
					entry.setdefault("ip_history",      [])
					entry.setdefault("local_name",        "")
					entry.setdefault("local_name_source", "")   # "mdns" | "arp" | ""
					entry.setdefault("mdns_name",         "")
					entry.setdefault("arp_name",          "")
					entry.setdefault("name",              "")
					entry.setdefault("curlPort",          None)
					entry.setdefault("curlUseless",      0)
					entry.setdefault("curlPingMismatch", 0)
					entry.setdefault("last_indigo_push",  0)
					entry.setdefault("is_ap_or_router",  False)
					entry.setdefault("ip_change_times",  [])
					# Reset probe-success timestamp — a stale value from a previous run
					# would cause the offline threshold to fire immediately on the first
					# failed probe.  Set to 0 so _check_one's "or now" fallback kicks in
					# and the threshold starts fresh from the first successful probe.
					entry["ping_only_last_ping_ok"] = 0
					# Remove any ip_history entries involving 0.0.0.0, then cap at 20
					entry["ip_history"] = [
						r for r in entry["ip_history"]
						if r.get("old_ip") != "0.0.0.0" and r.get("new_ip") != "0.0.0.0"
					][-20:]
				# Scrub stale device IDs from all _known entries.
				# live_ids = every plugin device currently in Indigo.
				# • Synthetic MACs (00:00:00:00:00:XX) with a dead ID → delete the
				#   whole entry; they are ephemeral and should be rediscovered fresh.
				# • Real MACs with a dead ID → clear just the indigo_device_id so the
				#   entry's history/IP/vendor is preserved for re-association, but the
				#   sentinel check in _ensure_indigo_device is not fooled into blocking
				#   device recreation.
				live_ids      = {dev.id for dev in indigo.devices.iter(PLUGIN_ID)}
				# Also build a set of MACs that have a live device, for synthetic check
				live_macs     = {dev.states.get("MACNumber", "").lower()
				                 for dev in indigo.devices.iter(PLUGIN_ID)}
				synth_purged  = []
				stale_cleared = []
				for mac in list(self._known):
					dev_id = self._known[mac].get("indigo_device_id")
					if mac.startswith("00:00:00:00:00:"):
						# Synthetic MACs are ephemeral — remove the entry unless a live
						# Indigo device still claims this MAC (regardless of stored ID).
						if mac not in live_macs:
							synth_purged.append(mac)
							del self._known[mac]
					else:
						# Real MAC — only act when there is a stale non-None, non-sentinel ID
						if dev_id is None or dev_id == -1 or dev_id in live_ids:
							continue   # no ID, sentinel in progress, or device is alive
						stale_cleared.append(mac)
						self._known[mac].pop("indigo_device_id", None)
				if synth_purged:
					self.indiLOG.log(20,
						f"Startup: removed {len(synth_purged)} orphaned synthetic entry(s) from state: "
						+ ", ".join(synth_purged)
					)
				if stale_cleared:
					self.indiLOG.log(20,
						f"Startup: cleared stale device ID from {len(stale_cleared)} known entry(s) "
						f"(Indigo device was deleted): " + ", ".join(stale_cleared)
					)
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def copyFingscanOnlyToNetworkScanner(self, valuesDict=None, *args):
		"""Copy Fingscan IP-Device entries that have no matching MAC in NetworkScanner.

		Each imported device is created as a networkDevice with:
		  - pingMode  = "pingOnly"
		  - enabled   = False  (user must enable manually)
		A log line is written for every device created.
		"""
		# ── Build MAC → device lookups ───────────────────────────────────────
		fing = {}   # mac → fingscan dev
		for dev in indigo.devices.iter("com.karlwachs.fingscan"):
			if dev.deviceTypeId != "IP-Device":
				continue
			mac = dev.states.get("MACNumber", "").strip().lower()
			if mac:
				fing[mac] = dev

		net_macs = set()  # MACs already in NetworkScanner
		for dev in indigo.devices.iter(PLUGIN_ID):
			if dev.deviceTypeId != DEVICE_TYPE_ID:
				continue
			mac = dev.states.get("MACNumber", "").strip().lower()
			if mac:
				net_macs.add(mac)

		# ── Only process MACs that are in Fingscan but NOT in NetworkScanner ─
		missing = {mac: dev for mac, dev in fing.items() if mac not in net_macs}

		if not missing:
			msg = "No Fingscan-only devices found — nothing to copy."
			self.indiLOG.log(20, f"copyFingscanOnlyToNetworkScanner: {msg}")
			if valuesDict is not None:
				valuesDict["MSG"] = msg
			return valuesDict

		folder_id = self._get_or_create_folder()
		_flip     = self.pluginPrefs.get("flipAddressNotes", False)
		_flip     = (_flip is True) or (str(_flip).lower() == "true")

		created  = []
		skipped  = []

		for mac, fdev in sorted(missing.items()):
			ip        = fdev.states.get("ipNumber",  "") or ""

			# Skip devices with no usable IP
			if not ip or ip == "0.0.0.0":
				skipped.append(f"{mac}  ({fdev.name}): no IP address")
				continue

			# Skip devices whose IP is not a private LAN address — those belong in
			# External Devices (internet hosts), not networkDevices.
			# Private ranges: 10.x.x.x / 172.16-31.x.x / 192.168.x.x
			_oct = ip.split(".")
			try:
				_a, _b = int(_oct[0]), int(_oct[1])
				_is_private = (
					_a == 10
					or (_a == 172 and 16 <= _b <= 31)
					or (_a == 192 and _b == 168)
				)
			except (IndexError, ValueError):
				_is_private = False
			if not _is_private:
				skipped.append(f"{mac}  ({fdev.name}): non-local IP {ip} — use External Device instead")
				continue

			fing_name = fdev.name.strip()
			prefix    = self._getPrefixName()
			name      = f"{fing_name}-{prefix}-ping-only" if fing_name else f"Net_{mac.upper()}-ping only"
			vendor    = fdev.states.get("hardwareVendor", "") or self.get_vendor(mac)

			# Make the name unique across ALL Indigo devices (including disabled ones)
			safe_name = self._unique_device_name(name)

			props = {
				"address":          mac,
				"pingMode":         "pingOnly",
				"offlineThreshold": "0",
			}

			try:
				_padded_ip = _ip_for_notes(ip) if ip else ""
				new_dev = indigo.device.create(
					protocol     = indigo.kProtocol.Plugin,
					name         = safe_name,
					description  = mac if _flip else _padded_ip,
					pluginId     = PLUGIN_ID,
					deviceTypeId = DEVICE_TYPE_ID,
					props        = props,
					folder       = folder_id,
				)
				# Disable the device — user must enable it explicitly
				# Indigo C++ binding: positional args only — (elem, value)
				indigo.device.enable(new_dev.id, False)

				# Seed initial states where possible
				state_updates = [{"key": "MACNumber", "value": mac.upper()}]
				if ip:
					state_updates.append({"key": "ipNumber", "value": ip})
				if vendor and vendor != "Unknown":
					state_updates.append({"key": "hardwareVendor", "value": vendor})
				state_updates.append({"key": "created", "value": _now_str()})
				try:
					new_dev.updateStatesOnServer(state_updates)
				except Exception:
					pass   # states may not be registered yet on first creation

				# Register in _known so the plugin tracks it immediately
				with self._known_lock:
					e = self._known.setdefault(mac.lower(), {})
					e["indigo_device_id"] = new_dev.id
					e["name"]             = new_dev.name
					if ip:
						e.setdefault("ip", ip)

				self._cache_put(new_dev)

				self.indiLOG.log(20,
					f"Fingscan import: '{safe_name}' (MAC={mac.upper()}  IP={ip or '?'}) "
					f"was added as ping-only, but is in DISABLED mode. "
					f"Enable it in Indigo to start monitoring."
				)
				created.append(safe_name)

			except Exception as e:
				skipped.append(f"{mac}  ({fdev.name}): {e}")
				self.indiLOG.log(30,
					f"Fingscan import: could not create device for {mac} ({fdev.name}): {e}"
				)

		# ── Summary ──────────────────────────────────────────────────────────
		lines = [f"\n  Created {len(created)} device(s), skipped {len(skipped)}:"]
		for n in created:
			lines.append(f"    + {n}  [ping-only / DISABLED]")
		for s in skipped:
			lines.append(f"    ! {s}")
		self.indiLOG.log(20, "\n".join(lines))

		msg = f"created:{len(created)}  skipped:{len(skipped)}"
		if valuesDict is not None:
			valuesDict["MSG"] = msg
		return valuesDict

	###----------------------------------------------------------###
	def importNamesFromFingscan(self, valuesDict=None, *args):
		"""Read device names from Fingscan and write them into the matching NetworkScanner
		device's fingscanDeviceInfo state, matched by MAC address."""
		self.indiLOG.log(20, "Importing fingscan dev names…")

		# ── Step 1: build MAC → fingscan-name lookup ────────────────────────
		fing_by_mac = {}
		fing_total  = 0
		for dev in indigo.devices.iter("com.karlwachs.fingscan"):
			if dev.deviceTypeId != "IP-Device":
				continue
			if "MACNumber" not in dev.states: 
				continue
			mac = dev.states.get("MACNumber", "").strip().lower()
			if not mac:
				continue
			fing_by_mac[mac] = dev.name
			fing_total += 1
		self.indiLOG.log(20, f"  Fingscan IP-Device count: {fing_total}  (unique MACs: {len(fing_by_mac)})")

		if not fing_by_mac:
			msg = "No Fingscan IP-Device devices found — nothing to import."
			self.indiLOG.log(20, f"  {msg}")
			if valuesDict is not None:
				valuesDict["MSG"] = msg
			return valuesDict

		# ── Step 2: match NetworkScanner networkDevice entries by MAC ────────
		count = 0
		out   = ["\n"]
		for dev in indigo.devices.iter(PLUGIN_ID):
			# Only MAC-based network devices have a fingscanDeviceInfo state
			if dev.deviceTypeId != DEVICE_TYPE_ID:
				continue
			if "MACNumber" not in dev.states: 
				continue
			mac = dev.states.get("MACNumber", "").strip().lower()
			if not mac:
				continue
			fing_name = fing_by_mac.get(mac)
			if fing_name is None:
				continue
			try:
				count += 1
				out.append(f"  {mac}  {dev.name}  ←  {fing_name}")
			except Exception as e:
				self.indiLOG.log(30, f"  Could not update fingscanDeviceInfo for {dev.name}: {e}")

		out_str = "\n".join(out)
		self.indiLOG.log(20, f"  {count} MAC match(es):{out_str}")
		msg = f"found {count} matching MAC number(s)"
		if valuesDict is not None:
			valuesDict["MSG"] = msg
		return valuesDict


	###----------------------------------------------------------###
	def overwriteDevNamesWithFingNames(self, valuesDict=None, *args):
		"""use the above imported names to overwrite the device names like: oldFingname-Net"""
		self.indiLOG.log(20, f"overwriting dev names with fingscan dev names… to old fingscan name-net ... ")
		countN = 0
		# not used countP = 0
	
		#  not used _fingToMyPingMode = {"doNotUsePing":"none", "usePingifUP":"offline", "usePingifDown":"online", "usePingifUPdown":"both", "useOnlyPing":"pingOnly"}
		out = ["\n"]
		for dev in indigo.devices.iter("com.karlwachs.networkscanner"):
			if "fingscanDeviceInfo" not in dev.states: 
				continue
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


	###----------------------------------------------------------###
	def listKnownDevices(self, valuesDict=None, *args):
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
				lines.append(f"    previousIps    : {states.get('previousIps',     '') or '—'}")
				lines.append(f"    MACNumber      : {states.get('MACNumber',       '') or '—'}")
				lines.append(f"    hardwareVendor  : {states.get('hardwareVendor',     '') or '—'}")
				lines.append(f"    mdnsName        : {states.get('mdnsName',         '') or '—'}")
				lines.append(f"    arpHostname     : {states.get('arpHostname',      '') or '—'}")
				lines.append(f"    dhcpHostname    : {states.get('dhcpHostname',     '') or '—'}")
				lines.append(f"    mdnsServices    : {states.get('mdnsServices',     '') or '—'}")
				lines.append(f"    mdnsModel       : {states.get('mdnsModel',        '') or '—'}")
				lines.append(f"    osHint          : {states.get('osHint',           '') or '—'}")
				lines.append(f"    openPorts       : {states.get('openPorts',        '') or '—'}")
				lines.append(f"    comment         : {states.get('comment',          '') or '—'}")
				lines.append(f"    fingscanInfo    : {states.get('fingscanDeviceInfo','') or '—'}")
				lines.append(f"    isApOrRouter    : {bool(states.get('isApOrRouter', False))}")

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
		return valuesDict


	###----------------------------------------------------------###
	def listEmptyStates(self, valuesDict=None, *args):
		"""Menu: list state names that are empty in every networkDevice."""
		_ALL_STATES = [
			"MACNumber", "ipNumber", "previousIps", "hardwareVendor",
			"mdnsName", "arpHostname",
			"dhcpHostname", "dhcpOsFingerprint",
			"mdnsServices", "mdnsModel", "deviceType", "appleModel", "osVersion",
			"osHint", "networkInterface",
			"pingMs", "openPorts",
			"created", "changeToOn", "changeToOff", "lastOnOffChange", "setOnBy", "setOffBy",
		]
		sep  = "═" * 80
		now  = datetime.datetime.now().strftime(STDDTSTRING)
		devs = [d for d in indigo.devices.iter(PLUGIN_ID) if d.deviceTypeId == DEVICE_TYPE_ID]
		# A state is "empty in all devices" when no device has a non-empty value for it
		empty_in_all = [k for k in _ALL_STATES
		                if not any(d.states.get(k, "") for d in devs)]
		lines = ["\n", sep, f"States empty across all {len(devs)} devices   {now}", sep]
		if empty_in_all:
			for k in empty_in_all:
				lines.append(f"  {k}")
		else:
			lines.append("  (all states have at least one device with a value)")
		lines.append(sep)
		self.indiLOG.log(20, "\n".join(lines))
		return valuesDict

	###----------------------------------------------------------###
	def listDevicesByState(self, valuesDict=None, *args):
		"""Menu: group all networkDevices by osHint, osVersion, deviceType,
		dhcpOsFingerprint, networkInterface, and open port."""

		sep  = "═" * 90
		sep2 = "─" * 60
		now  = datetime.datetime.now().strftime(STDDTSTRING)
		lines = ["\n", sep, f"Devices Grouped by State Value   {now}", sep]

		# Collect all networkDevices once
		devs = [d for d in indigo.devices.iter(PLUGIN_ID)
		        if d.deviceTypeId == DEVICE_TYPE_ID]
		devs.sort(key=lambda d: d.name.lower())

		def _section(title, state_key):
			"""Build one section: group devices by the value of state_key.
			Devices with an empty state are silently omitted."""
			buckets: dict = {}   # value → [device name (IP)]
			for dev in devs:
				val = (dev.states.get(state_key, "") or "").strip()
				if not val:
					continue   # skip devices where this state is not yet populated
				buckets.setdefault(val, []).append(
					f"{dev.name}" + (f" ({dev.states.get('ipNumber','')})"
					                 if dev.states.get("ipNumber") else "")
				)
			if not buckets:
				return   # nothing to show for this state
			lines.append(f"\n{sep2}")
			lines.append(f"  {title}  [{state_key}]")
			lines.append(sep2)
			for val in sorted(buckets.keys()):
				names = buckets[val]
				# Wrap long device lists at ~88 chars
				prefix   = f"  {val:<28}  "
				combined = ",  ".join(names)
				if len(prefix) + len(combined) <= 88:
					lines.append(prefix + combined)
				else:
					lines.append(prefix)
					chunk, line_len = [], 4
					for name in names:
						if line_len + len(name) + 3 > 88 and chunk:
							lines.append("    " + ",  ".join(chunk) + ",")
							chunk, line_len = [], 4
						chunk.append(name)
						line_len += len(name) + 3
					if chunk:
						lines.append("    " + ",  ".join(chunk))

		_section("OS Hint",            "osHint")
		_section("OS Version",         "osVersion")
		_section("DHCP OS Fingerprint","dhcpOsFingerprint")
		_section("Device Type",        "deviceType")
		_section("Network Interface",  "networkInterface")

		# ── Open Ports: each port is its own bucket ──────────────────────────────
		lines.append(f"\n{sep2}")
		lines.append(f"  Open Ports  [openPorts — one line per port]")
		lines.append(sep2)

		port_buckets: dict = {}   # "80/HTTP" → [device name (IP)]
		for dev in devs:
			ports_raw = (dev.states.get("openPorts", "") or "").strip()
			if not ports_raw:
				continue
			dev_label = (f"{dev.name}" +
			             (f" ({dev.states.get('ipNumber','')})"
			              if dev.states.get("ipNumber") else ""))
			for part in ports_raw.split(","):
				port_entry = part.strip()
				if port_entry:
					port_buckets.setdefault(port_entry, []).append(dev_label)

		# Sort ports numerically by the port number prefix
		def _port_sort_key(s):
			try: return int(s.split("/")[0])
			except ValueError: return 99999

		for port_entry in sorted(port_buckets.keys(), key=_port_sort_key):
			names    = port_buckets[port_entry]
			prefix   = f"  {port_entry:<28}  "
			combined = ",  ".join(names)
			if len(prefix) + len(combined) <= 88:
				lines.append(prefix + combined)
			else:
				lines.append(prefix)
				chunk, line_len = [], 4
				for name in names:
					if line_len + len(name) + 3 > 88 and chunk:
						lines.append("    " + ",  ".join(chunk) + ",")
						chunk, line_len = [], 4
					chunk.append(name)
					line_len += len(name) + 3
				if chunk:
					lines.append("    " + ",  ".join(chunk))

		lines += ["\n", sep,
		          f"  {len(devs)} networkDevice(s) included.", sep]
		self.indiLOG.log(20, "\n".join(lines))

	###----------------------------------------------------------###
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
			return valuesDict

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
		return valuesDict

	###----------------------------------------------------------###
	def addDefaultExternalDevices(self, valuesDict, *args):
		"""Button callback (PluginConfig): create checked externalDevice entries.

		Each checkbox key extDev_<key> maps to (device-name, host).
		Only checked entries that don't already exist (by host) are created.
		Devices are placed in the same Device Folder as Net_* devices.
		"""
		_ALL = {
			"extDev_google":     ("Ping-google",     "www.google.com"),
			"extDev_yahoo":      ("Ping-yahoo",       "www.yahoo.com"),
			"extDev_microsoft":  ("Ping-microsoft",   "www.microsoft.com"),
			"extDev_cnn":        ("Ping-cnn",         "www.cnn.com"),
			"extDev_siemens":    ("Ping-siemens",     "www.siemens.de"),
			"extDev_sap":        ("Ping-sap",         "www.sap.de"),
			"extDev_indigodomo": ("Ping-indigodomo",  "www.indigodomo.com"),
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

	# ------------------------------------------------------------------
	# Device-tracking buttons  (debug section of PluginConfig)
	# ------------------------------------------------------------------


	###----------------------------------------------------------###
	@staticmethod
	def _is_valid_mac(s: str) -> bool:
		"""Return True if s is a valid colon-separated MAC address (aa:bb:cc:dd:ee:ff)."""
		return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", s.strip()))

	###----------------------------------------------------------###
	def activateDeviceTracking(self, valuesDict, *args):
		"""Button: validate each comma-separated MAC/IP and immediately start tracing."""
		raw = valuesDict.get("debugTrackedDevice", "").strip()
		if not raw:
			self.pluginPrefs["debugTrackedDevice"] = ""
			valuesDict["trackingActivateMsg"] = "Tracking disabled (field is empty)."
			return valuesDict

		# Validate every entry in the comma-separated list
		entries  = [e.strip() for e in raw.split(",") if e.strip()]
		good     = []   # normalised valid entries
		bad      = []   # rejected entries
		for entry in entries:
			is_mac = self._is_valid_mac(entry)
			is_ip  = self.isValidIP(entry)
			if is_mac or is_ip:
				good.append(entry.lower())
			else:
				bad.append(entry)

		if bad:
			valuesDict["trackingActivateMsg"] = (
				f"Invalid (not MAC or IP): {', '.join(bad)}  — fix and try again."
			)
			return valuesDict

		if not good:
			valuesDict["trackingActivateMsg"] = "Nothing valid entered."
			return valuesDict

		# Write comma-separated normalised list directly to pluginPrefs so all threads pick it up
		target_str = ", ".join(good)
		self.pluginPrefs["debugTrackedDevice"] = target_str
		# Also update the dialog field so it shows the normalised form
		valuesDict["debugTrackedDevice"] = target_str
		msg = f"Tracking {len(good)} device(s): {target_str} — logging to plugin.log"
		self.indiLOG.log(20, f"[TRACK] {msg}")
		valuesDict["trackingActivateMsg"] = f"✓ {msg}"
		return valuesDict

	###----------------------------------------------------------###
	def stopDeviceTracking(self, valuesDict, *args):
		"""Button: immediately stop device tracing."""
		prev = self.pluginPrefs.get("debugTrackedDevice", "").strip()
		self.pluginPrefs["debugTrackedDevice"] = ""
		valuesDict["debugTrackedDevice"]   = ""
		valuesDict["trackingActivateMsg"]  = (
			f"Tracking stopped (was: {prev})." if prev else "Tracking was already off."
		)
		if prev:
			self.indiLOG.log(20, f"[TRACK] Tracking stopped (was: {prev})")
		return valuesDict

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def pingCustomHostButton(self, valuesDict, typeId="", devId=0):
		"""Button callback inside the 'Ping a Device' menu dialog."""
		host  = valuesDict.get("host", "").strip()
		alive, ip, detail, ms = self._ping_custom_host(host)
		status = "ONLINE" if alive else "OFFLINE"
		ip_str = f"  ({ip})" if ip and ip != host else ""
		msg    = f"Ping {host}{ip_str}  →  {status}  [{detail}]  {ms} ms"
		msg1   = f"{status} [{detail}] {ms} ms"
		self.indiLOG.log(20, msg)
		label = host if (host and host != ip) else ip
		self._update_ping_device_variable(alive, ip=label, ms=ms)
		valuesDict["result"] = msg1
		return valuesDict

	###----------------------------------------------------------###
	def pingCustomHostAction(self, action):
		"""Action callback: ping the configured host and update the variable."""
		return self.pingCustomHostButton(action.props)

	###----------------------------------------------------------###
	def forceRescan(self):
		"""Trigger an immediate ARP sweep + ping check."""
		iface = self.pluginPrefs.get("networkInterface", "_auto").strip()
		if not iface or iface == "_auto":
			iface = _auto_detect_iface()
		self.indiLOG.log(20, "Forcing immediate network rescan…")
		t = threading.Thread(
			target=self._scan_loop_once,
			args=(iface, self.pluginPrefs.get("arpSweepEnabled", kDefaultPluginPrefs["arpSweepEnabled"])),
			daemon=True,
		)
		t.start()

	###----------------------------------------------------------###
	def _scan_loop_once(self, iface: str, sweep_enabled: bool):
		if sweep_enabled:
			self._arp_sweep(iface)
		self._check_all_devices(iface)
		self._check_external_devices()
		self._save_state()
		self.indiLOG.log(20, "Forced rescan complete.")


	###----------------------------------------------------------###
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
				
				

	###----------------------------------------------------------###
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
		# Align the "Bins:" footer label with the first bin column in the data rows.
		# Data columns before bins: W_NAME+1 + W_IP+1 + 3+1 + W_PING + 19+1 + 8+1 + 7+2
		_bins_col_offset = W_NAME + 1 + W_IP + 1 + 3 + 1 + W_PING + 19 + 1 + 8 + 1 + 7 + 2
		_bins_label      = "Bins: "
		out +=		_bins_label + " " * (_bins_col_offset - len(_bins_label))
		out +=		"  ".join(f"{_SEEN_LABEL[b]:>7}" for b in _SEEN_BINS)
		out +=		"   (counts = number of sightings within that gap)"
		
		out += "\n"+sep
		self.indiLOG.log(20,out)
		return valuesDict   # button callback inside ConfigUI — must return valuesDict to keep dialog open

	###----------------------------------------------------------###
	def resetSeenStats(self, valuesDict=None, *args):
		"""Menu: clear all seen-interval histograms for every known device."""
		with self._known_lock:
			count = len(self._known)
			for mac in self._known:
				self._known[mac]["seen_stats"] = {b: 0 for b in _SEEN_BINS}
		self._save_state()
		self.indiLOG.log(20, f"Seen-interval stats reset for {count} device(s).")
		return valuesDict

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def scanOpenPorts(self):
		"""Menu: launch TCP port scan on all online devices in a background thread."""
		t = threading.Thread(target=self._port_scan_worker, daemon=True, name="NS-PortScan")
		t.start()

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def _dialog_ignored(self, valuesDict):
		"""Return the working ignored-set for the current dialog session."""
		if valuesDict is None:
			return set(self._ignored_macs)
		raw = valuesDict.get("pendingIgnoredMacs", None)
		if raw is None:
			return set(self._ignored_macs)   # first open — seed from real set
		return {m.strip() for m in raw.split(",") if m.strip()}


	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def addToIgnored(self, valuesDict, *args):
		"""Button: move selected device from available list → ignored list."""
		mac = self._list_selection(valuesDict, "availableDevicesList")
		if not mac:
			return valuesDict
		pending = self._dialog_ignored(valuesDict)
		pending.add(mac)
		valuesDict["pendingIgnoredMacs"] = ",".join(sorted(pending))
		return valuesDict

	###----------------------------------------------------------###
	def removeFromIgnored(self, valuesDict, *args):
		"""Button: move selected device from ignored list → available list."""
		mac = self._list_selection(valuesDict, "ignoredDevicesList")
		if not mac:
			return valuesDict
		pending = self._dialog_ignored(valuesDict)
		pending.discard(mac)
		valuesDict["pendingIgnoredMacs"] = ",".join(sorted(pending))
		return valuesDict

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def pingDeviceAction(self, pluginAction, dev, callerWaitingForResult):
		"""Ping a single device on demand."""
		mac   = dev.states.get("MACNumber", "")
		ip    = dev.states.get("ipNumber",  "")
		iface = self.pluginPrefs.get("networkInterface", "_auto").strip()
		if not iface or iface == "_auto":
			iface = _auto_detect_iface()

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

	###----------------------------------------------------------###
	def filterNetworkAllDevices(self, filter="", valuesDict=None, typeId="", targetId=0):
		"""Populate device selector in setDevState dialog."""
		items = []
		for dev in indigo.devices.iter(PLUGIN_ID):
			mac = dev.states.get("MACNumber", "")
			ip  = dev.states.get("ipNumber",  "")
			items.append((str(dev.id), f"{dev.name}   {ip}   {mac}"))
		items.sort(key=lambda x: x[1])
		return items

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
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
					"ipNumber":      "ip",
					"mdnsName":      "mdns_name",
					"arpHostname":   "arp_name",
					"hardwareVendor": "vendor",
					"isApOrRouter":  "is_ap_or_router",
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

	###----------------------------------------------------------###
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

	###----------------------------------------------------------###
	def __init__(self, fmt=None, datefmt=None, level_fmts=None, level_date=None):
		self._level_formatters = {}
		if level_fmts and level_date:
			for level, fmt_str in level_fmts.items():
				self._level_formatters[level] = logging.Formatter(
					fmt=fmt_str, datefmt=level_date.get(level, datefmt)
				)
		super().__init__(fmt=fmt, datefmt=datefmt)

	###----------------------------------------------------------###
	def format(self, record):
		if record.levelno in self._level_formatters:
			return self._level_formatters[record.levelno].format(record)
		return super().format(record)
