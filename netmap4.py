#!/usr/bin/env python3
"""
netmap - discover hosts on a network you own or administer and draw an
interactive map of them.

Pure standard library (Python 3.8+), no root needed. Works on Linux, macOS, Windows.

    python netmap.py                      # scan your local /24, write netmap.html
    python netmap.py 192.168.1.0/24       # scan a specific range
    python netmap.py 10.0.0.0/23 --ports 22,80,443 -o office.html --json office.json
    python netmap.py --load office.json   # rebuild the map from a saved scan
    python netmap.py --methods arp,udp    # only use methods that don't rely on ICMP
    python netmap.py --thorough           # also sweep many more TCP ports during discovery

Topology (who is plugged into what):
    python netmap.py --snmp env:SNMP_RO --snmp-hosts 10.0.0.2,10.0.0.3   # read switch MAC tables + LLDP
    python netmap.py 10.0.1.0/24 10.0.2.0/24                             # several subnets, with the routed path

Port scanning (on the hosts that were found):
    python netmap.py --ports top          # ~100 frequently open TCP ports (default)
    python netmap.py --ports 1-1024       # a range; also: all, common, none, 22,80,8000-8100
    python netmap.py --udp                # also check DNS, NTP, NetBIOS, UPnP and mDNS over UDP
    python netmap.py --no-banners         # skip service identification

Host discovery combines several methods, so devices that ignore ping are still found:
  arp   - ARP neighbour table (cannot be firewalled on the local segment)
  udp   - NetBIOS, mDNS and UPnP/SSDP queries (unicast and multicast)
  icmp  - ordinary ping
  tcp   - TCP connect probes (an open port or a refusal both prove a host is up)

Only scan networks you are authorised to scan. By default only private
(RFC 1918 / link-local / loopback) ranges are accepted.
"""
import argparse
import asyncio
import concurrent.futures as cf
import errno
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 139: "netbios",
    443: "https", 445: "smb", 515: "lpd", 554: "rtsp", 631: "ipp", 1883: "mqtt",
    3389: "rdp", 5900: "vnc", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 9100: "jetdirect", 62078: "ios-sync",
}
DISCOVERY_PORTS = (443, 80, 22, 445, 139, 135, 53, 3389, 8080, 554, 9100, 62078)
THOROUGH_PORTS = DISCOVERY_PORTS + (21, 23, 25, 110, 143, 631, 1883, 5000, 5900, 7000, 8008,
                                    8009, 8443, 32400, 49152)
METHODS = ("arp", "udp", "icmp", "tcp")

# About the 100 TCP ports most often found open on home and office networks.
TOP_PORTS = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7000, 7070, 8000, 8008, 8009,
    8080, 8081, 8123, 8443, 8888, 9100, 9200, 9999, 10000, 11211, 27017, 32400, 32768, 49152,
    49153, 49154, 49155, 49156, 49157, 62078,
)
SERVICE_NAMES = {
    **COMMON_PORTS,
    135: "msrpc", 144: "news", 179: "bgp", 389: "ldap", 427: "slp", 465: "smtps", 548: "afp",
    587: "submission", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1723: "pptp", 2049: "nfs", 2375: "docker", 3128: "proxy", 3306: "mysql", 5000: "upnp/http",
    5060: "sip", 5357: "wsd", 5432: "postgres", 5555: "adb", 5985: "winrm", 6379: "redis",
    7000: "airplay", 8008: "cast-http", 8009: "cast", 8123: "home-assistant", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 32400: "plex",
}
# Open ports worth a second look on most networks. Informational, not a verdict.
RISKY = {
    21: "FTP sends logins unencrypted",
    23: "Telnet sends logins unencrypted",
    69: "TFTP has no authentication",
    135: "Windows RPC is reachable",
    139: "SMB file sharing is reachable",
    445: "SMB file sharing is reachable",
    1433: "A database is listening on the network",
    2375: "Docker API without TLS gives full control of the host",
    3306: "A database is listening on the network",
    3389: "Remote Desktop is reachable",
    5432: "A database is listening on the network",
    5555: "Android debug bridge is reachable",
    5900: "VNC remote screen is reachable",
    6379: "Redis is listening on the network",
    9200: "Elasticsearch is listening on the network",
    11211: "Memcached is listening on the network",
    27017: "MongoDB is listening on the network",
}
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9000, 9090, 9200, 32400}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 5001, 8443, 8883, 9443}
SYSTEM = platform.system()
REFUSED = {errno.ECONNREFUSED, 10061}  # a refusal still proves the host is up


# --------------------------------------------------------------------------- #
# Local network info
# --------------------------------------------------------------------------- #
def run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # UDP connect sends nothing
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway():
    if SYSTEM == "Linux":
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", run(["ip", "route", "show", "default"]))
    elif SYSTEM == "Darwin":
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", run(["route", "-n", "get", "default"]))
    elif SYSTEM == "Windows":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", run(["route", "print", "0.0.0.0"]))
    else:
        m = None
    return m.group(1) if m else None


def read_arp_table():
    """Return {ip: mac} from the OS neighbour cache (only hosts on our own L2 segment)."""
    out = run(["ip", "neigh"]) if SYSTEM == "Linux" else run(["arp", "-a"])
    table = {}
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})", line)
        if not (ip and mac):
            continue
        octets = [o.zfill(2) for o in re.split(r"[:-]", mac.group(1).lower())]
        norm = ":".join(octets)
        if norm in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or int(octets[0], 16) & 1:
            continue  # broadcast / multicast entries are not devices
        table[ip.group(1)] = norm
    return table


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #
def ping(ip, timeout):
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]
    start = time.perf_counter()
    try:
        ok = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout + 2).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None
    return round((time.perf_counter() - start) * 1000, 1) if ok else None


def tcp_probe(ip, port, timeout):
    """Return (state, rtt_ms): state is 'open', 'refused' or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.perf_counter()
    try:
        code = s.connect_ex((ip, port))
    except OSError:
        return None, None
    finally:
        s.close()
    rtt = round((time.perf_counter() - start) * 1000, 1)
    if code == 0:
        return "open", rtt
    if code in REFUSED:
        return "refused", rtt
    return None, None


def _dns_query(name, qtype=12):
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack(">HH", qtype, 1)


MDNS_QUERY = _dns_query("_services._dns-sd._udp.local")
NBNS_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
              + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1))  # node status "*"
SSDP_QUERY = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
              b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")


def parse_nbns(data):
    """Pull the workstation name out of a NetBIOS node-status reply."""
    try:
        for i in range(data[56]):
            rec = data[57 + i * 18: 57 + (i + 1) * 18]
            flags = struct.unpack(">H", rec[16:18])[0]
            if rec[15] == 0 and not flags & 0x8000:
                return rec[:15].decode("ascii", "ignore").strip()
    except (IndexError, struct.error):
        pass
    return ""


def udp_sweep(targets, me, wait):
    """
    Ask every address for NetBIOS and mDNS names (unicast) and shout on the mDNS and
    UPnP multicast groups. Sending to each address also makes the OS ARP for it.
    Returns {ip: (set_of_methods, name)}.
    """
    wanted = set(targets)
    hits = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
    except OSError:
        pass
    s.settimeout(0.25)
    probes = [(ip, 137, NBNS_QUERY) for ip in targets] + [(ip, 5353, MDNS_QUERY) for ip in targets]
    probes += [("224.0.0.251", 5353, MDNS_QUERY), ("239.255.255.250", 1900, SSDP_QUERY)]
    for ip, port, payload in probes:
        try:
            s.sendto(payload, (ip, port))
        except OSError:
            pass
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            data, (ip, port) = s.recvfrom(4096)
        except OSError:  # timeout, or Windows reporting an ICMP port-unreachable
            continue
        if ip not in wanted:
            continue
        if port == 137:
            method, name = "nbns", parse_nbns(data)
        elif port == 1900:
            method, name = "ssdp", ""
        elif port == 5353:
            method, name = "mdns", ""
        else:
            continue
        methods, old = hits.get(ip, (set(), ""))
        methods.add(method)
        hits[ip] = (methods, old or name)
    s.close()
    return hits


def arp_trigger(targets):
    """Send a throwaway UDP packet to every address so the OS has to ARP for it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in targets:
        try:
            s.sendto(b"\0", (ip, 9))
        except OSError:
            pass
    s.close()


# --------------------------------------------------------------------------- #
# Port scanning
# --------------------------------------------------------------------------- #
DNS_PROBE = _dns_query("example.com", 1)
NTP_PROBE = b"\x1b" + b"\0" * 47
UDP_PROBES = {  # port -> (service, payload). A reply proves the port is open.
    53: ("dns", DNS_PROBE), 123: ("ntp", NTP_PROBE), 137: ("netbios-ns", NBNS_QUERY),
    1900: ("upnp", SSDP_QUERY), 5353: ("mdns", MDNS_QUERY),
}


def service_name(port):
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "tcp"


def fd_budget(requested):
    """Keep concurrency under the process's open-file limit (macOS defaults to 256)."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = requested + 64
        if hard != resource.RLIM_INFINITY:
            want = min(want, hard)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            soft = want
        return max(16, min(requested, soft - 64))
    except (ImportError, ValueError, OSError):
        return requested


async def _probe(ip, port, timeout):
    """'open', 'closed' (host sent a refusal) or 'filtered' (no answer)."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return "filtered"
    except (ConnectionRefusedError, ConnectionResetError):
        return "closed"
    except OSError as e:
        return "closed" if e.errno in REFUSED else "filtered"
    writer.close()
    return "open"


async def scan_tcp(ports, hosts, timeout, concurrency):
    total = len(ports) * len(hosts)
    pairs = ((ip, p) for p in ports for ip in hosts)  # spread load across hosts
    results = {}

    async def worker():
        for ip, port in pairs:
            results[(ip, port)] = await _probe(ip, port, timeout)
            if len(results) % 500 == 0 or len(results) == total:
                progress(f"\r  {len(results)}/{total} probes", end="")

    await asyncio.gather(*(worker() for _ in range(max(1, min(concurrency, total)))))
    progress("")
    return results


def clean(text, limit=100):
    """Printable ASCII only; returns '' for binary data."""
    if not text:
        return ""
    ok = sum(32 <= ord(c) < 127 for c in text)
    if ok < 0.8 * len(text):
        return ""
    return "".join(c if 32 <= ord(c) < 127 else " " for c in text).strip()[:limit]


def describe(port, data, tls):
    """Turn raw bytes from a service into (service_name_or_None, short banner)."""
    text = data.decode("latin-1", "replace")
    first = clean(text.splitlines()[0]) if text.strip() else ""
    if text.startswith("HTTP/"):
        server = re.search(r"(?im)^server:\s*(.+)$", text)
        title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        parts = [clean(server.group(1))] if server else []
        if title:
            parts.append(clean(title.group(1), 80))
        parts = [x for x in parts if x] or [first]
        return ("https" if tls else "http"), " | ".join(parts)[:120]
    if text.startswith("SSH-"):
        return "ssh", first
    if text.startswith("RFB "):
        return "vnc", first
    if re.match(r"220[ -]", text):
        low = text.lower()
        if "ftp" in low or port in (21, 2121):
            return "ftp", first
        if "smtp" in low or port in (25, 465, 587):
            return "smtp", first
        return None, first
    if text.startswith("+OK"):
        return "pop3", first
    if text.startswith("* OK"):
        return "imap", first
    if data[:1] == b"\xff":
        return "telnet", "telnet negotiation"
    return None, first


async def _read_some(reader, limit, wait, first_only=False):
    data, end = b"", time.monotonic() + wait
    while len(data) < limit:
        left = end - time.monotonic()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(limit - len(data)), left)
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        data += chunk
        if first_only:
            break
    return data


async def grab(ip, port, timeout):
    """Identify what's listening: read a greeting, or ask web servers for their front page."""
    info = {"service": None, "banner": "", "tls": ""}
    tls = port in TLS_PORTS
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx), timeout + 2)
    except Exception:
        return info
    try:
        if tls:
            sslobj = writer.get_extra_info("ssl_object")
            info["tls"] = (sslobj.version() or "") if sslobj else ""
        webby = port in HTTP_PORTS or (tls and port in (443, 5001, 8443, 9443))
        data = b""
        if not webby:  # most other services speak first
            data = await _read_some(reader, 256, 0.8, first_only=True)
        if not data and webby:
            request = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netmap\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await _read_some(reader, 4096, timeout + 1)
        if data:
            info["service"], info["banner"] = describe(port, data, tls)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return info


async def identify_all(pairs, timeout):
    sem = asyncio.Semaphore(48)
    out = {}

    async def one(ip, port):
        async with sem:
            out[(ip, port)] = await grab(ip, port, timeout)

    await asyncio.gather(*(one(ip, p) for ip, p in pairs))
    return out


def udp_ports(hosts, wait):
    """Send a protocol-correct probe for a few UDP services; only real services answer."""
    found = {ip: [] for ip in hosts}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.25)
    for ip in hosts:
        for port, (_, payload) in UDP_PROBES.items():
            try:
                s.sendto(payload, (ip, port))
            except OSError:
                pass
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            _, (ip, port) = s.recvfrom(4096)
        except OSError:
            continue
        if ip in found and port in UDP_PROBES and port not in found[ip]:
            found[ip].append(port)
    s.close()
    return found


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def classify(ports, hostname, is_gateway, is_self):
    p = set(ports)
    name = hostname.lower()
    if is_self:
        return "self"
    if is_gateway:
        return "gateway"
    if p & {9100, 631, 515} or re.search(r"print|laserjet|officejet|epson|brother", name):
        return "printer"
    if 554 in p or re.search(r"cam|nvr|dvr", name):
        return "camera"
    if 62078 in p or re.search(r"iphone|ipad|android|galaxy|pixel", name):
        return "mobile"
    if p & {135, 3389, 5985} or (p & {445, 139} and 22 not in p):
        return "windows"
    if p & {22, 21, 53, 1883, 5900, 1433, 3306, 5432, 6379, 9200, 11211, 27017, 2375} \
            or (p & {80, 443, 8080, 8443} and 22 in p):
        return "server"
    if p & {80, 443, 8000, 8080, 8443}:
        return "iot"  # something with a web interface: NAS, TV, smart device...
    return "unknown"


# --------------------------------------------------------------------------- #
# SNMP v2c client (read-only, standard library only)
# --------------------------------------------------------------------------- #
EOM = object()  # endOfMibView marker


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, body):
    return bytes([tag]) + _enc_len(len(body)) + body


def _enc_int(v):
    return _tlv(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big", signed=True))


def _enc_oid(text):
    arcs = [int(x) for x in text.strip(".").split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _read_tlv(buf, i):
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + length > len(buf):
        raise ValueError("truncated")
    return tag, bytes(buf[i:i + length]), i + length


def _dec_oid(b):
    arcs, value = [b[0] // 40, b[0] % 40], 0
    for x in b[1:]:
        value = (value << 7) | (x & 0x7F)
        if not x & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(map(str, arcs))


def _dec_val(tag, body):
    if tag == 0x02:
        return int.from_bytes(body, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):  # counter32, gauge32, timeticks, counter64
        return int.from_bytes(body, "big")
    if tag == 0x04:
        return body
    if tag == 0x06:
        return _dec_oid(body)
    if tag == 0x40:
        return ".".join(str(x) for x in body)
    return None  # null, noSuchObject, noSuchInstance


def _oid_key(text):
    return tuple(int(x) for x in text.split("."))


class Snmp:
    """Minimal SNMPv2c GET / GETBULK client. Sends only reads."""

    def __init__(self, host, community, timeout=2.0, retries=1, port=161):
        self.host, self.port = host, port
        self.community = community.encode("utf-8")
        self.timeout, self.retries, self.req = timeout, retries, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def close(self):
        self.sock.close()

    @staticmethod
    def _parse(data):
        try:
            tag, body, _ = _read_tlv(data, 0)
            if tag != 0x30:
                return None
            _, _, i = _read_tlv(body, 0)       # version
            _, _, i = _read_tlv(body, i)       # community
            tag, pdu, _ = _read_tlv(body, i)
            if tag != 0xA2:                    # not a response
                return None
            _, rid, i = _read_tlv(pdu, 0)
            _, status, i = _read_tlv(pdu, i)
            _, _, i = _read_tlv(pdu, i)
            _, binds, _ = _read_tlv(pdu, i)
            request_id = int.from_bytes(rid, "big")
            if int.from_bytes(status, "big"):
                return request_id, []
            out, j = [], 0
            while j < len(binds):
                _, vb, j = _read_tlv(binds, j)
                _, ob, k = _read_tlv(vb, 0)
                vtag, vv, _ = _read_tlv(vb, k)
                out.append((_dec_oid(ob), EOM if vtag == 0x82 else _dec_val(vtag, vv)))
            return request_id, out
        except (IndexError, ValueError):
            return None

    def _request(self, pdu_tag, a, b, oids):
        self.req = (self.req + 1) & 0x7FFFFFFF
        binds = b"".join(_tlv(0x30, _enc_oid(o) + b"\x05\x00") for o in oids)
        pdu = _tlv(pdu_tag, _enc_int(self.req) + _enc_int(a) + _enc_int(b) + _tlv(0x30, binds))
        message = _tlv(0x30, _enc_int(1) + _tlv(0x04, self.community) + pdu)  # version 1 = v2c
        for _ in range(self.retries + 1):
            try:
                self.sock.sendto(message, (self.host, self.port))
                while True:
                    data, addr = self.sock.recvfrom(65535)
                    parsed = self._parse(data) if addr[0] == self.host else None
                    if parsed and parsed[0] == self.req:
                        return parsed[1]
            except socket.timeout:
                continue
            except OSError:
                return None
        return None

    def get(self, *oids):
        return dict(self._request(0xA0, 0, 0, list(oids)) or [])

    def walk(self, root, max_rep=25, limit=20000):
        """All (oid, value) pairs under root, using GETBULK."""
        out, cur = [], root
        while len(out) < limit:
            binds = self._request(0xA5, 0, max_rep, [cur])
            if not binds:
                break
            advanced = False
            for oid, val in binds:
                if val is EOM or not (oid == root or oid.startswith(root + ".")):
                    return out
                if _oid_key(oid) <= _oid_key(cur):
                    return out
                out.append((oid, val))
                cur, advanced = oid, True
            if not advanced:
                break
        return out


OID_SYSDESCR, OID_SYSUPTIME, OID_SYSNAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"
OID_BRIDGE_ADDR = "1.3.6.1.2.1.17.1.1.0"
OID_IFNAME, OID_IFDESCR, OID_IFPHYS = "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.6"
OID_BPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_QFDB = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort.<vlan>.<mac x6>
OID_DFDB = "1.3.6.1.2.1.17.4.3.1.2"       # dot1dTpFdbPort.<mac x6>
OID_LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"   # lldpRemEntry.<column>.<time>.<local port>.<index>
OID_LLDP_LOCDESC = "1.0.8802.1.1.2.1.3.7.1.4"


def _text(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").replace("\x00", "").strip()
    return "" if v is None else str(v)


def _fmt_mac(raw):
    if isinstance(raw, bytes) and len(raw) == 6 and raw != b"\x00" * 6 and not raw[0] & 1:
        return ":".join(f"{x:02x}" for x in raw)
    return ""


def snmp_collect(ip, community, timeout=2.0, port=161):
    """Read name, interfaces, MAC forwarding table and LLDP neighbours from one device."""
    c = Snmp(ip, community, timeout, port=port)
    try:
        info = c.get(OID_SYSDESCR, OID_SYSNAME, OID_SYSUPTIME, OID_BRIDGE_ADDR)
        if not info or all(v is None for v in info.values()):
            return None
        dev = {"ip": ip, "sys_name": _text(info.get(OID_SYSNAME)), "sys_descr": _text(info.get(OID_SYSDESCR))[:160],
               "uptime_s": (info.get(OID_SYSUPTIME) or 0) // 100, "macs": set(), "fdb": {}, "lldp": []}
        bridge_mac = _fmt_mac(info.get(OID_BRIDGE_ADDR))
        if bridge_mac:
            dev["macs"].add(bridge_mac)

        ifname = {}
        for oid, val in c.walk(OID_IFNAME) or c.walk(OID_IFDESCR):
            ifname[int(oid.rsplit(".", 1)[1])] = _text(val)
        for oid, val in c.walk(OID_IFPHYS):
            mac = _fmt_mac(val)
            if mac:
                dev["macs"].add(mac)

        bport_if = {int(oid.rsplit(".", 1)[1]): val for oid, val in c.walk(OID_BPORT_IFINDEX)}

        def port_name(bridge_port):
            idx = bport_if.get(bridge_port, bridge_port)
            return ifname.get(idx) or f"port {bridge_port}"

        def read_fdb(root, skip):
            for oid, val in c.walk(root):
                arcs = oid[len(root) + 1:].split(".")[skip:]
                if len(arcs) != 6 or not isinstance(val, int) or val == 0:
                    continue
                mac = _fmt_mac(bytes(int(x) for x in arcs))
                if mac and mac not in dev["fdb"]:
                    dev["fdb"][mac] = port_name(val)

        read_fdb(OID_QFDB, 1)
        if not dev["fdb"]:
            read_fdb(OID_DFDB, 0)

        loc_desc = {int(oid.rsplit(".", 1)[1]): _text(v) for oid, v in c.walk(OID_LLDP_LOCDESC)}
        groups = {}
        for oid, val in c.walk(OID_LLDP_REM):
            col, _time, local, idx = oid[len(OID_LLDP_REM) + 1:].split(".")[:4]
            groups.setdefault((int(local), idx), {})[int(col)] = val
        for (local, _idx), g in groups.items():
            chassis = g.get(5)
            remote_port = g.get(8) or g.get(7)
            if g.get(6) == 3 and isinstance(g.get(7), bytes):  # port id is a MAC address
                remote_port = _fmt_mac(g[7]) or remote_port
            dev["lldp"].append({
                "local_port": loc_desc.get(local) or ifname.get(local) or f"port {local}",
                "mac": _fmt_mac(chassis) if g.get(4) == 4 else "",
                "name": _text(g.get(9)),
                "desc": _text(g.get(10))[:120],
                "remote_port": _text(remote_port),
            })
        return dev
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Topology: links from switch tables, LLDP and traceroute
# --------------------------------------------------------------------------- #
class LinkSet:
    def __init__(self):
        self.links = {}

    def add(self, a, b, via, a_port="", b_port=""):
        if a == b:
            return
        key = frozenset((a, b))
        link = self.links.get(key)
        if link is None:
            self.links[key] = {"ends": {a: a_port, b: b_port}, "via": via}
            return
        for node, port in ((a, a_port), (b, b_port)):
            if port and not link["ends"].get(node):
                link["ends"][node] = port
        if via == "lldp":
            link["via"] = "lldp"

    def output(self, valid):
        out = []
        for link in self.links.values():
            (a, ap), (b, bp) = list(link["ends"].items())
            if a in valid and b in valid:
                out.append({"a": a, "b": b, "a_port": ap, "b_port": bp, "via": link["via"]})
        return out


def build_switch_links(data, devices, ls):
    """Work out who plugs into what from each switch's learned-MAC table and LLDP neighbours."""
    hosts = {h["ip"]: h for h in data["hosts"]}
    bridges = {ip for ip, d in devices.items() if d["fdb"]}
    owner = {h["mac"]: h["ip"] for h in data["hosts"] if h["mac"]}
    for ip, d in devices.items():
        for m in d["macs"]:
            owner[m] = ip
    extras, uplinks, port_neighbour = {}, {ip: set() for ip in devices}, {}

    def name_of(ip):
        return devices[ip]["sys_name"] or hosts.get(ip, {}).get("hostname") or ip

    # 1. LLDP: the neighbour tells us exactly what is on the other end of a port.
    for ip, d in devices.items():
        for n in d["lldp"]:
            remote = owner.get(n["mac"]) if n["mac"] else None
            if remote is None and n["name"]:
                remote = next((i for i, o in devices.items()
                               if i != ip and o["sys_name"].lower() == n["name"].lower()), None)
            if remote is None:
                if not n["name"]:
                    continue
                remote = "lldp:" + (n["mac"] or n["name"])
                extras[remote] = {"id": remote, "label": n["name"], "type": "unknown", "ip": "",
                                  "note": "Seen only through LLDP. " + n["desc"]}
            if remote == ip:
                continue
            ls.add(ip, remote, "lldp", n["local_port"], n["remote_port"])
            port_neighbour[(ip, n["local_port"])] = remote
            if remote in bridges:
                uplinks[ip].add(n["local_port"])

    # 2. Two switches that each see the other's MAC on one port are neighbours; drop pairs
    #    that only see each other through a third switch.
    def seen_port(a, b):
        ports = [devices[a]["fdb"][m] for m in devices[b]["macs"] if m in devices[a]["fdb"]]
        return Counter(ports).most_common(1)[0][0] if ports else ""

    names = sorted(bridges)
    mutual = {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            pa, pb = seen_port(a, b), seen_port(b, a)
            if pa and pb:
                mutual[(a, b)], mutual[(b, a)] = (pa, pb), (pb, pa)
    for (a, c), (pa, pc) in list(mutual.items()):
        if a > c:
            continue
        indirect = any((a, b) in mutual and (b, c) in mutual
                       and mutual[(a, b)][0] == pa and mutual[(b, c)][1] == pc
                       for b in names if b not in (a, c))
        if not indirect:
            ls.add(a, c, "fdb", pa, pc)
            uplinks[a].add(pa)
            uplinks[c].add(pc)

    # 3. Every other device sits on the switch port where it is learned, ignoring trunk ports.
    counts = {ip: Counter(devices[ip]["fdb"].values()) for ip in bridges}
    attached = {}
    for ip, h in hosts.items():
        if ip in bridges:
            continue
        macs = ({h["mac"]} if h["mac"] else set()) | devices.get(ip, {}).get("macs", set())
        best = None
        for b in bridges:
            for m in macs:
                port = devices[b]["fdb"].get(m)
                if port and port not in uplinks[b]:
                    cand = (counts[b][port], b, port)
                    best = cand if best is None or cand < best else best
        if best:
            attached.setdefault((best[1], best[2]), []).append(ip)

    for (b, port), eps in attached.items():
        neighbour = port_neighbour.get((b, port))
        if neighbour:
            for e in eps:
                ls.add(e, neighbour, "fdb")
        elif len(eps) >= 2 and counts[b][port] >= 2:
            sid = f"port:{b}:{port}"
            extras[sid] = {"id": sid, "label": f"Shared port {port}", "type": "switch", "ip": "",
                           "note": f"Several devices share port {port} on {name_of(b)}. That is an unmanaged "
                                   "switch, an access point, or a host running virtual machines."}
            ls.add(b, sid, "fdb", port, "")
            for e in eps:
                ls.add(e, sid, "fdb")
        else:
            for e in eps:
                ls.add(e, b, "fdb", "", port)
    return extras


def trace_route(ip, timeout, max_hops=12):
    """Router hops towards ip (destination excluded); None entries are silent hops."""
    exe = "tracert" if SYSTEM == "Windows" else "traceroute"
    if not shutil.which(exe):
        return None
    if SYSTEM == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["traceroute", "-n", "-q", "1", "-w", str(max(1, int(round(timeout)))), "-m", str(max_hops), ip]
    hops = {}
    for line in run(cmd, timeout=max_hops * 4 + 15).splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if m:
            found = re.search(r"(\d+\.\d+\.\d+\.\d+)", m.group(2))
            hops.setdefault(int(m.group(1)), found.group(1) if found else None)
    path = [hops[t] for t in sorted(hops)]
    if path and path[-1] == ip:
        path.pop()
    while path and path[-1] is None:
        path.pop()
    return path


def build_routed_links(data, nets, hub, hostmap, ls, timeout):
    """Trace the path from this machine to every subnet that is not on our own segment."""
    me = ipaddress.ip_address(data["self"])
    targets = {}
    for net in nets:
        if me in net:
            continue
        members = [h["ip"] for h in data["hosts"] if ipaddress.ip_address(h["ip"]) in net]
        if members:
            targets[net] = members
    extras = {}
    if not targets:
        return extras
    progress(f"Tracing the route to {len(targets)} other subnet(s)...")
    with cf.ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        paths = dict(zip(targets, pool.map(lambda n: trace_route(targets[n][0], timeout), targets)))
    for net, members in targets.items():
        path = paths[net]
        if path is None:
            progress("  traceroute isn't installed, so routed subnets are shown without their path")
            path = []
        prev = hub
        for ttl, hop in enumerate(path, 1):
            if hop is None:
                nid = f"hop:{net}:{ttl}"
                extras[nid] = {"id": nid, "label": "no reply", "type": "gateway", "ip": "",
                               "note": "A router on the path that didn't answer traceroute."}
            elif hop in hostmap:
                nid = hop
            else:
                nid = f"hop:{hop}"
                extras[nid] = {"id": nid, "label": hop, "type": "gateway", "ip": hop,
                               "note": "Router found by traceroute."}
            ls.add(prev, nid, "traceroute")
            prev = nid
        net_id = f"net:{net}"
        extras[net_id] = {"id": net_id, "label": str(net), "type": "network", "ip": "",
                          "note": "Subnet reached through the router chain shown."}
        ls.add(prev, net_id, "traceroute")
        for m in members:
            ls.add(m, net_id, "subnet")
    return extras


def pick_snmp_targets(spec, data):
    hosts = [h["ip"] for h in data["hosts"]]
    spec = (spec or "gateway").strip().lower()
    if spec == "all":
        return hosts
    if spec == "gateway":
        return [data["gateway"]] if data["gateway"] else []
    out = []
    for part in spec.split(","):
        try:
            out.append(str(ipaddress.ip_address(part.strip())))
        except ValueError:
            raise SystemExit(f"--snmp-hosts: '{part}' is not an IP address (use gateway, all, or IPs like 10.0.0.2,10.0.0.3)")
    return out


def add_topology(data, community, snmp_spec, snmp_port, snmp_timeout, do_trace, timeout):
    """Attach data['hub'], data['links'] and data['extra_nodes'] to a scan."""
    nets = [ipaddress.ip_network(c) for c in data["networks"]]
    hostmap = {h["ip"]: h for h in data["hosts"]}
    devices = {}
    if community:
        targets = pick_snmp_targets(snmp_spec, data)
        if not targets:
            progress("SNMP: no targets. Pass --snmp-hosts with your switch addresses.")
        else:
            progress("Reading switch tables over SNMP v2c (the community string is sent unencrypted)...")
        for ip in targets:
            dev = snmp_collect(ip, community, snmp_timeout, snmp_port)
            if dev is None:
                progress(f"  {ip}: no SNMP answer (check the community string and that SNMP is enabled)")
                continue
            devices[ip] = dev
            progress(f"  {ip}: {dev['sys_name'] or 'unnamed'}, {len(dev['fdb'])} MACs learned, "
                     f"{len(dev['lldp'])} LLDP neighbours")
    for ip, dev in devices.items():
        h = hostmap.get(ip)
        if h is None:
            h = {"ip": ip, "hostname": "", "mac": "", "rtt_ms": None, "found_by": [], "ports": [],
                 "flags": [], "type": "unknown"}
            data["hosts"].append(h)
            hostmap[ip] = h
        h["hostname"] = h["hostname"] or dev["sys_name"]
        h["found_by"] = sorted(set(h["found_by"]) | {"snmp"})
        h["snmp"] = {"sys_name": dev["sys_name"], "sys_descr": dev["sys_descr"], "uptime_s": dev["uptime_s"],
                     "macs_learned": len(dev["fdb"]), "lldp_neighbours": len(dev["lldp"])}
        if dev["fdb"] and h["type"] != "gateway":
            h["type"] = "switch"

    gw = data["gateway"]
    hub = gw if gw in hostmap else "__hub__"
    extras = {}
    if hub == "__hub__":
        extras[hub] = {"id": hub, "label": data["cidr"], "type": "network", "ip": "",
                       "note": "No default gateway was found, so the range itself is drawn as the centre."}
    ls = LinkSet()
    if devices:
        extras.update(build_switch_links(data, devices, ls))
    if do_trace:
        extras.update(build_routed_links(data, nets, hub, hostmap, ls, timeout))

    # Anything still unconnected hangs off the hub, marked as assumed.
    ids = list(hostmap) + list(extras)
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    degree = Counter()
    for key in ls.links:
        a, b = tuple(key)
        if a in parent and b in parent:
            parent[find(a)] = find(b)
            degree[a] += 1
            degree[b] += 1
    groups = {}
    for i in ids:
        groups.setdefault(find(i), []).append(i)
    bridges = {ip for ip, d in devices.items() if d["fdb"]}
    for root, members in groups.items():
        if root != find(hub):
            ls.add(max(members, key=lambda i: (i in bridges, degree[i])), hub, "inferred")

    data["hub"] = hub
    data["extra_nodes"] = list(extras.values())
    data["links"] = ls.output(set(ids))
    return data


def merge_scans(parts):
    me = parts[0]["self"]
    primary = next((p for p in parts if ipaddress.ip_address(me) in ipaddress.ip_network(p["cidr"])), parts[0])
    seen, hosts = set(), []
    for p in parts:
        for h in p["hosts"]:
            if h["ip"] not in seen:
                seen.add(h["ip"])
                hosts.append(h)
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return {"generated": parts[-1]["generated"], "duration_s": round(sum(p["duration_s"] for p in parts), 1),
            "cidr": ", ".join(p["cidr"] for p in parts), "networks": [p["cidr"] for p in parts],
            "gateway": primary["gateway"], "self": me, "methods": parts[0]["methods"], "hosts": hosts}


def resolve_community(value):
    if value and value.startswith("env:"):
        found = os.environ.get(value[4:])
        if not found:
            raise SystemExit(f"--snmp: environment variable {value[4:]} is not set")
        return found
    return value


# --------------------------------------------------------------------------- #
# Scan orchestration
# --------------------------------------------------------------------------- #
def progress(msg, end="\n"):
    print(msg, file=sys.stderr, end=end, flush=True)


def scan(network, ports, timeout, workers, resolve, methods, thorough,
         banners=True, udp=False, concurrency=400):
    started = time.time()
    me = local_ip()
    gw = default_gateway()
    targets = [str(h) for h in network.hosts()] or [str(network.network_address)]
    if me not in targets and ipaddress.ip_address(me) in network:
        targets.append(me)
    onlink = ipaddress.ip_address(me) in network
    progress(f"Discovering hosts in {network} ({len(targets)} addresses) using: {', '.join(methods)}")

    found = {}

    def hit(ip, via, rtt=None, name=""):
        d = found.setdefault(ip, {"rtt": None, "via": set(), "name": ""})
        d["via"].add(via)
        if rtt is not None and d["rtt"] is None:
            d["rtt"] = rtt
        if name and not d["name"]:
            d["name"] = name

    if me in targets:
        hit(me, "local")

    # 1. UDP name queries + multicast (these also make the OS ARP for every address)
    if "udp" in methods:
        progress("  NetBIOS / mDNS / UPnP...")
        for ip, (vias, name) in udp_sweep(targets, me, timeout + 1.5).items():
            for v in vias:
                hit(ip, v, name=name)

    # 2. ARP neighbour table: a live host on the same segment must answer ARP
    arp_covers_segment = False
    if "arp" in methods:
        progress("  ARP table...")
        if "udp" not in methods:
            arp_trigger(targets)
            time.sleep(max(1.5, timeout))
        table = read_arp_table()
        for ip in targets:
            if ip in table:
                hit(ip, "arp")
        arp_covers_segment = onlink and any(ip in table for ip in targets if ip != me)

    # 3. ICMP ping
    if "icmp" in methods:
        progress("  ping...")
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, rtt in zip(targets, pool.map(lambda x: ping(x, timeout), targets)):
                if rtt is not None:
                    hit(ip, "icmp", rtt)

    # 4. TCP connect probes for whatever is still unaccounted for
    if "tcp" in methods:
        remaining = [ip for ip in targets if ip not in found]
        if arp_covers_segment and not thorough:
            progress("  TCP sweep skipped: ARP already answers for every host on this segment (use --thorough to force)")
            remaining = []
        probe_ports = THOROUGH_PORTS if thorough else DISCOVERY_PORTS
        if remaining:
            progress(f"  TCP probes ({len(remaining)} addresses x {len(probe_ports)} ports)...")
            with cf.ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(tcp_probe, ip, p, timeout): ip for ip in remaining for p in probe_ports}
                for fut in cf.as_completed(futs):
                    state, rtt = fut.result()
                    if state:
                        hit(futs[fut], "tcp", rtt)

    alive = sorted(found, key=lambda x: ipaddress.ip_address(x))
    progress(f"{len(alive)} hosts up")

    states = {ip: {} for ip in alive}
    open_tcp = {ip: [] for ip in alive}
    if ports and alive:
        conc = fd_budget(concurrency)
        total = len(ports) * len(alive)
        progress(f"Scanning {len(ports)} TCP ports on {len(alive)} hosts ({total} probes, "
                 f"{conc} at a time; worst case about {int(total / conc * timeout) + 1} s)...")
        for (ip, port), st in asyncio.run(scan_tcp(ports, alive, timeout, conc)).items():
            states[ip][port] = st
            if st == "open":
                open_tcp[ip].append(port)

    details = {}
    pairs = [(ip, p) for ip in alive for p in sorted(open_tcp[ip])]
    if banners and pairs:
        progress(f"Identifying {len(pairs)} open services...")
        details = asyncio.run(identify_all(pairs, timeout))

    open_udp = {ip: [] for ip in alive}
    if udp and alive:
        progress("Checking UDP services (DNS, NTP, NetBIOS, UPnP, mDNS)...")
        open_udp = udp_ports(alive, timeout + 1.5)

    names = {}
    if resolve and alive:
        progress("Resolving hostnames...")
        with cf.ThreadPoolExecutor(max_workers=min(32, len(alive))) as pool:
            names = dict(zip(alive, pool.map(reverse_dns, alive)))

    arp = read_arp_table()
    hosts = []
    for ip in alive:
        tcp = sorted(open_tcp[ip])
        plist = []
        for p in tcp:
            d = details.get((ip, p), {})
            plist.append({"port": p, "proto": "tcp", "service": d.get("service") or service_name(p),
                          "banner": d.get("banner", ""), "tls": d.get("tls", "")})
        for p in sorted(open_udp.get(ip, [])):
            plist.append({"port": p, "proto": "udp", "service": UDP_PROBES[p][0], "banner": "", "tls": ""})
        hostname = names.get(ip) or found[ip]["name"]
        counts = list(states[ip].values())
        host = {
            "ip": ip,
            "hostname": hostname,
            "mac": arp.get(ip, ""),
            "rtt_ms": found[ip]["rtt"],
            "found_by": sorted(found[ip]["via"]),
            "ports": plist,
            "flags": [{"port": p, "note": RISKY[p]} for p in tcp if p in RISKY],
            "type": classify(tcp, hostname, ip == gw, ip == me),
        }
        if counts:
            host["port_summary"] = {k: counts.count(k) for k in ("open", "closed", "filtered")}
        hosts.append(host)

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1),
        "cidr": str(network),
        "gateway": gw,
        "self": me,
        "methods": list(methods),
        "hosts": hosts,
    }


# --------------------------------------------------------------------------- #
# HTML map
# --------------------------------------------------------------------------- #
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network map</title>
<style>
:root{
  --bg:#f3f5f7; --panel:#ffffff; --ink:#17212b; --muted:#5d6b78; --line:#c3ccd5; --rule:#dde3e8;
  --gateway:#1f5fbf; --switch:#0b6e8a; --self:#0e8f7e; --server:#6b5bd6; --windows:#2f86d4; --printer:#c98a12;
  --camera:#b5338a; --mobile:#d2553d; --iot:#4d9a3f; --unknown:#8a97a3; --network:#5d6b78; --warn:#d9480f;
}
@media (prefers-color-scheme:dark){
  :root{ --bg:#10161c; --panel:#18212a; --ink:#e8edf1; --muted:#93a1ad; --line:#334350; --rule:#26323c;
         --warn:#ff8a5c; --switch:#2fa3c4; --network:#93a1ad; --gateway:#4a8de0; }
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);display:grid;grid-template-columns:1fr 330px;grid-template-rows:auto 1fr;grid-template-areas:"top top" "map side"}
header{grid-area:top;display:flex;flex-wrap:wrap;gap:12px 28px;align-items:baseline;padding:14px 20px;border-bottom:1px solid var(--rule);background:var(--panel)}
header h1{font-size:16px;font-weight:650;margin:0}
header span{color:var(--muted)}
header b{color:var(--ink);font-weight:600}
#mapwrap{grid-area:map;position:relative;min-width:0;min-height:0}
svg{width:100%;height:100%;display:block;touch-action:none}
aside{grid-area:side;background:var(--panel);border-left:1px solid var(--rule);padding:16px 18px;overflow:auto}
aside h2{font-size:13px;font-weight:650;margin:18px 0 8px}
aside h2:first-child{margin-top:0}
input[type=search]{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
input[type=search]:focus-visible,button:focus-visible,.chip:focus-visible,g.node:focus-visible{outline:2px solid var(--gateway);outline-offset:2px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;gap:6px;align-items:center;padding:4px 9px;border:1px solid var(--line);border-radius:99px;background:none;color:var(--ink);font:inherit;font-size:12.5px;cursor:pointer}
.chip i{width:9px;height:9px;border-radius:50%;background:var(--c)}
.chip[aria-pressed=false]{opacity:.45}
dl{margin:0;display:grid;grid-template-columns:92px 1fr;gap:6px 10px}
dt{color:var(--muted)}
dd{margin:0;word-break:break-word}
.plist{list-style:none;margin:0;padding:0}
.plist li{padding:7px 0;border-bottom:1px solid var(--rule)}
.pn{font-weight:600}
.pb{color:var(--muted);font-size:12.5px;word-break:break-word}
.conn{display:block;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid var(--rule);padding:7px 0;color:var(--ink);font:inherit;cursor:pointer}
.conn:hover .cn{text-decoration:underline}
.conn .cn{font-weight:600}
.conn .cs{display:block;color:var(--muted);font-size:12.5px}
.hint{color:var(--muted)}
.link{stroke:var(--line);stroke-width:1.5}
.link.dash{stroke-dasharray:4 5}
.link.hl{stroke:var(--ink);stroke-width:2}
.lp{fill:var(--muted);font-size:11px;text-anchor:middle;paint-order:stroke;stroke:var(--bg);stroke-width:4px;display:none;pointer-events:none}
.lp.on{display:block}
.node .body{fill:var(--c);stroke:var(--bg);stroke-width:3}
.node .halo{fill:none;stroke:var(--c);stroke-opacity:.35;stroke-width:1.5}
.node circle.flag{fill:var(--warn);stroke:var(--bg);stroke-width:2}
.node text{fill:var(--ink);font-size:12px;text-anchor:middle;pointer-events:none;paint-order:stroke;stroke:var(--bg);stroke-width:4px}
.node text.sub{fill:var(--muted);font-size:11px}
.node{cursor:grab}
.node.sel .body{stroke:var(--ink)}
.dim{opacity:.15}
.hide{display:none}
@media (max-width:760px){
  body{grid-template-columns:1fr;grid-template-rows:auto 1fr auto;grid-template-areas:"top" "map" "side"}
  aside{border-left:0;border-top:1px solid var(--rule);max-height:42vh}
}
</style>
</head>
<body>
<header>
  <h1>Network map</h1>
  <span>Range <b id="h-cidr"></b></span>
  <span>Hosts up <b id="h-count"></b></span>
  <span>Topology <b id="h-topo"></b></span>
  <span>With flagged ports <b id="h-flag"></b></span>
  <span>Scanned <b id="h-when"></b></span>
</header>
<div id="mapwrap"><svg id="map" role="img" aria-label="Network map"></svg></div>
<aside>
  <h2>Find a device</h2>
  <input type="search" id="q" placeholder="IP, name, MAC, port or banner" aria-label="Find a device">
  <h2>Device types</h2>
  <div class="chips" id="chips"></div>
  <h2 id="dtitle">Details</h2>
  <div id="detail"><p class="hint">Select a device to see its address, connections and open ports. Drag devices to rearrange them. Square nodes are network equipment.</p></div>
</aside>
<script>
const DATA = __DATA__;
const TYPES = {
  gateway:"Router", switch:"Switch", self:"This device", server:"Server", windows:"Windows PC", printer:"Printer",
  camera:"Camera", mobile:"Phone / tablet", iot:"Web-enabled device", unknown:"Unidentified", network:"Network"
};
const VIA = {arp:"ARP", icmp:"ping", tcp:"TCP connect", nbns:"NetBIOS", mdns:"mDNS", ssdp:"UPnP", snmp:"SNMP", local:"this machine"};
const LINKVIA = {fdb:"the switch's MAC table", lldp:"LLDP", traceroute:"traceroute", subnet:"subnet membership", inferred:"assumed, no switch data"};
const INFRA = new Set(["gateway", "switch", "network"]);
const NS = "http://www.w3.org/2000/svg";
const svg = document.getElementById("map");
const $ = id => document.getElementById(id);
const el = (name, attrs = {}, parent) => {
  const e = document.createElementNS(NS, name);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
};
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const W = () => svg.clientWidth, H = () => svg.clientHeight;

// ---- Build the graph ------------------------------------------------------
const nodes = DATA.hosts.map(h => ({...h, id: h.ip, ports: h.ports || [], flags: h.flags || []}));
(DATA.extra_nodes || []).forEach(e => nodes.push({
  id: e.id, ip: e.ip || "", hostname: "", mac: "", ports: [], flags: [], found_by: [],
  type: e.type, label: e.label, note: e.note || "", virtual: true
}));
let hub = nodes.find(n => n.id === DATA.hub) || nodes.find(n => n.type === "gateway");
if (!hub) {
  hub = {id: "__hub__", ip: "", hostname: "", mac: "", ports: [], flags: [], found_by: [], type: "network",
         label: DATA.cidr, note: "No gateway was found, so the range is drawn as the centre.", virtual: true};
  nodes.unshift(hub);
}
const byId = new Map(nodes.map(n => [n.id, n]));
const links = (DATA.links || []).map(l => ({...l, na: byId.get(l.a), nb: byId.get(l.b)})).filter(l => l.na && l.nb);
const adj = new Map(nodes.map(n => [n.id, []]));
links.forEach(l => { adj.get(l.a).push(l); adj.get(l.b).push(l); });

nodes.forEach(n => { n.depth = -1; n.children = []; n.size = 1; });
const order = [];
function grow(root) {
  order.push(root);
  for (let i = order.indexOf(root); i < order.length; i++) {
    const u = order[i];
    adj.get(u.id).forEach(l => {
      const v = l.na === u ? l.nb : l.na;
      if (v.depth < 0) { v.depth = u.depth + 1; v.parent = u; u.children.push(v); order.push(v); }
    });
  }
}
hub.depth = 0; grow(hub);
for (;;) {  // anything unreachable hangs off the hub as an assumed link
  const rest = nodes.filter(n => n.depth < 0);
  if (!rest.length) break;
  const rep = rest.reduce((a, b) => adj.get(b.id).length > adj.get(a.id).length ? b : a);
  const l = {a: hub.id, b: rep.id, na: hub, nb: rep, via: "inferred", a_port: "", b_port: ""};
  links.push(l); adj.get(hub.id).push(l); adj.get(rep.id).push(l);
  rep.depth = 1; rep.parent = hub; hub.children.push(rep); grow(rep);
}
for (let i = order.length - 1; i > 0; i--) order[i].parent.size += order[i].size;
const anyReal = links.some(l => l.via !== "inferred");

$("h-cidr").textContent = DATA.cidr;
$("h-count").textContent = DATA.hosts.length;
$("h-flag").textContent = DATA.hosts.filter(h => h.flags && h.flags.length).length;
$("h-topo").textContent = anyReal ? links.filter(l => l.via !== "inferred").length + " measured links" : "assumed from the gateway";
$("h-when").textContent = DATA.generated.replace("T", " ") + " (" + DATA.duration_s + " s)";

const nodeLabel = n => n.label || (n.hostname ? n.hostname.split(".")[0] : n.ip);
const linkLayer = el("g", {}, svg);
const nodeLayer = el("g", {}, svg);
links.forEach(l => {
  l.line = el("line", {class: "link" + (anyReal && l.via === "inferred" ? " dash" : "")}, linkLayer);
  l.ta = el("text", {class: "lp"}, linkLayer); l.ta.textContent = l.a_port || "";
  l.tb = el("text", {class: "lp"}, linkLayer); l.tb.textContent = l.b_port || "";
});
nodes.forEach(n => {
  n.r = n === hub ? 24 : n.type === "switch" ? 18 : n.type === "network" ? 16 : 11 + Math.min(n.ports.length, 6) * 1.5;
  const g = el("g", {class: "node", tabindex: 0, role: "button", "aria-label": nodeLabel(n) + ", " + TYPES[n.type]}, nodeLayer);
  g.style.setProperty("--c", "var(--" + n.type + ")");
  const infra = INFRA.has(n.type);
  const shape = (cls, r) => infra
    ? el("rect", {class: cls, x: -r, y: -r, width: 2 * r, height: 2 * r, rx: Math.round(r * 0.38)}, g)
    : el("circle", {class: cls, r}, g);
  if (n.ports.length) shape("halo", n.r + 6);
  shape("body", n.r);
  if (n.flags.length) el("circle", {class: "flag", r: 5.5, cx: n.r * 0.72, cy: -n.r * 0.72}, g);
  const name = nodeLabel(n);
  const t1 = el("text", {y: n.r + 16}, g); t1.textContent = name.length > 18 ? name.slice(0, 17) + "…" : name;
  if (n.hostname && !n.virtual && n.ip) { const t2 = el("text", {class: "sub", y: n.r + 29}, g); t2.textContent = n.ip; }
  n.g = g;
  g.addEventListener("click", () => select(n));
  g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(n); } });
  g.addEventListener("pointerdown", e => startDrag(e, n));
});

// ---- Layout and physics ---------------------------------------------------
function layout() {
  const cx = W() / 2, cy = H() / 2;
  const maxDepth = Math.max(1, ...nodes.map(n => n.depth));
  const ring = Math.min(W(), H()) * 0.42 / maxDepth;
  (function place(n, a0, a1) {
    const a = (a0 + a1) / 2;
    n.x = cx + Math.cos(a) * ring * n.depth; n.y = cy + Math.sin(a) * ring * n.depth; n.vx = n.vy = 0;
    let start = a0;
    n.children.forEach(c => { const span = (a1 - a0) * c.size / (n.size - 1); place(c, start, start + span); start += span; });
  })(hub, 0, 2 * Math.PI);
  const hubRest = Math.min(Math.min(W(), H()) * 0.4, 110 + hub.children.length * 4);
  links.forEach(l => {
    const child = l.na.depth > l.nb.depth ? l.na : l.nb;
    const parent = child === l.na ? l.nb : l.na;
    l.rest = clamp(55 + 20 * Math.sqrt(child.size), 70, 200);
    if (parent === hub) l.rest = Math.max(l.rest, hubRest);
  });
}
let alpha = 1, drag = null, selected = null, running = false;
function step() {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy || 0.01;
      if (d2 > 90000) continue;
      const d = Math.sqrt(d2), f = (4200 / d2) * alpha;
      dx /= d; dy /= d;
      a.vx -= dx * f; a.vy -= dy * f; b.vx += dx * f; b.vy += dy * f;
    }
  }
  links.forEach(l => {
    const dx = l.nb.x - l.na.x, dy = l.nb.y - l.na.y, d = Math.hypot(dx, dy) || 1, f = (d - l.rest) * 0.03 * alpha;
    l.na.vx += (dx / d) * f; l.na.vy += (dy / d) * f; l.nb.vx -= (dx / d) * f; l.nb.vy -= (dy / d) * f;
  });
  hub.vx += (W() / 2 - hub.x) * 0.02; hub.vy += (H() / 2 - hub.y) * 0.02;
  nodes.forEach(n => {
    if (n === drag) { n.vx = n.vy = 0; return; }
    n.vx *= 0.8; n.vy *= 0.8;
    n.x = clamp(n.x + n.vx, 40, W() - 40); n.y = clamp(n.y + n.vy, 40, H() - 50);
  });
  alpha *= 0.985;
}
function draw() {
  links.forEach(l => {
    const {na: a, nb: b} = l;
    l.line.setAttribute("x1", a.x); l.line.setAttribute("y1", a.y); l.line.setAttribute("x2", b.x); l.line.setAttribute("y2", b.y);
    l.ta.setAttribute("x", a.x + (b.x - a.x) * 0.3); l.ta.setAttribute("y", a.y + (b.y - a.y) * 0.3 - 4);
    l.tb.setAttribute("x", a.x + (b.x - a.x) * 0.7); l.tb.setAttribute("y", a.y + (b.y - a.y) * 0.7 - 4);
  });
  nodes.forEach(n => n.g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")"));
}
function loop() {
  if (alpha > 0.02 || drag) { step(); draw(); requestAnimationFrame(loop); } else { running = false; }
}
function reheat(a) { alpha = Math.max(alpha, a); if (!running) { running = true; requestAnimationFrame(loop); } }
function startDrag(e, n) {
  drag = n; n.g.setPointerCapture(e.pointerId); n.g.style.cursor = "grabbing";
  const move = ev => {
    const r = svg.getBoundingClientRect();
    n.x = clamp(ev.clientX - r.left, 30, W() - 30); n.y = clamp(ev.clientY - r.top, 30, H() - 30);
    draw(); reheat(0.3);
  };
  const up = () => {
    drag = null; n.g.style.cursor = "";
    n.g.removeEventListener("pointermove", move); n.g.removeEventListener("pointerup", up);
  };
  n.g.addEventListener("pointermove", move); n.g.addEventListener("pointerup", up);
}

// ---- Details panel --------------------------------------------------------
function row(dl, k, v) {
  const dt = document.createElement("dt"); dt.textContent = k;
  const dd = document.createElement("dd"); dd.textContent = v || "unknown";
  dl.append(dt, dd);
}
function heading(box, text) { const h = document.createElement("h2"); h.textContent = text; box.appendChild(h); }
function uptime(s) { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600); return d ? d + " d " + h + " h" : h + " h " + Math.floor(s % 3600 / 60) + " min"; }
function select(n) {
  if (selected) selected.g.classList.remove("sel");
  selected = n; n.g.classList.add("sel");
  links.forEach(l => {
    const on = l.na === n || l.nb === n;
    l.line.classList.toggle("hl", on); l.ta.classList.toggle("on", on); l.tb.classList.toggle("on", on);
  });
  const box = $("detail"); box.textContent = "";
  $("dtitle").textContent = nodeLabel(n);
  const dl = document.createElement("dl");
  if (n.ip) row(dl, "Address", n.ip);
  if (n.hostname) row(dl, "Hostname", n.hostname);
  if (!n.virtual) row(dl, "MAC", n.mac);
  row(dl, "Type", TYPES[n.type] + (n.type === "unknown" || n.type === "iot" ? " (a guess from open ports)" : ""));
  if (n.snmp) {
    if (n.snmp.sys_descr) row(dl, "Description", n.snmp.sys_descr);
    row(dl, "Uptime", uptime(n.snmp.uptime_s));
    row(dl, "Learned MACs", n.snmp.macs_learned + " addresses, " + n.snmp.lldp_neighbours + " LLDP neighbours");
  }
  if (n.rtt_ms != null) row(dl, "Response", n.rtt_ms + " ms");
  if (n.found_by && n.found_by.length) row(dl, "Found by", n.found_by.map(m => VIA[m] || m).join(", "));
  if (n.port_summary) row(dl, "Port scan", n.port_summary.open + " open, " + n.port_summary.closed + " closed, " + n.port_summary.filtered + " filtered");
  box.appendChild(dl);
  if (n.note) { const p = document.createElement("p"); p.className = "hint"; p.textContent = n.note; box.appendChild(p); }

  const mine = adj.get(n.id);
  if (mine.length) {
    heading(box, "Connections");
    mine.forEach(l => {
      const other = l.na === n ? l.nb : l.na;
      const here = l.na === n ? l.a_port : l.b_port, there = l.na === n ? l.b_port : l.a_port;
      const btn = document.createElement("button"); btn.className = "conn"; btn.type = "button";
      const cn = document.createElement("span"); cn.className = "cn"; cn.textContent = nodeLabel(other);
      const parts = [];
      if (there) parts.push("port " + there + " on " + nodeLabel(other));
      if (here) parts.push("this device's port " + here);
      parts.push("from " + LINKVIA[l.via]);
      const cs = document.createElement("span"); cs.className = "cs"; cs.textContent = parts.join(", ");
      btn.append(cn, cs); btn.addEventListener("click", () => select(other)); box.appendChild(btn);
    });
  }
  if (!n.virtual) {
    heading(box, "Open ports");
    if (n.ports.length) {
      const ul = document.createElement("ul"); ul.className = "plist";
      n.ports.forEach(p => {
        const li = document.createElement("li");
        const head = document.createElement("span"); head.className = "pn";
        head.textContent = p.port + "/" + (p.proto || "tcp") + " " + p.service + (p.tls ? " (" + p.tls + ")" : "");
        li.appendChild(head);
        if (p.banner) { const b = document.createElement("div"); b.className = "pb"; b.textContent = p.banner; li.appendChild(b); }
        ul.appendChild(li);
      });
      box.appendChild(ul);
    } else {
      const p = document.createElement("p"); p.className = "hint"; p.textContent = "No open ports found among the ports scanned."; box.appendChild(p);
    }
    if (n.flags.length) {
      heading(box, "Worth checking");
      const ul2 = document.createElement("ul"); ul2.className = "plist";
      n.flags.forEach(f => { const li = document.createElement("li"); li.textContent = "Port " + f.port + ": " + f.note; ul2.appendChild(li); });
      box.appendChild(ul2);
    }
  }
}

// ---- Filters --------------------------------------------------------------
const hidden = new Set();
[...new Set(nodes.map(n => n.type))].forEach(t => {
  const b = document.createElement("button");
  b.className = "chip"; b.setAttribute("aria-pressed", "true"); b.style.setProperty("--c", "var(--" + t + ")");
  b.append(document.createElement("i"), document.createTextNode(TYPES[t] + " " + nodes.filter(n => n.type === t).length));
  b.addEventListener("click", () => {
    hidden.has(t) ? hidden.delete(t) : hidden.add(t);
    b.setAttribute("aria-pressed", hidden.has(t) ? "false" : "true"); applyFilter();
  });
  $("chips").appendChild(b);
});
function matches(n, q) {
  if (!q) return true;
  const hay = [n.id, n.ip, n.label, n.hostname, n.mac, n.type, ...n.ports.map(p => [p.port, p.service, p.banner].join(" "))].join(" ").toLowerCase();
  return q.split(/\s+/).every(w => hay.includes(w));
}
function applyFilter() {
  const q = $("q").value.trim().toLowerCase();
  nodes.forEach(n => {
    n.g.classList.toggle("hide", hidden.has(n.type) && n !== hub);
    n.g.classList.toggle("dim", !matches(n, q));
  });
  links.forEach(l => {
    l.line.classList.toggle("hide", (hidden.has(l.na.type) && l.na !== hub) || (hidden.has(l.nb.type) && l.nb !== hub));
    l.line.classList.toggle("dim", !matches(l.na, q) && !matches(l.nb, q));
  });
}
$("q").addEventListener("input", applyFilter);

layout(); draw(); reheat(1);
addEventListener("resize", () => { layout(); reheat(1); });
if (nodes.length === 1) $("detail").insertAdjacentHTML("beforeend", "<p class='hint'>No hosts answered. Check the range, or that this machine can reach it.</p>");
</script>
</body>
</html>
"""


def write_html(data, path):
    payload = json.dumps(data).replace("</", "<\\/")  # keep hostnames from closing the script tag
    Path(path).write_text(HTML.replace("__DATA__", payload), encoding="utf-8")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_ports(spec):
    spec = spec.strip().lower()
    if spec in ("none", "off", ""):
        return []
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "top":
        return sorted(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    usage = "use top, common, all, none, or a list like 22,80,8000-8100"
    ports = set()
    try:
        for part in spec.split(","):
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                ports.update(range(lo, hi + 1))
            else:
                ports.add(int(part))
    except ValueError:
        raise argparse.ArgumentTypeError(usage)
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535 (" + usage + ")")
    return sorted(ports)


def parse_methods(spec):
    chosen = [m.strip().lower() for m in spec.split(",") if m.strip()]
    bad = [m for m in chosen if m not in METHODS]
    if bad or not chosen:
        raise argparse.ArgumentTypeError(f"choose from: {', '.join(METHODS)}")
    return [m for m in METHODS if m in chosen]


def main():
    ap = argparse.ArgumentParser(description="Scan a network and draw an interactive map.")
    ap.add_argument("target", nargs="*", help="CIDR range(s), e.g. 192.168.1.0/24 (default: your local /24)")
    ap.add_argument("--ports", type=parse_ports, default="top", metavar="SPEC",
                    help="TCP ports to scan: top (default, ~100), common, all, none, or e.g. 22,80,8000-8100")
    ap.add_argument("--udp", action="store_true", help="also probe DNS, NTP, NetBIOS, UPnP and mDNS over UDP")
    ap.add_argument("--no-banners", action="store_true", help="don't identify services on open ports")
    ap.add_argument("--concurrency", type=int, default=400, help="simultaneous port probes (default 400)")
    ap.add_argument("--methods", type=parse_methods, default=list(METHODS), metavar="LIST",
                    help="discovery methods, comma separated: arp,udp,icmp,tcp (default: all)")
    ap.add_argument("--thorough", action="store_true",
                    help="probe many more TCP ports and don't skip the TCP sweep when ARP covers the segment")
    ap.add_argument("--snmp", metavar="COMMUNITY",
                    help="read-only SNMP v2c community for switch topology; use env:NAME to read it from an "
                         "environment variable so it stays out of your shell history. It is sent unencrypted.")
    ap.add_argument("--snmp-hosts", default="gateway", metavar="LIST",
                    help="devices to query: gateway (default), all, or IPs like 10.0.0.2,10.0.0.3")
    ap.add_argument("--snmp-port", type=int, default=161, help=argparse.SUPPRESS)
    ap.add_argument("--snmp-timeout", type=float, default=2.0, help="seconds to wait for each SNMP reply (default 2)")
    ap.add_argument("--no-trace", action="store_true", help="don't traceroute to subnets outside your own segment")
    ap.add_argument("--timeout", type=float, default=1.0, help="seconds to wait per probe (default 1.0)")
    ap.add_argument("--workers", type=int, default=128, help="parallel probes (default 128)")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    ap.add_argument("-o", "--output", default="netmap.html", help="HTML map to write (default netmap.html)")
    ap.add_argument("--json", metavar="FILE", help="also save raw results as JSON")
    ap.add_argument("--load", metavar="FILE", help="skip scanning; build the map from a saved JSON file")
    ap.add_argument("--max-hosts", type=int, default=1024, help="refuse larger ranges unless --force")
    ap.add_argument("--force", action="store_true", help="allow ranges above --max-hosts")
    ap.add_argument("--allow-public", action="store_true",
                    help="allow non-private ranges (only if you are authorised to scan them)")
    args = ap.parse_args()
    ports = parse_ports(args.ports) if isinstance(args.ports, str) else args.ports

    if args.load:
        data = json.loads(Path(args.load).read_text(encoding="utf-8"))
    else:
        nets = []
        for text in args.target or [f"{local_ip()}/24"]:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError as e:
                ap.error(str(e))
            if network.version != 4:
                ap.error("only IPv4 ranges are supported")
            if not (network.is_private or network.is_loopback or network.is_link_local) and not args.allow_public:
                ap.error(f"{network} is not a private range. Scan only networks you are authorised to test; "
                         "pass --allow-public to override.")
            if network.num_addresses > args.max_hosts and not args.force:
                ap.error(f"{network} has {network.num_addresses} addresses (limit {args.max_hosts}). Use --force to scan anyway.")
            nets.append(network)
        progress("Only scan networks you own or have permission to scan.")
        parts = [scan(net, ports, args.timeout, args.workers, not args.no_dns, args.methods, args.thorough,
                      banners=not args.no_banners, udp=args.udp, concurrency=max(1, args.concurrency))
                 for net in nets]
        data = merge_scans(parts)
        add_topology(data, resolve_community(args.snmp), args.snmp_hosts, args.snmp_port,
                     args.snmp_timeout, not args.no_trace, args.timeout)
        if args.json:
            Path(args.json).write_text(json.dumps(data, indent=2), encoding="utf-8")

    write_html(data, args.output)
    print(f"{len(data['hosts'])} hosts up. Map written to {Path(args.output).resolve()}")
    for h in data["hosts"]:
        ports = ",".join(str(p["port"]) + ("u" if p.get("proto") == "udp" else "") for p in h["ports"]) or "-"
        via = ",".join(h.get("found_by", [])) or "-"
        print(f"  {h['ip']:<16} {h['type']:<8} {h['mac'] or '-':<18} {h['hostname'] or '-':<26} via {via:<18} ports: {ports}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
