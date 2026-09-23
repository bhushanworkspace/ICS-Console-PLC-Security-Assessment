#!/usr/bin/env python3
"""
ICS Console - PLC / OT Network Security Assessment (Wireshark-style edition)
===========================================================================

Defensive asset-discovery + vulnerability-assessment for industrial control
networks, with a local web dashboard that includes a Wireshark-style packet
inspector for the probe traffic it sends/receives.

  * Zero pip dependencies - Python 3.8+ standard library only.
  * Runs offline - safe for air-gapped OT. No external CDNs.
  * Read-only assessment - it identifies, decodes, and reports. It does NOT
    exploit, fuzz, write to controllers, or send state-changing commands.

RUN
---
    python3 ics_console.py        # keep ics_console.html in the same folder
    # then open http://127.0.0.1:8800

Only scan equipment you OWN or are AUTHORIZED to test. Use Gentle on live gear.
"""

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ics_console.html")

# ===========================================================================
# REFERENCE DATA
# ===========================================================================
# port: (name, transport, note)
ICS_PORTS = {
    102:   ("S7comm",      "tcp", "Siemens S7 (ISO-TSAP): programming/data, no native auth"),
    502:   ("Modbus/TCP",  "tcp", "Modbus: cleartext, no authentication in base protocol"),
    789:   ("Red Lion",    "tcp", "Red Lion Crimson"),
    1200:  ("CODESYS",     "tcp", "CODESYS runtime: check firmware for known CVEs"),
    1911:  ("Niagara Fox", "tcp", "Tridium Niagara building automation"),
    2404:  ("IEC-104",     "tcp", "IEC 60870-5-104 telecontrol: cleartext"),
    4840:  ("OPC UA",      "tcp", "OPC UA: securable - verify it actually is"),
    9600:  ("OMRON FINS",  "tcp", "Omron FINS: cleartext"),
    20000: ("DNP3",        "tcp", "DNP3: often cleartext; Secure Auth (SAv5) optional"),
    44818: ("EtherNet/IP", "tcp", "EtherNet/IP explicit (CIP): Rockwell/Allen-Bradley"),
}

GUIDANCE = {
    "Modbus/TCP":  "No auth/encryption in base protocol. Restrict to a dedicated VLAN, "
                   "firewall to known masters, consider a Modbus security gateway.",
    "S7comm":      "Programming access. Enable access/know-how protection on the PLC, "
                   "segment the cell network, disable unused services.",
    "EtherNet/IP": "Exposed CIP. Use CIP Security where supported, segment with managed "
                   "switches/firewalls, keep controllers in RUN via keyswitch.",
    "DNP3":        "Enable DNP3 Secure Authentication (SAv5) and isolate the link.",
    "IEC-104":     "Cleartext telecontrol. Tunnel over VPN/TLS, restrict by firewall.",
    "OPC UA":      "Ensure endpoints enforce Sign&Encrypt and anonymous access is disabled.",
    "CODESYS":     "Runtime has had multiple CVEs. Verify firmware and patch.",
    "Niagara Fox": "Change default credentials, patch Niagara, restrict exposure.",
    "OMRON FINS":  "Cleartext. Segment, firewall, restrict node access.",
    "Red Lion":    "Change defaults, patch firmware, restrict network exposure.",
}

# Pointers to authoritative advisory sources (no fabricated CVE IDs).
ADVISORIES = {
    "Modbus/TCP":  "CISA ICS guidance on Modbus exposure; NVD search 'Modbus'.",
    "S7comm":      "Siemens ProductCERT advisories for your CPU/firmware.",
    "EtherNet/IP": "Rockwell PSIRT + CISA ICS advisories for the product/revision.",
    "CODESYS":     "CODESYS Security Advisories; verify firmware version.",
    "OPC UA":      "OPC Foundation security bulletins; confirm SecurityPolicy.",
    "DNP3":        "CISA ICS advisories; vendor DNP3 stack notices.",
    "Niagara Fox": "Tridium/Honeywell advisories; check Niagara build.",
    "OMRON FINS":  "Omron security advisories; CISA ICS advisories.",
    "IEC-104":     "CISA ICS advisories for IEC 60870-5-104 stacks.",
    "Red Lion":    "Red Lion security advisories; CISA ICS advisories.",
}

HIGH_RISK = {"S7comm", "EtherNet/IP", "CODESYS", "Niagara Fox", "Red Lion"}


# ===========================================================================
# PACKET HELPERS
# ===========================================================================
def _hexdump(b):
    return " ".join(f"{x:02x}" for x in b)


def _asciidump(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def _pkt(direction, src, dst, proto, info, data, fields):
    return {"t": time.time(), "dir": direction, "src": src, "dst": dst,
            "proto": proto, "length": len(data), "info": info,
            "hex": _hexdump(data), "ascii": _asciidump(data), "fields": fields}


# ---- protocol identity parsers (read-only) --------------------------------
def parse_eip(data):
    info = {}
    try:
        body = data[24:]
        _, item_len = struct.unpack_from("<HH", body, 2)
        item = body[6:6 + item_len]
        p = 18
        vid, dtype, pcode = struct.unpack_from("<HHH", item, p); p += 6
        rmaj, rmin = item[p], item[p + 1]; p += 2
        p += 2
        serial = struct.unpack_from("<I", item, p)[0]; p += 4
        nlen = item[p]; p += 1
        name = item[p:p + nlen].decode("latin-1", "replace")
        info = {"vendor_id": vid, "device_type": dtype, "product_code": pcode,
                "revision": f"{rmaj}.{rmin}", "serial": f"0x{serial:08X}",
                "product_name": name}
    except (struct.error, IndexError):
        pass
    return info


def parse_modbus(data):
    info = {}
    try:
        if len(data) < 14 or data[7] != 0x2B:
            return info
        num, off = data[13], 14
        names = {0: "vendor", 1: "product_code", 2: "revision", 4: "product_name", 5: "model"}
        for _ in range(num):
            if off + 2 > len(data):
                break
            oid, olen = data[off], data[off + 1]; off += 2
            val = data[off:off + olen].decode("latin-1", "replace"); off += olen
            info[names.get(oid, f"obj_{oid}")] = val
    except (IndexError, ValueError):
        pass
    return info


# ---- request payloads ------------------------------------------------------
EIP_REQ = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
MODBUS_REQ = struct.pack(">HHHB", 1, 0, 5, 0) + bytes([0x2B, 0x0E, 0x01, 0x00])
S7_CR = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
               0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02])


# ---- response decoders (-> info string, [(field,value)...]) ----------------
def decode_eip(data):
    fields, info = [], "EtherNet/IP reply"
    try:
        cmd, length, sess, status = struct.unpack_from("<HHII", data, 0)
        fields = [("Command", f"0x{cmd:04x} (List Identity)"), ("Length", str(length)),
                  ("Session", f"0x{sess:08x}"), ("Status", f"0x{status:08x}")]
        ident = parse_eip(data)
        for k, v in ident.items():
            fields.append((k, str(v)))
        if ident.get("product_name"):
            info = "List Identity reply - " + ident["product_name"]
    except struct.error:
        pass
    return info, fields


def decode_modbus(data):
    fields, info = [], "Modbus reply"
    try:
        txn, proto, length = struct.unpack_from(">HHH", data, 0)
        unit, func = data[6], data[7]
        fields = [("Transaction", str(txn)), ("Protocol", str(proto)),
                  ("Length", str(length)), ("Unit", str(unit)), ("Function", f"0x{func:02x}")]
        if func & 0x80:
            fields.append(("Exception", f"0x{data[8]:02x}")); info = "Modbus exception"
        elif func == 0x2B:
            ident = parse_modbus(data)
            for k, v in ident.items():
                fields.append((k, str(v)))
            info = "Read Device ID reply" + (" - " + ident["vendor"] if ident.get("vendor") else "")
    except (struct.error, IndexError):
        pass
    return info, fields


def decode_cotp(data):
    fields, info = [], "S7 ISO-TSAP reply"
    try:
        if len(data) >= 6 and data[0] == 0x03:
            tlen = struct.unpack_from(">H", data, 2)[0]
            pdu = data[5]
            names = {0xD0: "Connection Confirm", 0x80: "Disconnect Request"}
            fields = [("TPKT version", str(data[0])), ("TPKT length", str(tlen)),
                      ("COTP PDU", f"0x{pdu:02x} {names.get(pdu, '')}".strip())]
            info = "S7 ISO-TSAP " + names.get(pdu, "response")
    except (struct.error, IndexError):
        pass
    return info, fields


# port: (payload, proto, tx_info, [(field,value)...], decode_fn, identity_fn|None)
PROBES = {
    502:   (MODBUS_REQ, "Modbus/TCP", "Read Device ID request",
            [("Transaction", "1"), ("Protocol", "0"), ("Unit", "0"),
             ("Function", "0x2B Read Device ID"), ("MEI", "0x0E")], decode_modbus, parse_modbus),
    44818: (EIP_REQ, "EtherNet/IP", "List Identity request",
            [("Command", "0x0063 List Identity"), ("Length", "0"),
             ("Session", "0x00000000")], decode_eip, parse_eip),
    102:   (S7_CR, "S7comm", "COTP Connection Request",
            [("TPKT version", "3"), ("COTP PDU", "0xE0 Connection Request"),
             ("Dst TSAP", "0x0102 (rack0/slot2)")], decode_cotp, None),
}


# ===========================================================================
# SCAN ENGINE
# ===========================================================================
def tcp_open(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def probe(ip, port, payload, timeout):
    resp, err = b"", None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(payload)
            resp = s.recv(2048)
    except OSError as e:
        err = str(e)
    return resp, err


def scan_host(ip, ports, timeout):
    open_ports, services, findings, packets, events = [], [], [], [], []
    for port in ports:
        if tcp_open(ip, port, timeout):
            open_ports.append(port)
        else:
            events.append({"level": "info", "msg": f"{ip}:{port} closed / filtered"})

    for port in sorted(open_ports):
        name, _, note = ICS_PORTS[port]
        entry = {"port": port, "protocol": name, "note": note}
        events.append({"level": "ok", "msg": f"{ip}:{port} OPEN - {name}"})

        spec = PROBES.get(port)
        if spec:
            payload, proto, tx_info, tx_fields, decode_fn, ident_fn = spec
            packets.append(_pkt("TX", "local", ip, proto, tx_info, payload, tx_fields))
            resp, err = probe(ip, port, payload, timeout)
            if err:
                events.append({"level": "warn", "msg": f"{ip}:{port} {proto} probe: {err}"})
            if resp:
                info, fields = decode_fn(resp)
                packets.append(_pkt("RX", ip, "local", proto, info, resp, fields))
                if ident_fn:
                    ident = ident_fn(resp)
                    if ident:
                        entry["identity"] = ident

        services.append(entry)

        sev = "HIGH" if name in HIGH_RISK else "MEDIUM"
        findings.append({
            "host": ip, "port": port, "protocol": name, "severity": sev,
            "issue": ("Programming/control protocol reachable - review segmentation."
                      if sev == "HIGH" else "Insecure-by-default ICS service exposed."),
            "guidance": GUIDANCE.get(name, "Segment and firewall this service."),
            "advisory": ADVISORIES.get(name, ""),
        })
        if entry.get("identity"):
            ident = entry["identity"]
            tag = " ".join(str(ident.get(k, "")) for k in
                           ("vendor", "product_name", "model", "revision") if ident.get(k)).strip()
            if tag:
                findings.append({
                    "host": ip, "port": port, "protocol": name, "severity": "INFO",
                    "issue": f"Identified: {tag}",
                    "guidance": f"Cross-check {tag} against advisories.",
                    "advisory": ADVISORIES.get(name, "NVD / CISA ICS advisories."),
                })

    return {"host": ip, "open_ports": sorted(open_ports), "services": services,
            "findings": findings, "packets": packets, "events": events}


def expand_targets(target):
    out = []
    for chunk in str(target).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "/" in chunk:
                net = ipaddress.ip_network(chunk, strict=False)
                out += [str(h) for h in net.hosts()] or [str(net.network_address)]
            else:
                out.append(str(ipaddress.ip_address(chunk)))
        except ValueError:
            pass
    return out


# ===========================================================================
# HTTP SERVER
# ===========================================================================
def load_html():
    try:
        with open(HTML_PATH, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ("<h1>ics_console.html not found</h1>"
                "<p>Keep <code>ics_console.html</code> in the same folder as "
                "<code>ics_console.py</code>, then reload.</p>")


class Handler(BaseHTTPRequestHandler):
    server_version = "ICSConsole/2.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, load_html(), "text/html; charset=utf-8")
        elif self.path == "/health":
            self._send(200, {"ok": True, "version": self.server_version})
        else:
            self._send(404, {"error": "Not found"})

    def do_POST(self):
        data = self._read_json()
        if self.path == "/api/targets":
            hosts = expand_targets(data.get("target", ""))
            if len(hosts) > 4096:
                self._send(200, {"hosts": [], "error": "Range too large (>4096). Narrow it."})
            else:
                self._send(200, {"hosts": hosts})
        elif self.path == "/api/scan_host":
            ip = str(data.get("ip", "")).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self._send(400, {"error": "Invalid IP"})
                return
            gentle = bool(data.get("gentle", True))
            timeout = 4.0 if gentle else 1.5
            ports = [p for p, v in ICS_PORTS.items() if v[1] == "tcp"]
            self._send(200, scan_host(ip, ports, timeout))
        else:
            self._send(404, {"error": "Not found"})


def main():
    ap = argparse.ArgumentParser(description="ICS Console - PLC/OT assessment dashboard.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    url = f"http://{args.host}:{args.port}"
    print("=" * 62)
    print(" ICS CONSOLE 2.0 - PLC / OT assessment + packet inspector")
    print("=" * 62)
    print(f" Dashboard:  {url}")
    print(" Reminder:   authorized targets only. Gentle on live gear.")
    print(" Stop:       Ctrl+C")
    print("=" * 62)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
