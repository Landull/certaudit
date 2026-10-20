#!/usr/bin/env python3
"""
certaudit - check TLS certificates and protocol settings for a list of hosts.

Connects to each host, validates the certificate chain and hostname,
reports days until expiry, issuer, key details and the negotiated
protocol and cipher, and checks whether legacy TLS 1.0 / 1.1 are still
accepted. Built for keeping an eye on many domains at once.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import json
import socket
import ssl
import os
import subprocess
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "1.0.0"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
WEAK_CIPHER_BITS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5")


def ssl_context(verify=True):
    """Default TLS context. python.org builds for macOS ship without CA certificates,
    so when none are loaded there, borrow the system roots from the macOS keychain."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sys.platform == "darwin" and not ctx.cert_store_stats().get("x509_ca"):
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=30).stdout
            if pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError, ValueError):
            pass
    return ctx


def parse_target(target, default_port):
    target = target.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0]
    if target.startswith("[") and "]" in target:  # [IPv6]:port
        host, _, rest = target[1:].partition("]")
        port = int(rest.lstrip(":")) if rest.startswith(":") else default_port
        return host, port
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


def cert_time(value):
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def name_dict(seq):
    out = {}
    for rdn in seq or ():
        for key, value in rdn:
            out[key] = value
    return out


def fetch_cert(host, port, timeout, verify, retries=1):
    """Return (decoded_cert_or_None, der_bytes, protocol, cipher)."""
    ctx = ssl_context(verify)
    for attempt in range(retries + 1):
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    return tls.getpeercert(), tls.getpeercert(binary_form=True), tls.version(), tls.cipher()
        except ConnectionResetError:
            if attempt == retries:
                raise
            time.sleep(1)


def legacy_accepted(host, port, timeout, version):
    """True/False if the server completes a handshake at exactly `version`, None if untestable."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError, AttributeError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLError as err:
        # Local OpenSSL refusing to even offer the version means we can't tell
        if "NO_PROTOCOLS_AVAILABLE" in str(err).upper():
            return None
        return False
    except OSError:
        return False


def audit(target, default_port=443, timeout=8, warn_days=30, check_legacy=True):
    host, port = parse_target(target, default_port)
    rec = {"target": f"{host}:{port}", "host": host, "port": port, "results": []}

    def add(check, status, detail):
        rec["results"].append({"check": check, "status": status, "detail": detail})

    verify_error = None
    try:
        cert, der, proto, cipher = fetch_cert(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as err:
        verify_error = err.verify_message or str(err)
        try:
            cert, der, proto, cipher = fetch_cert(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as err2:
            rec["error"] = str(err2)
            return rec
    except (OSError, ssl.SSLError) as err:
        msg = str(getattr(err, "strerror", None) or err)
        if "HANDSHAKE_FAILURE" in msg or "UNSUPPORTED_PROTOCOL" in msg or "VERSION" in msg.upper():
            msg = ("Handshake failed: the server only offers protocols or ciphers this machine refuses "
                   "(usually TLS 1.0/1.1 only)")
        rec["error"] = msg
        return rec

    if not cert:
        # Unverified connections don't decode the cert; load it via a temp context
        cert = decode_der(der)

    subject = name_dict(cert.get("subject"))
    issuer = name_dict(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    rec.update({
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "sans": sans,
        "serial": cert.get("serialNumber"),
        "protocol": proto,
        "cipher": cipher[0] if cipher else None,
    })

    # Chain / hostname
    if verify_error:
        status = FAIL
        if "self-signed" in verify_error or "self signed" in verify_error:
            detail = "Self-signed certificate; browsers won't trust it"
        elif "hostname" in verify_error.lower() or "mismatch" in verify_error.lower():
            detail = f"Hostname doesn't match the certificate ({verify_error})"
        elif "expired" in verify_error.lower():
            detail = "Certificate has expired"
        else:
            detail = verify_error
        add("Trust", status, detail)
    else:
        add("Trust", PASS, f"Valid chain, issued by {rec['issuer']}")

    # Expiry
    if cert.get("notAfter"):
        not_after = cert_time(cert["notAfter"])
        not_before = cert_time(cert["notBefore"])
        now = datetime.now(timezone.utc)
        days = (not_after - now).days
        rec["not_before"] = not_before.date().isoformat()
        rec["not_after"] = not_after.date().isoformat()
        rec["days_left"] = days
        if days < 0:
            add("Expiry", FAIL, f"Expired {-days} day(s) ago ({rec['not_after']})")
        elif days <= warn_days:
            add("Expiry", WARN, f"Expires in {days} day(s) ({rec['not_after']})")
        else:
            add("Expiry", PASS, f"{days} day(s) left ({rec['not_after']})")
        if now < not_before:
            add("Not yet valid", FAIL, f"Valid from {rec['not_before']}")

    # Protocol and cipher
    if proto in ("TLSv1.3",):
        add("Protocol", PASS, proto)
    elif proto == "TLSv1.2":
        add("Protocol", PASS, f"{proto} (TLS 1.3 not negotiated)")
    else:
        add("Protocol", FAIL, f"{proto} negotiated; TLS 1.2+ is required")
    if cipher:
        name, _ver, bits = cipher
        if any(w in name for w in WEAK_CIPHER_BITS) or (bits and bits < 128):
            add("Cipher", FAIL, f"{name} ({bits}-bit) is weak")
        else:
            add("Cipher", PASS, f"{name} ({bits}-bit)")

    # Legacy protocol support
    if check_legacy:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            legacy = (("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                      ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)))
        for label, ver in legacy:
            ok = legacy_accepted(host, port, timeout, ver) if ver else None
            if ok is True:
                add(label, WARN, "Still accepted; disable it")
            elif ok is False:
                add(label, PASS, "Rejected")
            else:
                add(label, INFO, "Couldn't test (disabled in this machine's OpenSSL)")
    return rec


def decode_der(der):
    """Decode a DER certificate into the getpeercert() dict using a temp file."""
    import os
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # stdlib helper, stable since 3.x
    except Exception:
        return {}
    finally:
        os.unlink(path)


def worst(rec):
    if "error" in rec:
        return "ERROR"
    statuses = [r["status"] for r in rec["results"]]
    for s in (FAIL, WARN):
        if s in statuses:
            return s
    return PASS


def color(status, enabled):
    if not enabled:
        return status
    code = {PASS: "32", WARN: "33", FAIL: "31", INFO: "36", "ERROR": "35"}[status]
    return f"\033[{code}m{status}\033[0m"


def print_detail(rec, use_color):
    print(rec["target"])
    if "error" in rec:
        print(f"  [{color('ERROR', use_color)}] {rec['error']}")
        return
    print(f"  Subject  {rec['subject']}")
    print(f"  Issuer   {rec['issuer']}")
    if rec.get("sans"):
        more = f" (+{len(rec['sans']) - 5} more)" if len(rec["sans"]) > 5 else ""
        print(f"  SANs     {', '.join(rec['sans'][:5])}{more}")
    width = max(len(r["check"]) for r in rec["results"])
    for r in rec["results"]:
        print(f"  [{color(r['status'], use_color)}] {r['check']:<{width}}  {r['detail']}")


def print_summary(records, use_color):
    print(f"{'STATUS':<6}  {'DAYS':>5}  {'EXPIRES':<10}  {'PROTO':<7}  {'TARGET':<32}  ISSUER")
    for rec in records:
        st = worst(rec)
        pad = " " * (6 - len(st))
        if "error" in rec:
            print(f"{color(st, use_color)}{pad}  {'':>5}  {'':<10}  {'':<7}  {rec['target']:<32}  {rec['error']}")
            continue
        print(f"{color(st, use_color)}{pad}  {rec.get('days_left', ''):>5}  {rec.get('not_after', ''):<10}  "
              f"{rec.get('protocol', ''):<7}  {rec['target']:<32}  {rec.get('issuer', '')}")


def write_output(records, fmt, path):
    if fmt == "csv":
        fields = ["target", "status", "days_left", "not_after", "issuer", "subject", "protocol", "cipher", "error"]
        fh = open(path, "w", newline="", encoding="utf-8") if path else sys.stdout
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow({**r, "status": worst(r)})
        if path:
            fh.close()
    else:
        data = json.dumps(records, indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)
    if path:
        print(f"[*] Wrote {path}", file=sys.stderr)


def parse_args(argv):
    p = argparse.ArgumentParser(prog="certaudit",
                                description="Check TLS certificates, expiry and protocol support.")
    p.add_argument("targets", nargs="*", help="host, host:port or URL (repeatable)")
    p.add_argument("-i", "--input", metavar="FILE", help="read targets from a file, one per line")
    p.add_argument("-p", "--port", type=int, default=443, help="default port (default 443)")
    p.add_argument("-w", "--warn-days", type=int, default=30, help="warn when expiry is this close (default 30)")
    p.add_argument("-t", "--timeout", type=float, default=8, help="connection timeout in seconds (default 8)")
    p.add_argument("-j", "--threads", type=int, default=10, help="parallel workers (default 10)")
    p.add_argument("--no-legacy", action="store_true", help="skip TLS 1.0/1.1 tests (faster)")
    p.add_argument("-s", "--summary", action="store_true", help="one line per host (default when >1 host)")
    p.add_argument("-d", "--detail", action="store_true", help="full detail even for many hosts")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    targets = list(args.targets)
    if args.input:
        try:
            with open(args.input, encoding="utf-8") as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as err:
            print(f"[!] {err}", file=sys.stderr)
            return 2
    if not targets:
        print("[!] Give at least one host or use --input.", file=sys.stderr)
        return 2

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        records = list(pool.map(
            lambda t: audit(t, args.port, args.timeout, args.warn_days, not args.no_legacy), targets))

    use_color = sys.stdout.isatty() and not args.no_color
    if args.format == "table" and not args.output:
        if (len(records) > 1 or args.summary) and not args.detail:
            print_summary(records, use_color)
        else:
            for i, rec in enumerate(records):
                if i:
                    print()
                print_detail(rec, use_color)
    else:
        write_output(records, "json" if args.format == "table" else args.format, args.output)

    if all("error" in r for r in records):
        return 2
    return 1 if any(worst(r) in (FAIL, "ERROR") for r in records) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
