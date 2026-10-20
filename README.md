# certaudit

A small, dependency-free command-line tool for checking TLS certificates and protocol settings across many hosts at once.

- Validates the **certificate chain and hostname**, and names the problem (self-signed, mismatch, expired)
- Shows **days until expiry** and warns before it happens (default 30 days)
- Reports issuer, SANs, **negotiated protocol and cipher**
- Tests whether legacy **TLS 1.0 / 1.1** are still accepted
- Checks a whole list in parallel, with a one-line-per-host summary and **CSV / JSON** export

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# One host, full detail
python certaudit.py example.com

# Non-standard port
python certaudit.py mail.example.com:993

# Everything in a list, warn 45 days ahead, as a spreadsheet
python certaudit.py -i hosts.txt -w 45 -f csv -o certs.csv
```

### Example output

```
$ python certaudit.py intranet.example.com
intranet.example.com:443
  Subject  intranet.example.com
  Issuer   intranet.example.com
  SANs     intranet.example.com
  [FAIL] Trust     Self-signed certificate; browsers won't trust it
  [WARN] Expiry    Expires in 19 day(s) (2026-11-09)
  [PASS] Protocol  TLSv1.3
  [PASS] Cipher    TLS_AES_256_GCM_SHA384 (256-bit)
  [PASS] TLS 1.0   Rejected
  [PASS] TLS 1.1   Rejected

$ python certaudit.py -i hosts.txt --no-legacy
STATUS   DAYS  EXPIRES     PROTO    TARGET                            ISSUER
PASS       73  2027-01-01  TLSv1.3  example.com:443                   Let's Encrypt
WARN       12  2026-11-01  TLSv1.2  shop.example.com:443              Sectigo Limited
FAIL       19  2026-11-09  TLSv1.3  intranet.example.com:443          intranet.example.com
ERROR                               old.example.com:443               Connection refused
```

## Options

| Flag | Description |
|---|---|
| `-i, --input FILE` | Read targets from a file, one per line |
| `-p, --port N` | Default port (default 443) |
| `-w, --warn-days N` | Warn when expiry is this close (default 30) |
| `-t, --timeout N` | Connection timeout in seconds (default 8) |
| `-j, --threads N` | Parallel workers (default 10) |
| `--no-legacy` | Skip TLS 1.0/1.1 tests (faster) |
| `-s, --summary` | One line per host (default when >1 host) |
| `-d, --detail` | Full detail even for many hosts |
| `-f, --format` | Output format (`table` / `csv` / `json`) |
| `-o, --output FILE` | Write results to a file |
| `--no-color` | Plain output without colors |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every host passed |
| `1` | At least one failure or unreachable host |
| `2` | Bad input, or no host could be reached |

## Notes

The TLS 1.0 / 1.1 test depends on your own machine's OpenSSL. Recent builds refuse to offer those versions at all; when that happens the check shows `INFO: Couldn't test` instead of guessing.

The `hosts.txt` format is one `host`, `host:port` or URL per line. Lines starting with `#` are ignored.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s auditkit.
