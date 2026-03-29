# nmapparser

A flexible Go CLI tool to convert **Nmap XML output** (`-oX`) into clean, structured **JSON** — pipe-friendly, single binary, zero dependencies.

Built for bug bounty hunters and recon pipelines. Installable like any Go tool.

---

## Install

**Via `go install` (recommended):**
```bash
go install github.com/ihsanlearn/nmapparser@latest
```

**Download prebuilt binary (Linux):**
```bash
# amd64
curl -L https://github.com/ihsanlearn/nmapparser/releases/latest/download/nmapparser-linux-amd64 -o nmapparser
chmod +x nmapparser
sudo mv nmapparser /usr/local/bin/

# arm64
curl -L https://github.com/ihsanlearn/nmapparser/releases/latest/download/nmapparser-linux-arm64 -o nmapparser
chmod +x nmapparser
sudo mv nmapparser /usr/local/bin/
```

**Build from source:**
```bash
git clone https://github.com/ihsanlearn/nmapparser.git
cd nmapparser
go build -o nmapparser .
```

---

## Requirements

- Go 1.21+ (for `go install`)
- No external dependencies — standard library only

---

## Usage

```
nmapparser [flags] <nmap.xml>
nmapparser [flags] -           # read from stdin
```

| Flag | Description |
|---|---|
| `-o FILE` | Write JSON to file (default: stdout) |
| `-compact` | Compact JSON (no indentation) |
| `-filter-state STATE` | Only include ports with this state (`open`, `closed`, `filtered`) |
| `-hosts-only` | Condensed host-level summary, no port details |
| `-summary` | Print a human-readable table to stderr |

---

## Examples

**Basic conversion:**
```bash
nmap -sS -sV -oX scan.xml 192.168.1.0/24
nmapparser scan.xml -o result.json
```

**Only show open ports:**
```bash
nmapparser scan.xml -filter-state open
```

**Quick host overview:**
```bash
nmapparser scan.xml -hosts-only
```

**Human-readable summary + save JSON:**
```bash
nmapparser scan.xml -summary -o result.json
```

**Pipe directly from nmap:**
```bash
nmap -sS -oX - 192.168.1.1 | nmapparser -
```

**Pipe into `jq`:**
```bash
# List all open ports
nmapparser scan.xml -compact | jq '[.hosts[].ports[] | select(.state.state=="open") | {port: .portid, service: .service.name}]'

# Extract unique services
nmapparser scan.xml -compact | jq '[.hosts[].ports[].service.name] | unique'

# Get all IPs with port 443 open
nmapparser scan.xml -compact | jq -r '.hosts[] | select(.ports[]? | .portid==443 and .state.state=="open") | .addresses[0].addr'
```

**Full recon pipeline (nmap → httpx):**
```bash
nmap -sS -p 80,443,8080,8443 -oX - 192.168.1.0/24 \
  | nmapparser - -filter-state open -compact \
  | jq -r '.hosts[] | .addresses[0].addr as $ip | .ports[] | "\($ip):\(.portid)"' \
  | httpx -silent
```

---

## JSON Output Structure

```json
{
  "scanner": "nmap",
  "args": "nmap -sS -sV -oX scan.xml 192.168.1.1",
  "start": 1774791049,
  "startstr": "Sun Mar 29 13:30:49 2026",
  "version": "7.95",
  "scaninfo": [
    { "type": "syn", "protocol": "tcp", "numservices": 1000 }
  ],
  "hosts": [
    {
      "status": { "state": "up", "reason": "echo-reply", "reason_ttl": 52 },
      "addresses": [
        { "addr": "192.168.1.1", "addrtype": "ipv4" },
        { "addr": "AA:BB:CC:DD:EE:FF", "addrtype": "mac", "vendor": "Cisco" }
      ],
      "hostnames": [{ "name": "router.local", "type": "PTR" }],
      "ports": [
        {
          "protocol": "tcp",
          "portid": 22,
          "state": { "state": "open", "reason": "syn-ack", "reason_ttl": 64 },
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "cpes": ["cpe:/a:openbsd:openssh:8.2p1"]
          }
        }
      ],
      "os": {
        "matches": [{ "name": "Linux 5.4", "accuracy": 95 }]
      }
    }
  ],
  "runstats": {
    "finished": { "elapsed": 20.24, "exit": "success" },
    "hosts": { "up": 1, "down": 0, "total": 1 }
  }
}
```

---

## Supported Nmap Flags

| Nmap Flag | What it adds to JSON |
|---|---|
| `-sS`, `-sT`, `-sU` | Port state, reason, protocol |
| `-sV` | Service name, product, version, CPEs |
| `-O` | `os.matches`, `os.fingerprints` |
| `-sC` / `--script` | `ports[].scripts`, `hostscripts` |
| `--traceroute` | `traceroute.hops[]` |
| (default) | MAC address + vendor, IPv4/IPv6, hostnames |

---

## Releases

Prebuilt binaries are automatically published via GitHub Actions on every tagged release.

To release a new version:
```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions will build and attach binaries for `linux/amd64` and `linux/arm64`.

---

## License

MIT License — free to use, modify, and distribute.

---

## Disclaimer

This tool is intended for use in **authorized security assessments, bug bounty programs, and CTFs only**. Always ensure you have explicit permission before scanning any target. The author is not responsible for any misuse.