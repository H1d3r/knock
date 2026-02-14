# 🔍 Knockpy Subdomain Scan v9.0

✅ Fast & Async • 🔐 Recon + Brute • 🔧 Easy to Extend

**KnockPy** is a modular Python 3 tool to enumerate subdomains via passive reconnaissance and bruteforce, now with **async/await support**, enhanced performance, and modern HTTP/TLS handling.

---

## 🚀 Features (v9)

- ✅ **Async scanning** with `httpx` and DNS resolution
- ✅ Modular: plug new passive sources easily
- 🔍 Supports **passive recon**, **bruteforce**, or both
- 🎨 Formatted terminal output with **Rich** (tables, progress, panels)
- 📜 Validates **HTTP/HTTPS status**, **TLS cert**, and **IP**
- ⚠️ Detects legacy TLS support (**TLS 1.0/1.1**) as warning in CLI/verbose/HTML report
- 🧾 Checks **AXFR (zone transfer)** on root domain during domain-mode scans
- 🔎 `--verbose` single-domain diagnostics (DNS/TCP/TLS/redirect chains/request errors + security checks)
- 💡 Supports **wildcard DNS** detection
- 🧪 SQLite reports with interactive catalog (`show/delete/export/search`)
- 🔐 Supports **VirusTotal** and **Shodan** API
- 🚀 Optimized bruteforce runtime with TLS-probe endpoint caching (no timeout changes required)

---

## 📦 Installation

### From GitHub source (recommended)

```bash
git clone https://github.com/guelfoweb/knockpy.git
cd knockpy
# recommended: install in a virtual environment
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -U pip
pip install .

# alternative: install for the current user (no venv)
# python3 -m pip install --user .
```

⚠️ Recommended Python version: 3.9+

## 🧱 Project Structure

The codebase is organized by responsibility, with stable facades for backward compatibility:

```text
knockpy/
  cli.py                   # CLI entrypoint (facade/orchestration)
  cli_parts/
    status.py              # runtime/status panel rendering
    setup.py               # interactive setup and persisted runtime defaults
    report.py              # interactive report mode
    scan_flow.py           # exclude rules, recon-test, wildcard helpers
  core.py                  # public core facade (compatibility)
  engine/
    runtime.py             # scanning engine implementation
  storage.py               # public storage facade (compatibility)
  storage_parts/
    db.py                  # SQLite persistence/settings
    export.py              # report export orchestration
    html_report.py         # HTML report rendering
  output.py                # terminal output rendering
  server_versions.py       # web-server versions catalog
  knockpy.py               # compatibility module exports
```

Compatibility note:
- Preferred external imports: `import knockpy` or `from knockpy import KNOCKPY`.
- Internal modules are split into `engine/`, `cli_parts/`, and `storage_parts/`.


### Using pip

*Only after the stable version is released on GitHub*

```bash
pip install knock-subdomains
```

## 🧪 Usage

```bash
knockpy -d domain.com [options]
```

### Options

| Flag              | Description                        |
| ----------------- | ---------------------------------- |
| `-d`, `--domain`  | Target domain (or stdin if used without value) |
| `-f`, `--file`    | File with list of domains          |
| `--recon`         | Enable passive reconnaissance      |
| `--bruteforce`, `--brute` | Enable bruteforce using wordlist   |
| `--exclude TYPE VALUE` | Exclude matches (`status`, `length/lenght`, `body`) |
| `--verbose`       | Deep diagnostics for single-domain scans only |
| `--wildcard`      | Test wildcard DNS and exit         |
| `--test`          | With `--recon`, test each recon source (failed/empty/data) |
| `--setup`         | Interactive setup (runtime defaults + API keys in DB) |
| `--update-versions` | Update local latest web-server versions catalog |
| `--report [ID|latest|list]` | Report mode (interactive show/delete/export/search/reset db, export HTML) |
| `--check-update` | Check online if a newer Knockpy release is available on PyPI |
| `--wordlist`      | Runtime override for wordlist      |
| `--dns`           | Runtime override for DNS resolver  |
| `--useragent`     | Runtime override for HTTP user-agent |
| `--timeout`       | Runtime override for timeout (seconds) |
| `--threads`       | Runtime override for concurrent workers |
| `--silent`        | Hide progress bar                  |
| `--json`          | JSON-only output (forces `--silent`) |
| `--status`        | Print runtime status and continue  |
| `-h`, `--help`    | Show help message                  |

### Performance Tuning: `--threads` and `--timeout`

These two options have the biggest impact on runtime for large scans.

- `--threads` controls concurrency (how many targets are processed in parallel)
- `--timeout` controls how long each network step waits before giving up

Trade-off:

- higher `threads` = faster scans, but more load on CPU/network/DNS and higher risk of remote rate-limits
- lower `timeout` = faster scans, but higher risk of missing slow yet valid targets (false negatives)

Recommended profiles:

- small/accurate scan (few domains): `--threads 50 --timeout 5`
- balanced scan: `--threads 150 --timeout 4`
- large scan (10k+ domains): start with `--threads 250 --timeout 3`

If you need both speed and completeness on very large lists, use 2-pass strategy:

1. fast pass: `--threads 250 --timeout 3`
2. retry pass only on missing/uncertain targets: `--threads 80 --timeout 5` (or higher)

Notes:

- CLI values always override saved setup values
- saved setup values (`--setup`) override built-in defaults
- current built-in defaults are `threads=250`, `timeout=3`


## 📌 Examples

### 🔎 Recon + Brute

```bash
knockpy -d example.com --recon --bruteforce
```

### 🧪 Recon services test

```bash
knockpy -d example.com --recon --test
```

### 🔄 Update web-server latest versions catalog

```bash
knockpy --update-versions
```

### 🆕 Check for Knockpy updates

```bash
knockpy --check-update
```

### ⚙️ Recon sources config (editable)

At first run, KnockPy creates:

```bash
~/.knockpy/recon_services.json
```

You can add/disable sources by editing the `services` array.
You can also point to a custom file path without changing code:

```bash
export KNOCK_RECON_SERVICES=/path/to/recon_services.json
```

Each service supports:

- `name`
- `enabled` (`true`/`false`)
- `parser`
- `url_template` (supports `{domain}`, `{virustotal_key}`, `{shodan_key}`)
- `requires_api` (`virustotal` or `shodan`, optional)

Supported parsers:

- `csv_first_column`
- `rapiddns_html_td`
- `json_list`
- `virustotal_subdomains`
- `shodan_subdomains`

### 📥 Domain from stdin

```bash
echo "example.com" | knockpy -d
```

### 🧠 API Keys (optional)

```bash
export API_KEY_VIRUSTOTAL=your-virustotal-api-key
export API_KEY_SHODAN=your-shodan-api-key
```

You can use `.env` file:

```bash
API_KEY_VIRUSTOTAL=your-virustotal-api-key
API_KEY_SHODAN=your-shodan-api-key
```

### 💾 Reports (SQLite + Interactive HTML export)

```bash
knockpy -d example.com --recon --bruteforce
knockpy --report list
knockpy --report latest
knockpy --report
```

Interactive report menu:

- `1 show`
- `2 delete`
- `3 export`
- `4 search`
- `0 reset db` (asks explicit confirmation)

Exit report mode:

- press `Enter` on empty action prompt
- or press `CTRL+C`

### 🔍 Single-domain diagnostics

```bash
knockpy -d forum.example.com --verbose
```

### 🧪 Wildcard test only

```bash
knockpy -d example.com --wildcard
```

## 🧬 Python API Usage

KnockPy can be used as a Python module:

```python
import knockpy

result = knockpy.KNOCKPY("example.com", timeout=5.0, threads=20)
print(result["domain"], result["ip"])
```

or:

```python
from knockpy import KNOCKPY

domain = 'example.com'

results = KNOCKPY(
    domain,
    dns="8.8.8.8",
    useragent="Mozilla/5.0",
    timeout=5,
    threads=10,
    recon=True,
    bruteforce=True,
    wordlist=None,
    silent=False
)

for entry in results:
    print(entry['domain'], entry['ip'], entry['http'], entry['cert'])
```

## 📂 Wordlist

A default wordlist is included in `knockpy/wordlist/wordlist.txt`.
You can supply your own with `--wordlist`.

## Test

```bash
python3 -m pytest

# (optional) smoke-run example script
python3 examples/poc.py
```

## 📖 License

Licensed under the GPLv3 license.

Gianni Amato (@guelfoweb)
