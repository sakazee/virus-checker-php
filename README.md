# Quick Suspicious File Scanner (PHP CLI)

A lightweight, signature based PHP CLI script that scans server files to detect potentially malicious code such as web shells, obfuscated payloads, and dangerous function usage.

This is not a full antivirus solution. It is designed to quickly highlight suspicious files for manual review.

---

## What It Does

This script:

* Scans selected file extensions
* Reads only the head and tail of large files for faster processing
* Detects common web shell and obfuscation patterns
* Flags long Base64 encoded blobs
* Generates a structured JSON report

---

## File Types Scanned

By default:

* php
* phtml
* php5
* php7
* inc
* js
* html
* htm
* py
* sh
* pl
* asp
* aspx
* jsp

---

## Suspicious Patterns Checked

Examples include:

* eval(
* assert(
* base64_decode(
* gzinflate(
* str_rot13(
* shell_exec(
* system(
* exec(
* passthru(
* proc_open(
* popen(
* fsockopen(
* curl_exec(
* preg_replace with /e modifier
* $_GET / $_POST / $_REQUEST / $_COOKIE
* php://input
* wget / curl
* powershell
* nc / netcat
* Long Base64 blobs

Especially suspicious combinations:

* base64_decode + eval
* gzinflate + base64_decode
* Obfuscation combined with superglobals

---

## Requirements

* PHP 7.4 or higher
* CLI access
* Proper read permissions

---

## Installation

1. Save the script as `quick_scan.php`
2. Place it outside your web root
3. Run it from the command line

---

## Usage

### Basic Scan

```
php quick_scan.php /var/www
```

### Excluding System Directories

```
php quick_scan.php /var/www --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/var/lib/docker
```

### Save Report to File

```
php quick_scan.php /var/www --out=report.json
```

---

## Available Options

| Option             | Description                                 |
| ------------------ | ------------------------------------------- |
| --exclude=PATH     | Exclude a directory prefix                  |
| --max-bytes=NUMBER | Maximum bytes read per file (default 512KB) |
| --max-size=NUMBER  | Maximum file size to scan (default 10MB)    |
| --out=FILE         | Write output to JSON file                   |

---

## Performance Tuning

For large servers:

Reduce bytes read per file:

```
--max-bytes=262144
```

Skip larger files:

```
--max-size=5242880
```

---

## Report Format

Output is generated in JSON format:

```
{
  "root": "/var/www",
  "scanned_files": 1234,
  "skipped_entries": 567,
  "findings": [
    {
      "path": "/var/www/suspicious.php",
      "size": 2048,
      "hits": ["php_eval", "php_base64_decode"]
    }
  ]
}
```

---

## Limitations

* Signature based detection only
* False positives are possible
* Encrypted or compressed payloads may not be detected
* Minified JavaScript may trigger alerts

---

## Security Notes

* Do not run this script via web browser
* Do not place it inside your web root
* Avoid running as root unless necessary
* Do not immediately delete flagged files without reviewing them

---

## Recommended Enhancements

For stronger security coverage, consider:

* Adding WordPress specific detection rules
* Excluding framework storage or cache directories
* Integrating YARA rules
* Implementing SHA256 file integrity baselining
* Running alongside ClamAV

---

## Disclaimer

This tool is intended for quick detection of suspicious code. It is not a complete security solution. Production systems should always use layered security controls.

---

If you want, I can also provide:

* A GitHub ready version with proper structure
* MIT license file
* Versioning and changelog
* Security policy
* WordPress or Laravel optimized detection rules
