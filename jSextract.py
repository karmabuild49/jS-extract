#!/usr/bin/env python3
import sys
import os
import re
import json
import requests
import urllib3
import base64
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

# ANSI Colors
C_GRN = "\033[38;2;0;255;136m"
C_RED = "\033[38;2;255;34;68m"
C_ORG = "\033[38;2;255;140;0m"
C_CYN = "\033[38;2;0;255;255m"
C_PUR = "\033[38;2;255;0;255m"
C_YEL = "\033[38;2;255;255;0m"
C_RST = "\033[0m"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class JSExtractor:
    def __init__(self, url):
        self.url = url
        self.raw_code = ""
        self.pretty_code = ""
        self.meta = {}
        self.data = {
            "urls": set(),
            "endpoints": set(),
            "emails": set(),
            "secrets": set(),
            "dom_selectors": set(),
            "comments": set(),
            "base64_strings": set()
        }

    def fetch(self):
        print(f"{C_CYN}[*] Downloading: {self.url}{C_RST}")
        try:
            r = requests.get(self.url, headers=HEADERS, timeout=15, verify=False)
            r.raise_for_status()
            self.raw_code = r.text
            self.meta = {
                "url": self.url,
                "size": len(self.raw_code),
                "timestamp": datetime.now().isoformat(),
                "content_type": r.headers.get("Content-Type", "unknown")
            }
            print(f"{C_GRN}[+] Downloaded {len(self.raw_code)} bytes.{C_RST}")
        except Exception as e:
            print(f"{C_RED}[!] Download failed: {e}{C_RST}")
            sys.exit(1)

    def beautify(self):
        if HAS_BEAUTIFIER:
            print(f"{C_CYN}[*] Beautifying JavaScript...{C_RST}")
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            opts.unescape_strings = True
            self.pretty_code = jsbeautifier.beautify(self.raw_code, opts)
        else:
            self.pretty_code = self.raw_code

    def extract(self):
        print(f"{C_CYN}[*] Extracting intelligence...{C_RST}")
        code = self.pretty_code

        # 1. URLs & Endpoints
        for m in re.finditer(r'https?://[^\s"\'<>]+', code):
            self.data["urls"].add(m.group(0))
        for m in re.finditer(r'(["\'])((?:/|\.\./)[a-zA-Z0-9_\-\.\/]+)\1', code):
            path = m.group(2)
            if len(path) > 3 and not path.startswith("//"):
                self.data["endpoints"].add(path)

        # 2. Emails
        for m in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', code):
            self.data["emails"].add(m.group(0))

        # 3. Secrets (Basic Heuristics)
        secret_patterns = [
            r'AKIA[0-9A-Z]{16}',                  # AWS
            r'AIza[0-9A-Za-z\-_]{35}',            # Google
            r'sk_live_[0-9a-zA-Z]{24,}',          # Stripe
            r'ghp_[0-9A-Za-z]{36}',               # GitHub
            r'(?i)api[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']' # Generic
        ]
        for p in secret_patterns:
            for m in re.finditer(p, code):
                val = m.group(0) if not m.groups() else m.group(1)
                self.data["secrets"].add(val)

        # 4. DOM Selectors
        for m in re.finditer(r'\$\(["\']([^"\']+)["\']\)', code):
            self.data["dom_selectors"].add(m.group(1))
        for m in re.finditer(r'document\.(?:getElementById|querySelector)\(["\']([^"\']+)["\']\)', code):
            self.data["dom_selectors"].add(m.group(1))

        # 5. Comments
        for m in re.finditer(r'/\*[\s\S]*?\*/', code):
            txt = m.group(0).strip()
            if len(txt) > 10: self.data["comments"].add(txt)
        for m in re.finditer(r'//[^\n]*', code):
            txt = m.group(0).strip()
            if len(txt) > 5 and not txt.startswith("//# sourceMappingURL"):
                self.data["comments"].add(txt)

        # 6. Base64 String Decode
        for m in re.finditer(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', code):
            try:
                decoded = base64.b64decode(m.group(1)).decode('utf-8')
                if decoded.isprintable() and len(decoded) > 5:
                    self.data["base64_strings"].add(f"{m.group(1)[:15]}... -> {decoded[:50]}")
            except Exception:
                pass

        # Convert sets to sorted lists
        for k in self.data:
            self.data[k] = sorted(list(self.data[k]))

    def save(self):
        base_name = self.url.split("/")[-1].split("?")[0].replace(".js", "")
        if not base_name: base_name = "extracted"

        # 1. Save Pretty Code
        with open(f"{base_name}_pretty.js", "w", encoding="utf-8") as f:
            f.write(self.pretty_code)

        # 2. Save JSON
        out_json = {"meta": self.meta, "data": self.data}
        with open(f"{base_name}_intel.json", "w", encoding="utf-8") as f:
            json.dump(out_json, f, indent=4)

        # 3. Save Markdown Report
        with open(f"{base_name}_report.md", "w", encoding="utf-8") as f:
            f.write(f"# JS Extraction Report\n\n**URL:** {self.url}\n**Size:** {self.meta['size']} bytes\n\n")
            for k, v in self.data.items():
                if v:
                    f.write(f"## {k.replace('_', ' ').title()} ({len(v)})\n")
                    for item in v:
                        f.write(f"- `{item}`\n")
                    f.write("\n")

        return base_name

    def print_summary(self):
        print(f"\n{C_CYN}========================================{C_RST}")
        print(f"{C_GRN}       EXTRACTION SUMMARY{C_RST}")
        print(f"{C_CYN}========================================{C_RST}")

        for k, v in self.data.items():
            if v:
                color = C_YEL if k in ["secrets", "urls"] else C_ORG
                print(f"{color}[+] {k.replace('_', ' ').title():<18}: {len(v)}{C_RST}")

        print(f"{C_CYN}----------------------------------------{C_RST}")
        if self.data["secrets"]:
            print(f"{C_RED}[!] WARNING: Potential secrets found!{C_RST}")
            for s in self.data["secrets"][:5]:
                print(f"    -> {s}")
        print(f"{C_CYN}========================================{C_RST}\n")

def main():
    print(f"{C_PUR}=== JS Heavyweight Extractor ==={C_RST}\n")

    default_url = "https://pssenior.edu.in/login/libs/jquery/jquery-1.11.3-jquery.min.js"
    url = input(f"{C_ORG}Enter JS URL [{default_url}]: {C_RST}").strip()
    if not url:
        url = default_url

    extractor = JSExtractor(url)
    extractor.fetch()
    extractor.beautify()
    extractor.extract()
    base_name = extractor.save()
    extractor.print_summary()

    print(f"{C_GRN}[+] Saved Output Files:{C_RST}")
    print(f"    - {base_name}_pretty.js    (Readable Code)")
    print(f"    - {base_name}_intel.json   (Structured Data)")
    print(f"    - {base_name}_report.md    (Markdown Report)")

if __name__ == "__main__":
    main()
