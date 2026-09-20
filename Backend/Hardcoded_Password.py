import re
from pathlib import Path
from typing import Dict, List, Any, Optional

class FirmwareScanner:
    def __init__(self, target_directory: str, max_file_size_mb: int = 10):
        self.target_dir = Path(target_directory)
        self.max_file_size = max_file_size_mb * 1024 * 1024  # Convert MB to Bytes
        
        # --- REGEX PATTERNS ---
        # 1. Cryptographic Keys & Certificates
        self.pem_pattern = re.compile(
            b'-----BEGIN (?:RSA |ENCRYPTED |EC |DSA )?(?:PRIVATE|PUBLIC) KEY-----|-----BEGIN CERTIFICATE-----'
        )
        self.encrypted_pem_marker = re.compile(b'Proc-Type: 4,ENCRYPTED|ENCRYPTED PRIVATE KEY')
        self.rsa_oid_binary = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
        
        # 2. Root-of-Trust Patterns
        self.rotkey_pattern = re.compile(b'rotkey|rot_key|root of trust', re.IGNORECASE)
        
        # 3. URL and Domain Patterns
        self.url_pattern = re.compile(
            b'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?::\\d+)?(?:/[^\\s"\'`<>]*)*', 
            re.IGNORECASE
        )
        self.domain_pattern = re.compile(
            b'\\b[a-zA-Z0-9.-]+\\.(?:com|cn|org|net|io|gov)\\b', 
            re.IGNORECASE
        )
        
        # 4. Hash Detection Patterns
        self.hash_patterns = {
            'md5crypt': r'^\$1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$',
            'sha256crypt': r'^\$5\$[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{43}$',
            'sha512crypt': r'^\$6\$[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{86}$',
            'bcrypt': r'^\$2[aby]?\$\d{2}\$[a-zA-Z0-9./]{53}$',
            'descrypt': r'^[a-zA-Z0-9./]{13}$'
        }
        
        self.ignored_credentials = {'*', '!', '!!', 'x', '*LK*', 'NP', ''}
        self.target_filenames = {'passwd', 'shadow', 'htpasswd', 'rototp.sh'}
        
        self.results = {
            "system_files": [],
            "extracted_credentials": [],
            "keys_and_certificates": [],
            "rotkeys_found": [],
            "urls_and_domains": set()
        }

    def detect_hash_type(self, credential: str) -> Optional[str]:
        for hash_type, pattern in self.hash_patterns.items():
            if re.match(pattern, credential):
                return hash_type
        return None

    def parse_credentials(self, file_path: Path, content_str: str):
        for line in content_str.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(':')
            if len(parts) >= 2:
                username = parts[0].strip()
                credential = parts[1].strip()

                if credential in self.ignored_credentials:
                    continue

                hash_type = self.detect_hash_type(credential)
                self.results["extracted_credentials"].append({
                    "username": username,
                    "credential": credential,
                    "hash_type": hash_type if hash_type else "plaintext/custom",
                    "source_file": str(file_path)
                })

    def _extract_context(self, lines: List[str], match_idx: int, context_after: int = 10) -> str:
        end = min(len(lines), match_idx + context_after + 1)
        extracted = []
        for j in range(match_idx, end):
            prefix = ">> " if j == match_idx else "   "
            extracted.append(f"{prefix}{lines[j].rstrip()}")
        return "\n".join(extracted)

    def scan_file(self, filepath: Path):
        if filepath.is_symlink():
            return

        try:
            if filepath.stat().st_size > self.max_file_size:
                return
        except OSError:
            return

        try:
            with open(filepath, 'rb') as f:
                content_bytes = f.read()

            # Passwords & Credentials
            if filepath.name.lower() in self.target_filenames or filepath.name.endswith('.bak'):
                self.results["system_files"].append(str(filepath))
                try:
                    text_content = content_bytes.decode('utf-8', errors='ignore')
                    self.parse_credentials(filepath, text_content)
                except Exception:
                    pass

            # Keys & Certificates
            if self.pem_pattern.search(content_bytes):
                key_type = "Encrypted PEM Private Key" if self.encrypted_pem_marker.search(content_bytes) else "Plaintext PEM Key/Certificate"
                self.results["keys_and_certificates"].append({
                    "file": str(filepath),
                    "type": key_type
                })
            elif self.rsa_oid_binary in content_bytes:
                self.results["keys_and_certificates"].append({
                    "file": str(filepath),
                    "type": "Binary DER (RSA Sequence)"
                })

            # Root of Trust
            if self.rotkey_pattern.search(content_bytes):
                context_str = ""
                try:
                    lines = content_bytes.decode('utf-8', errors='ignore').splitlines()
                    for i, line in enumerate(lines):
                        if re.search(r'rotkey|rot_key|root of trust', line, re.IGNORECASE):
                            context_str = self._extract_context(lines, i)
                            break
                except Exception:
                    context_str = "Could not parse text line context."

                self.results["rotkeys_found"].append({
                    "file": str(filepath),
                    "context": context_str
                })

            # URLs & Domains
            for match in self.url_pattern.finditer(content_bytes):
                self.results["urls_and_domains"].add(match.group(0).decode('ascii', errors='ignore'))
            
            for match in self.domain_pattern.finditer(content_bytes):
                self.results["urls_and_domains"].add(match.group(0).decode('ascii', errors='ignore'))

        except (PermissionError, IOError, OSError):
            pass

    def run(self) -> Dict[str, Any]:
        if not self.target_dir.is_dir():
            raise FileNotFoundError(f"Directory '{self.target_dir}' does not exist or is not reachable.")

        for filepath in self.target_dir.rglob('*'):
            if filepath.is_file():
                self.scan_file(filepath)

        self.results["urls_and_domains"] = sorted(list(self.results["urls_and_domains"]))
        return self.results
