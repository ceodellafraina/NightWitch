import os
import subprocess
import logging
from pathlib import Path
from typing import List, Optional
import base64
import secrets

class ZoneManager:
    """Manages DNSSEC zone operations for covert channel"""
    
    def __init__(self, mode: str = "bind9", mock_keys: bool = False):
        self.mode = mode
        self.mock_keys = mock_keys
        self.zones_dir = Path("zones")
        self.zones_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.zones_dir, 0o755)
        
    def initialize_zone(self, domain: str, ttl: int = 300) -> None:
        """Initialize a new DNSSEC zone"""
        logging.info(f"Initializing zone: {domain}")
        
        self._cleanup_existing_keys(domain)
        
        if self.mock_keys:
            self._generate_mock_keys(domain)
        else:
            self._generate_keys(domain)
        
        self._create_zone_file(domain, ttl)
        
        logging.info(f"Zone {domain} initialized")
        
    def _cleanup_existing_keys(self, domain: str) -> None:
        """Clean up existing key files that might have permission issues"""
        try:
            key_files = list(self.zones_dir.glob(f"K{domain}.*"))
            for key_file in key_files:
                try:
                    key_file.unlink()
                    logging.debug(f"Removed existing key file: {key_file}")
                except PermissionError:
                    try:
                        os.chmod(key_file, 0o644)
                        key_file.unlink()
                        logging.debug(f"Fixed permissions and removed: {key_file}")
                    except Exception as e:
                        logging.warning(f"Could not remove key file {key_file}: {e}")
        except Exception as e:
            logging.debug(f"Key cleanup completed with warnings: {e}")
    
    def _generate_mock_keys(self, domain: str) -> None:
        """Generate mock DNSSEC keys for testing (no dnssec-keygen required)"""
        logging.info(f"Generating mock DNSSEC keys for {domain} (LAN test mode)")
        
        # Generate random key data
        zsk_key = base64.b64encode(secrets.token_bytes(128)).decode('ascii')
        ksk_key = base64.b64encode(secrets.token_bytes(256)).decode('ascii')
        
        # Create mock key files
        zsk_file = self.zones_dir / f"K{domain}.+008+12345.key"
        ksk_file = self.zones_dir / f"K{domain}.+008+54321.key"
        
        with open(zsk_file, 'w') as f:
            f.write(f"; ZSK for {domain}\n")
            f.write(f"{domain}. IN DNSKEY 256 3 8 {zsk_key}\n")
        
        with open(ksk_file, 'w') as f:
            f.write(f"; KSK for {domain}\n")
            f.write(f"{domain}. IN DNSKEY 257 3 8 {ksk_key}\n")
        
        os.chmod(zsk_file, 0o644)
        os.chmod(ksk_file, 0o644)
        
        logging.info(f"Mock DNSSEC keys generated for {domain}")
        
    def _generate_keys(self, domain: str) -> None:
        """Generate DNSSEC keys for the domain using dnssec-keygen"""
        original_cwd = os.getcwd()
        
        try:
            os.chdir(self.zones_dir)
            
            if not self._check_dnssec_keygen():
                logging.warning("dnssec-keygen not found, falling back to mock keys")
                os.chdir(original_cwd)
                self._generate_mock_keys(domain)
                return
            
            zsk_cmd = ["dnssec-keygen", "-a", "RSASHA256", "-b", "1024", domain]
            result = subprocess.run(zsk_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to generate ZSK: {result.stderr}")
                
            ksk_cmd = ["dnssec-keygen", "-a", "RSASHA256", "-b", "2048", "-f", "KSK", domain]
            result = subprocess.run(ksk_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to generate KSK: {result.stderr}")
            
            key_files = list(Path(".").glob(f"K{domain}.*"))
            for key_file in key_files:
                os.chmod(key_file, 0o644)
                
            logging.info(f"DNSSEC keys generated for {domain}")
            
        finally:
            os.chdir(original_cwd)
    
    def _check_dnssec_keygen(self) -> bool:
        """Check if dnssec-keygen is available"""
        try:
            result = subprocess.run(["dnssec-keygen", "-h"], 
                                  capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        
    def _create_zone_file(self, domain: str, ttl: int = 300) -> None:
        """Create initial zone file"""
        zone_file = self.zones_dir / f"{domain}.zone"
        
        zone_content = f"""$ORIGIN {domain}.
$TTL {ttl}
@       IN      SOA     ns1.{domain}. admin.{domain}. (
                        2023010101      ; Serial
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        {ttl} )         ; Minimum TTL

        IN      NS      ns1.{domain}.
ns1     IN      A       192.168.1.1
"""
        
        with open(zone_file, 'w') as f:
            f.write(zone_content)
            
        logging.info(f"Zone file created: {zone_file}")
        
    def _sign_zone(self, domain: str) -> None:
        """Sign the zone with DNSSEC"""
        zone_file = self.zones_dir / f"{domain}.zone"
        signed_zone_file = self.zones_dir / f"{domain}.zone.signed"
        
        key_files = list(self.zones_dir.glob(f"K{domain}.*.key"))
        if not key_files:
            raise RuntimeError(f"No DNSSEC keys found for {domain}")
        
        cmd = [
            "dnssec-signzone", 
            "-o", domain,
            "-K", str(self.zones_dir),
            "-S",
            str(zone_file)
        ]
        
        result = subprocess.run(cmd, cwd=self.zones_dir, capture_output=True, text=True)
        
        if result.returncode != 0:
            logging.error(f"Zone signing failed: {result.stderr}")
            raise RuntimeError(f"Failed to sign zone {domain}")
        
        logging.info(f"Zone {domain} signed successfully")
        
    def publish_chunk(self, domain: str, chunk: str, sequence: int, record_type: str = "DNSKEY") -> None:
        """Publish a data chunk as a DNSSEC record"""
        zone_file = self.zones_dir / f"{domain}.zone"
        
        dnskey_record = f"{domain}. IN DNSKEY 256 3 7 {chunk} ; sequence={sequence}\n"
        
        with open(zone_file, 'a') as f:
            f.write(dnskey_record)
        
        logging.info(f"Publishing {record_type} record for {domain} (sequence {sequence}): {chunk[:50]}...")
        
    def extract_chunks(self, domain: str) -> List[str]:
        """Extract data chunks from DNSSEC records"""
        logging.info(f"Extracting chunks from {domain}")
        
        zone_file = self.zones_dir / f"{domain}.zone"
        chunks = []
        
        if not zone_file.exists():
            logging.warning(f"Zone file not found: {zone_file}")
            return chunks
        
        with open(zone_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                if 'DNSKEY' in line and 'sequence=' in line:
                    record_part = line.split(';')[0].strip()
                    parts = record_part.split()
                    
                    if len(parts) >= 6 and parts[2] == 'DNSKEY':
                        key_data = ' '.join(parts[6:])
                        key_data = key_data.strip()
                        
                        chunks.append(key_data)
                        logging.debug(f"Extracted chunk: {key_data[:50]}...")
        
        logging.info(f"Extracted {len(chunks)} chunks from {domain}")
        return chunks
        
    def cleanup_zone(self, domain: str) -> None:
        """Clean up zone files and keys"""
        zone_files = list(self.zones_dir.glob(f"{domain}.*"))
        key_files = list(self.zones_dir.glob(f"K{domain}.*"))
        
        for file_path in zone_files + key_files:
            file_path.unlink(missing_ok=True)
            
        logging.info(f"Cleaned up zone files for {domain}")
