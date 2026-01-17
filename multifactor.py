#!/usr/bin/env python3
"""
Secure Multi-Factor Authentication Tool
Encrypted storage for TOTP keys with secure CLI interface
"""

import os
import json
import getpass
import base64
import hashlib
import time
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()

# Security logging setup
security_log_path = Path.home() / ".mfa_security.log"
logging.basicConfig(
    filename=security_log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('mfa_security')

# Constants for security limits
MAX_IMPORT_LINES = 1000
MAX_TOTAL_KEYS = 500
MAX_KEY_NAME_LENGTH = 100
MIN_UNLOCK_TIME = 0.1  # Minimum time for unlock operation (timing attack protection)

class SecureMFA:
    """Secure MFA Key Manager with encrypted storage"""
    
    # Class-level rate limiting tracking
    _failed_attempts = defaultdict(int)
    _lockout_until = defaultdict(float)
    
    def __init__(self, storage_path: str = None):
        self.storage_path = Path(storage_path or Path.home() / ".mfa_storage.enc")
        self.salt_path = Path(str(self.storage_path) + ".salt")
        self._fernet = None
        self._instance_id = id(self)
        
    def _derive_key(self, password: str, salt: bytes, iterations: int = 600000) -> bytes:
        """Derive encryption key from password using PBKDF2
        
        Note: Defaults to 600,000 iterations (OWASP 2023 recommendation)
        Falls back to 100,000 for backward compatibility with existing storage
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if self.salt_path.exists():
            return self.salt_path.read_bytes()
        else:
            salt = os.urandom(16)
            self.salt_path.write_bytes(salt)
            os.chmod(self.salt_path, 0o600)  # Restrict permissions
            return salt
    
    def unlock(self, password: str) -> bool:
        """Unlock storage with password (with rate limiting and timing attack protection)"""
        start_time = time.time()
        success = False
        
        # Check if locked out
        if time.time() < self._lockout_until[self._instance_id]:
            wait_time = int(self._lockout_until[self._instance_id] - time.time())
            console.print(f"[red]Too many failed attempts. Please wait {wait_time} seconds[/red]")
            security_logger.warning(f"Unlock blocked - account locked out (wait: {wait_time}s)")
            time.sleep(max(0, MIN_UNLOCK_TIME - (time.time() - start_time)))
            return False
        
        try:
            salt = self._get_or_create_salt()
            
            # Try new iteration count first (600K)
            try:
                key = self._derive_key(password, salt, iterations=600000)
                self._fernet = Fernet(key)
                
                if self.storage_path.exists():
                    self._load_keys()
                success = True
                
            except (InvalidToken, Exception):
                # Fall back to old iteration count (100K) for backward compatibility
                key = self._derive_key(password, salt, iterations=100000)
                self._fernet = Fernet(key)
                
                if self.storage_path.exists():
                    self._load_keys()
                    # Successfully unlocked with old iterations - upgrade storage
                    console.print("[yellow]Upgrading key derivation security...[/yellow]")
                    keys = self._load_keys()
                    # Re-derive key with new iterations
                    key = self._derive_key(password, salt, iterations=600000)
                    self._fernet = Fernet(key)
                    self._save_keys(keys)
                    console.print("[green]✓ Security upgrade complete[/green]")
                    security_logger.info("Storage upgraded from 100K to 600K PBKDF2 iterations")
                
                success = True
            
            # Success - reset failed attempts
            self._failed_attempts[self._instance_id] = 0
            security_logger.info("Storage unlocked successfully")
            
        except InvalidToken:
            success = False
            self._failed_attempts[self._instance_id] += 1
            attempts = self._failed_attempts[self._instance_id]
            
            security_logger.warning(f"Failed unlock attempt #{attempts}")
            
            # Exponential backoff after 3 failures
            if attempts >= 3:
                lockout_time = 2 ** (attempts - 2)  # 2, 4, 8, 16, 32... seconds
                self._lockout_until[self._instance_id] = time.time() + lockout_time
                console.print(f"[red]Too many failed attempts. Locked out for {lockout_time} seconds[/red]")
                security_logger.warning(f"Account locked out for {lockout_time}s after {attempts} failed attempts")
            else:
                console.print("[red]Invalid password[/red]")
                
        except Exception as e:
            success = False
            security_logger.error(f"Unlock error: {type(e).__name__}")
            console.print("[red]Storage corrupted or system error[/red]")
        
        # Timing attack protection - ensure minimum response time
        elapsed = time.time() - start_time
        if elapsed < MIN_UNLOCK_TIME:
            time.sleep(MIN_UNLOCK_TIME - elapsed)
        
        return success
    
    def _load_keys(self) -> Dict:
        """Load and decrypt keys from storage"""
        if not self.storage_path.exists():
            return {}
        
        encrypted_data = self.storage_path.read_bytes()
        decrypted_data = self._fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def _save_keys(self, keys: Dict):
        """Encrypt and save keys to storage"""
        data = json.dumps(keys).encode()
        encrypted_data = self._fernet.encrypt(data)
        self.storage_path.write_bytes(encrypted_data)
        os.chmod(self.storage_path, 0o600)  # Restrict permissions
    
    def add_key(self, name: str, secret: str) -> bool:
        """Add new TOTP key with input validation"""
        # Validate key name
        if not name or len(name) > MAX_KEY_NAME_LENGTH:
            console.print(f"[red]Key name must be 1-{MAX_KEY_NAME_LENGTH} characters[/red]")
            return False
        
        if not re.match(r'^[a-zA-Z0-9_\-\. ]+$', name):
            console.print("[red]Key name can only contain: letters, numbers, spaces, _ - .[/red]")
            return False
        
        # Validate and clean secret (base32 format)
        secret_clean = secret.upper().replace(' ', '').replace('-', '')
        if not re.match(r'^[A-Z2-7]+=*$', secret_clean):
            console.print("[red]Secret must be valid base32 format (A-Z, 2-7)[/red]")
            return False
        
        try:
            # Test if secret generates valid TOTP
            totp = pyotp.TOTP(secret_clean)
            totp.now()
            
            keys = self._load_keys()
            
            # Check total key limit
            if len(keys) >= MAX_TOTAL_KEYS:
                console.print(f"[red]Maximum key limit ({MAX_TOTAL_KEYS}) reached[/red]")
                security_logger.warning(f"Add key failed - limit reached ({MAX_TOTAL_KEYS})")
                return False
            
            # Check for duplicate
            if name in keys:
                console.print(f"[yellow]Key '{name}' already exists. Overwrite? (y/n): [/yellow]", end='')
                if input().lower() != 'y':
                    console.print("[yellow]Cancelled[/yellow]")
                    return False
                security_logger.info(f"Key overwritten: {name}")
            else:
                security_logger.info(f"Key added: {name}")
            
            keys[name] = secret_clean
            self._save_keys(keys)
            console.print(f"[green]✓ Added key: {name}[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Invalid TOTP secret: {type(e).__name__}[/red]")
            security_logger.error(f"Add key failed for '{name}': {type(e).__name__}")
            return False
    
    def remove_key(self, name: str) -> bool:
        """Remove TOTP key"""
        try:
            keys = self._load_keys()
            if name in keys:
                del keys[name]
                self._save_keys(keys)
                console.print(f"[green]✓ Removed key: {name}[/green]")
                security_logger.info(f"Key removed: {name}")
                return True
            else:
                console.print(f"[red]Key not found: {name}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Error removing key: {e}[/red]")
            security_logger.error(f"Remove key failed: {type(e).__name__}")
            return False
    
    def list_keys(self) -> List[str]:
        """List all stored key names"""
        keys = self._load_keys()
        return list(keys.keys())
    
    def get_code(self, name: str) -> Optional[str]:
        """Generate TOTP code for key"""
        try:
            keys = self._load_keys()
            if name in keys:
                totp = pyotp.TOTP(keys[name])
                return totp.now()
            else:
                console.print(f"[red]Key not found: {name}[/red]")
                return None
        except Exception as e:
            console.print(f"[red]Error generating code: {e}[/red]")
            return None
    
    def get_all_codes(self) -> Dict[str, str]:
        """Generate codes for all keys"""
        keys = self._load_keys()
        codes = {}
        for name, secret in keys.items():
            try:
                totp = pyotp.TOTP(secret)
                codes[name] = totp.now()
            except Exception:
                codes[name] = "ERROR"
        return codes

# CLI Interface
mfa = SecureMFA()

@click.group()
def cli():
    """Secure Multi-Factor Authentication Tool"""
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def init(password):
    """Initialize encrypted storage"""
    if mfa.unlock(password):
        console.print("[green]✓ Storage initialized successfully[/green]")
    else:
        console.print("[red]✗ Failed to initialize storage[/red]")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.argument('name')
@click.option('--secret', prompt=True, hide_input=True)
def add(password, name, secret):
    """Add new TOTP key"""
    if mfa.unlock(password):
        mfa.add_key(name, secret)
    else:
        console.print("[red]✗ Failed to unlock storage[/red]")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.argument('name')
def remove(password, name):
    """Remove TOTP key"""
    if mfa.unlock(password):
        mfa.remove_key(name)
    else:
        console.print("[red]✗ Failed to unlock storage[/red]")

@cli.command('list')
@click.option('--password', prompt=True, hide_input=True)
def list_cmd(password):
    """List all stored keys"""
    if mfa.unlock(password):
        keys = mfa.list_keys()
        if keys:
            table = Table(title="Stored TOTP Keys")
            table.add_column("Name", style="cyan")
            table.add_column("Status", style="green")
            
            for key in keys:
                table.add_row(key, "✓ Active")
            
            console.print(table)
        else:
            console.print("[yellow]No keys stored[/yellow]")
    else:
        console.print("[red]✗ Failed to unlock storage[/red]")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.argument('name', required=False)
def code(password, name):
    """Generate TOTP code(s)"""
    if mfa.unlock(password):
        if name:
            # Generate code for specific key
            code = mfa.get_code(name)
            if code:
                console.print(f"[bold green]{name}:[/bold green] {code}")
        else:
            # Generate codes for all keys
            codes = mfa.get_all_codes()
            if codes:
                table = Table(title="TOTP Codes")
                table.add_column("Name", style="cyan")
                table.add_column("Code", style="bold green")
                table.add_column("Time Remaining", style="yellow")
                
                for key_name, code in codes.items():
                    # Calculate time remaining (30-second window)
                    import time
                    remaining = 30 - (int(time.time()) % 30)
                    table.add_row(key_name, code, f"{remaining}s")
                
                console.print(table)
            else:
                console.print("[yellow]No keys stored[/yellow]")
    else:
        console.print("[red]✗ Failed to unlock storage[/red]")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def import_keys(password):
    """Import keys from oathtool format (base32 secrets) with limits"""
    if not mfa.unlock(password):
        console.print("[red]✗ Failed to unlock storage[/red]")
        return
    
    console.print("[yellow]Enter keys in format: name:secret (one per line)[/yellow]")
    console.print(f"[yellow]Maximum {MAX_IMPORT_LINES} lines. Press Ctrl+D when finished[/yellow]")
    
    lines = []
    try:
        for i in range(MAX_IMPORT_LINES):
            line = input()
            if line.strip():
                lines.append(line.strip())
    except EOFError:
        pass
    
    # Check if import would exceed total key limit
    existing_count = len(mfa.list_keys())
    if existing_count + len(lines) > MAX_TOTAL_KEYS:
        console.print(f"[red]Cannot import: would exceed maximum {MAX_TOTAL_KEYS} keys[/red]")
        console.print(f"[yellow]Current keys: {existing_count}, attempting to import: {len(lines)}[/yellow]")
        security_logger.warning(f"Import blocked - would exceed limit ({existing_count} + {len(lines)} > {MAX_TOTAL_KEYS})")
        return
    
    imported = 0
    skipped = 0
    
    for line in lines:
        if ':' not in line:
            skipped += 1
            continue
        
        parts = line.split(':', 1)
        if len(parts) != 2:
            skipped += 1
            continue
        
        name, secret = parts
        if mfa.add_key(name.strip(), secret.strip()):
            imported += 1
        else:
            skipped += 1
    
    console.print(f"[green]✓ Import complete: {imported} added, {skipped} skipped[/green]")
    security_logger.info(f"Import completed: {imported} keys added, {skipped} skipped")

if __name__ == '__main__':
    cli()
