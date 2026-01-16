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
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()

class SecureMFA:
    """Secure MFA Key Manager with encrypted storage"""
    
    def __init__(self, storage_path: str = None):
        self.storage_path = Path(storage_path or Path.home() / ".mfa_storage.enc")
        self.salt_path = Path(str(self.storage_path) + ".salt")
        self._fernet = None
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
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
        """Unlock storage with password"""
        try:
            salt = self._get_or_create_salt()
            key = self._derive_key(password, salt)
            self._fernet = Fernet(key)
            
            # Test decryption if storage exists
            if self.storage_path.exists():
                self._load_keys()
            return True
        except Exception:
            console.print("[red]Invalid password or corrupted storage[/red]")
            return False
    
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
        """Add new TOTP key"""
        try:
            # Validate secret
            totp = pyotp.TOTP(secret)
            totp.now()  # Test if secret is valid
            
            keys = self._load_keys()
            keys[name] = secret
            self._save_keys(keys)
            console.print(f"[green]✓ Added key: {name}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error adding key: {e}[/red]")
            return False
    
    def remove_key(self, name: str) -> bool:
        """Remove TOTP key"""
        try:
            keys = self._load_keys()
            if name in keys:
                del keys[name]
                self._save_keys(keys)
                console.print(f"[green]✓ Removed key: {name}[/green]")
                return True
            else:
                console.print(f"[red]Key not found: {name}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Error removing key: {e}[/red]")
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

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def list(password):
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
    """Import keys from oathtool format (base32 secrets)"""
    if not mfa.unlock(password):
        console.print("[red]✗ Failed to unlock storage[/red]")
        return
    
    console.print("[yellow]Enter keys in format: name:secret (one per line)[/yellow]")
    console.print("[yellow]Press Ctrl+D when finished[/yellow]")
    
    try:
        lines = []
        while True:
            line = input()
            if line.strip():
                lines.append(line.strip())
    except EOFError:
        pass
    
    for line in lines:
        if ':' in line:
            name, secret = line.split(':', 1)
            mfa.add_key(name.strip(), secret.strip())

if __name__ == '__main__':
    cli()
