# White Hat Security Audit: MFA TOTP Tool
**Target:** `multifactor.py` and encrypted storage files  
**Date:** January 17, 2026  
**Scope:** Cryptographic implementation, storage security, attack vectors  

---

## Storage File Analysis

### Files Examined
- `~/.mfa_storage.enc` (588 bytes, permissions: 600)
- `~/.mfa_storage.enc.salt` (16 bytes, permissions: 600)

### Storage Security Assessment ✅

**Good practices observed:**
- Correct file permissions (600 = owner read/write only)
- Separate salt storage (16 bytes = 128-bit salt)
- Encrypted data appears as random bytes (no plaintext leakage)
- Salt is non-ISO extended-ASCII (cryptographically random)

---

## Critical Vulnerabilities Found

### 🔴 CRITICAL #1: No Rate Limiting on Password Attempts
**Location:** `@/home/nop/Nextcloud/projects/coding/private/multifactor/multifactor.py:53-66`

```python
def unlock(self, password: str) -> bool:
    try:
        salt = self._get_or_create_salt()
        key = self._derive_key(password, salt)
        self._fernet = Fernet(key)
        
        if self.storage_path.exists():
            self._load_keys()  # ⚠️ No rate limiting - unlimited attempts
        return True
    except Exception:
        console.print("[red]Invalid password or corrupted storage[/red]")
        return False
```

**Attack Scenario:**
```python
# Attacker can brute force with wordlist
import time
wordlist = ['password123', 'admin', 'qwerty', ...]

for password in wordlist:
    start = time.time()
    if mfa.unlock(password):
        print(f"CRACKED: {password}")
        break
    # No delay, no lockout, no logging
```

**Impact:** 
- Offline attack possible if `.mfa_storage.enc` is stolen
- Online attack possible with unlimited attempts
- PBKDF2 100K iterations = ~10ms per attempt on modern CPU
- Can test ~100 passwords/second

**Fix:**
```python
import time
from collections import defaultdict

class SecureMFA:
    _failed_attempts = defaultdict(int)
    _lockout_until = defaultdict(float)
    
    def unlock(self, password: str) -> bool:
        # Check if locked out
        if time.time() < self._lockout_until[id(self)]:
            wait = int(self._lockout_until[id(self)] - time.time())
            console.print(f"[red]Too many attempts. Wait {wait}s[/red]")
            return False
        
        try:
            salt = self._get_or_create_salt()
            key = self._derive_key(password, salt)
            self._fernet = Fernet(key)
            
            if self.storage_path.exists():
                self._load_keys()
            
            # Success - reset counter
            self._failed_attempts[id(self)] = 0
            return True
            
        except Exception:
            # Failed attempt - exponential backoff
            self._failed_attempts[id(self)] += 1
            attempts = self._failed_attempts[id(self)]
            
            if attempts >= 3:
                # Lockout: 2^(attempts-2) seconds
                lockout_time = 2 ** (attempts - 2)
                self._lockout_until[id(self)] = time.time() + lockout_time
                console.print(f"[red]Too many failures. Locked for {lockout_time}s[/red]")
            else:
                console.print("[red]Invalid password or corrupted storage[/red]")
            
            return False
```

---

### 🔴 CRITICAL #2: PBKDF2 Iterations Below OWASP Recommendations
**Location:** `@/home/nop/Nextcloud/projects/coding/private/multifactor/multifactor.py:35-41`

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,  # ⚠️ OWASP 2023 recommends 600,000+
)
```

**Benchmark Attack:**
```bash
# Modern GPU (RTX 4090) can compute:
# PBKDF2-SHA256 @ 100K iterations: ~1,000,000 hashes/second
# With 8-character password (62^8 combinations):
# Time to crack: 218 trillion / 1M = 218 million seconds = 6.9 years

# BUT with common password from rockyou.txt (14M passwords):
# Time to crack: 14 seconds
```

**OWASP Recommendation (2023):**
- PBKDF2-SHA256: **600,000 iterations minimum**
- Better: Argon2id (memory-hard, GPU-resistant)

**Fix:**
```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,  # OWASP 2023 compliant
)
```

**Migration Path:**
```python
def _derive_key(self, password: str, salt: bytes) -> bytes:
    """Derive encryption key with automatic iteration upgrade"""
    # Try new iteration count first
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Test if this key works
        test_fernet = Fernet(key)
        if self.storage_path.exists():
            test_fernet.decrypt(self.storage_path.read_bytes())
        return key
        
    except:
        # Fall back to old iteration count for backward compatibility
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Re-encrypt with new iteration count
        console.print("[yellow]Upgrading key derivation...[/yellow]")
        # ... re-save with new iterations ...
        
        return key
```

---

### ⚠️ HIGH #3: No Input Validation on TOTP Secrets
**Location:** `@/home/nop/Nextcloud/projects/coding/private/multifactor/multifactor.py:84-98`

```python
def add_key(self, name: str, secret: str) -> bool:
    try:
        totp = pyotp.TOTP(secret)  # ⚠️ No validation before this
        totp.now()
        
        keys = self._load_keys()
        keys[name] = secret  # ⚠️ No sanitization of name
        self._save_keys(keys)
```

**Attack Vectors:**

1. **Key Name Injection:**
```python
# Malicious key names could break JSON structure
mfa.add_key('","admin":"HACKED","x":"', 'VALIDBASE32SECRET')
# Results in corrupted JSON
```

2. **Invalid Base32 Secrets:**
```python
# Crashes with unhelpful error
mfa.add_key('test', 'not-base32-at-all!!!')
```

3. **Extremely Long Names:**
```python
# Memory exhaustion
mfa.add_key('A' * 1000000, 'JBSWY3DPEHPK3PXP')
```

**Fix:**
```python
import re

def add_key(self, name: str, secret: str) -> bool:
    # Validate name length and characters
    if not name or len(name) > 100:
        console.print("[red]Name must be 1-100 characters[/red]")
        return False
    
    if not re.match(r'^[a-zA-Z0-9_\-\. ]+$', name):
        console.print("[red]Name contains invalid characters[/red]")
        return False
    
    # Validate secret is base32
    secret_clean = secret.upper().replace(' ', '').replace('-', '')
    if not re.match(r'^[A-Z2-7]+=*$', secret_clean):
        console.print("[red]Secret must be valid base32[/red]")
        return False
    
    try:
        totp = pyotp.TOTP(secret_clean)
        totp.now()
        
        keys = self._load_keys()
        
        # Check for duplicate names
        if name in keys:
            console.print(f"[yellow]Key '{name}' already exists. Overwrite? (y/n)[/yellow]")
            if input().lower() != 'y':
                return False
        
        keys[name] = secret_clean
        self._save_keys(keys)
        console.print(f"[green]✓ Added key: {name}[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]Invalid TOTP secret: {e}[/red]")
        return False
```

---

### ⚠️ HIGH #4: Import Function Vulnerable to DoS
**Location:** `@/home/nop/Nextcloud/projects/coding/private/multifactor/multifactor.py:239-260`

```python
def import_keys(password):
    # ...
    try:
        lines = []
        while True:  # ⚠️ Infinite loop - no limit
            line = input()
            if line.strip():
                lines.append(line.strip())
    except EOFError:
        pass
    
    for line in lines:  # ⚠️ No limit on number of keys
        if ':' in line:
            name, secret = line.split(':', 1)
            mfa.add_key(name.strip(), secret.strip())
```

**Attack Scenarios:**

1. **Memory Exhaustion:**
```bash
# Generate 1 million lines
yes "test:JBSWY3DPEHPK3PXP" | head -1000000 | ./multifactor.py import-keys
```

2. **Storage Bloat:**
```python
# Each key ~50 bytes, 1M keys = 50MB encrypted file
# Slows down all operations
```

**Fix:**
```python
MAX_IMPORT_LINES = 1000
MAX_KEYS_TOTAL = 500

def import_keys(password):
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
    
    # Check total key limit
    existing_keys = len(mfa.list_keys())
    if existing_keys + len(lines) > MAX_KEYS_TOTAL:
        console.print(f"[red]Cannot import: would exceed {MAX_KEYS_TOTAL} key limit[/red]")
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
    
    console.print(f"[green]✓ Imported {imported} keys, skipped {skipped}[/green]")
```

---

### ⚠️ MEDIUM #5: No Secure Memory Wiping
**Location:** Throughout `multifactor.py`

**Issue:** Sensitive data (passwords, TOTP secrets) remain in memory

```python
def unlock(self, password: str) -> bool:
    # password string remains in memory
    # key remains in memory
    # decrypted secrets remain in memory
```

**Attack:** Memory dump could reveal secrets

**Mitigation (Limited in Python):**
```python
import gc
import ctypes

def secure_delete(data: str):
    """Attempt to overwrite string in memory (best effort in Python)"""
    if isinstance(data, str):
        # Python strings are immutable, but we can try
        try:
            location = id(data)
            size = len(data)
            ctypes.memset(location, 0, size)
        except:
            pass
    gc.collect()

def unlock(self, password: str) -> bool:
    try:
        salt = self._get_or_create_salt()
        key = self._derive_key(password, salt)
        self._fernet = Fernet(key)
        
        if self.storage_path.exists():
            self._load_keys()
        
        # Clean up sensitive data
        secure_delete(password)
        secure_delete(key)
        
        return True
    except Exception:
        secure_delete(password)
        console.print("[red]Invalid password or corrupted storage[/red]")
        return False
```

**Note:** Python's garbage collector makes true secure deletion difficult. Consider using `mlock()` for production.

---

### ⚠️ MEDIUM #6: No Backup/Recovery Mechanism

**Issue:** Lost password = lost all TOTP keys permanently

**Impact:**
- User locked out of all accounts
- No disaster recovery
- Single point of failure

**Recommendation:**
```python
@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--output', default='mfa_backup.enc', help='Backup file path')
def backup(password, output):
    """Create encrypted backup of all keys"""
    if mfa.unlock(password):
        import shutil
        shutil.copy2(mfa.storage_path, output)
        shutil.copy2(mfa.salt_path, output + '.salt')
        console.print(f"[green]✓ Backup created: {output}[/green]")
        console.print("[yellow]⚠ Store backup in secure location![/yellow]")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def recovery_codes(password):
    """Generate one-time recovery codes"""
    if mfa.unlock(password):
        import secrets
        codes = [secrets.token_hex(8) for _ in range(10)]
        
        # Store hashed codes
        recovery_file = Path.home() / ".mfa_recovery"
        import hashlib
        hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
        recovery_file.write_text('\n'.join(hashed))
        
        # Display codes once
        console.print("[green]Recovery Codes (save these securely!):[/green]")
        for i, code in enumerate(codes, 1):
            console.print(f"{i:2d}. {code}")
```

---

### ⚠️ MEDIUM #7: Timing Attack on Password Verification

**Location:** `@/home/nop/Nextcloud/projects/coding/private/multifactor/multifactor.py:53-66`

**Issue:** Fernet.decrypt() may leak timing information

**Attack:** Statistical analysis of response times could reveal password characteristics

**Current Code:**
```python
def unlock(self, password: str) -> bool:
    try:
        # ...
        self._fernet = Fernet(key)
        if self.storage_path.exists():
            self._load_keys()  # Timing varies based on correctness
        return True
    except Exception:
        return False  # Different timing for wrong password
```

**Fix:**
```python
import time
import hmac

def unlock(self, password: str) -> bool:
    start_time = time.time()
    success = False
    
    try:
        salt = self._get_or_create_salt()
        key = self._derive_key(password, salt)
        self._fernet = Fernet(key)
        
        if self.storage_path.exists():
            self._load_keys()
        success = True
        
    except Exception:
        success = False
    
    # Constant-time response (always take at least 100ms)
    elapsed = time.time() - start_time
    if elapsed < 0.1:
        time.sleep(0.1 - elapsed)
    
    if not success:
        console.print("[red]Invalid password or corrupted storage[/red]")
    
    return success
```

---

### ⚠️ LOW #8: No File Integrity Verification

**Issue:** Tampering with `.mfa_storage.enc` not detected until decryption

**Current Behavior:**
- Modified file causes decryption error
- No way to distinguish corruption from attack
- No audit trail

**Enhancement:**
```python
import hashlib
import hmac

def _save_keys(self, keys: Dict):
    """Encrypt and save keys with HMAC"""
    data = json.dumps(keys).encode()
    encrypted_data = self._fernet.encrypt(data)
    
    # Add HMAC for integrity
    h = hmac.new(self._fernet._signing_key, encrypted_data, hashlib.sha256)
    integrity_tag = h.digest()
    
    # Store: HMAC (32 bytes) + encrypted data
    self.storage_path.write_bytes(integrity_tag + encrypted_data)
    os.chmod(self.storage_path, 0o600)

def _load_keys(self) -> Dict:
    """Load and verify integrity before decryption"""
    if not self.storage_path.exists():
        return {}
    
    data = self.storage_path.read_bytes()
    
    # Extract HMAC and encrypted data
    integrity_tag = data[:32]
    encrypted_data = data[32:]
    
    # Verify HMAC
    h = hmac.new(self._fernet._signing_key, encrypted_data, hashlib.sha256)
    if not hmac.compare_digest(h.digest(), integrity_tag):
        raise ValueError("Storage file integrity check failed - possible tampering!")
    
    decrypted_data = self._fernet.decrypt(encrypted_data)
    return json.loads(decrypted_data.decode())
```

**Note:** Fernet already includes authentication (HMAC), so this is defense-in-depth.

---

### ⚠️ LOW #9: No Logging of Security Events

**Issue:** No audit trail for:
- Failed unlock attempts
- Key additions/deletions
- Storage modifications
- Suspicious activity

**Fix:**
```python
import logging
from datetime import datetime

# Setup security logger
security_log = Path.home() / ".mfa_security.log"
logging.basicConfig(
    filename=security_log,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecureMFA:
    def unlock(self, password: str) -> bool:
        try:
            # ... unlock logic ...
            logging.info("Storage unlocked successfully")
            return True
        except Exception as e:
            logging.warning(f"Failed unlock attempt: {type(e).__name__}")
            return False
    
    def add_key(self, name: str, secret: str) -> bool:
        # ... validation ...
        logging.info(f"Key added: {name}")
        return True
    
    def remove_key(self, name: str) -> bool:
        # ... removal logic ...
        logging.info(f"Key removed: {name}")
        return True
```

---

## Cryptographic Strength Analysis

### ✅ Strong Points

1. **Encryption Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)
   - Industry standard
   - Authenticated encryption
   - Prevents tampering

2. **Salt Generation:** `os.urandom(16)` 
   - Cryptographically secure
   - 128-bit entropy
   - Unique per installation

3. **Key Derivation:** PBKDF2-HMAC-SHA256
   - Standard algorithm
   - Prevents rainbow tables
   - (But iterations too low)

4. **File Permissions:** 0o600
   - Owner-only access
   - Prevents local user snooping

### ⚠️ Weak Points

1. **PBKDF2 Iterations:** 100,000 (should be 600,000+)
2. **No Rate Limiting:** Unlimited password attempts
3. **No Memory Protection:** Secrets in cleartext in RAM
4. **No Secure Deletion:** Data persists in memory/swap

---

## Attack Surface Summary

### Online Attacks (Tool Running)
- ✅ Password required for all operations
- ❌ No rate limiting (brute force possible)
- ❌ No account lockout
- ❌ No logging of attempts

### Offline Attacks (Files Stolen)
- ✅ Files are encrypted
- ⚠️ PBKDF2 iterations low (GPU crackable)
- ✅ Unique salt per installation
- ❌ No additional key stretching

### Side-Channel Attacks
- ⚠️ Timing attacks possible
- ❌ Memory dumps reveal secrets
- ❌ Swap file may contain secrets
- ✅ No network communication

### Physical Access Attacks
- ✅ File permissions protect from other users
- ❌ Root user can read files
- ❌ Cold boot attack could recover keys
- ❌ No TPM/hardware security module

---

## Recommended Fixes (Priority Order)

### 🔴 Critical (Implement Now)

1. **Add Rate Limiting**
   - Exponential backoff after 3 failures
   - Lockout period: 2^(attempts-2) seconds
   - Log all attempts

2. **Increase PBKDF2 Iterations**
   - Change from 100,000 to 600,000
   - Add migration path for existing users
   - Consider Argon2id for new installations

3. **Add Input Validation**
   - Validate key names (alphanumeric + limited special chars)
   - Validate TOTP secrets (base32 format)
   - Limit key name length to 100 chars
   - Limit total keys to 500

### ⚠️ High (Implement This Week)

4. **Add Import Limits**
   - Maximum 1000 lines per import
   - Maximum 500 total keys
   - Progress feedback for large imports

5. **Implement Security Logging**
   - Log all unlock attempts (success/failure)
   - Log key additions/deletions
   - Log suspicious activity
   - Rotate logs to prevent bloat

6. **Add Backup Functionality**
   - Encrypted backup command
   - Recovery code generation
   - Backup verification

### 📋 Medium (Implement This Month)

7. **Add Timing Attack Protection**
   - Constant-time responses
   - Minimum response delay (100ms)

8. **Add File Integrity Checks**
   - HMAC verification before decryption
   - Detect tampering vs corruption
   - Alert on integrity failures

9. **Improve Error Messages**
   - Distinguish error types (for user)
   - Generic messages (for security)
   - Helpful troubleshooting hints

---

## Compliance & Standards

### OWASP Compliance
- ✅ Encrypted storage at rest
- ⚠️ Key derivation (iterations low)
- ❌ No rate limiting
- ❌ No account lockout
- ✅ No plaintext secrets

### NIST SP 800-63B
- ⚠️ Password-based authentication (acceptable)
- ❌ No multi-factor for the MFA tool itself
- ✅ Encrypted storage
- ⚠️ PBKDF2 iterations below recommendation

### Best Practices
- ✅ Principle of least privilege (file permissions)
- ✅ Defense in depth (encryption + permissions)
- ❌ Fail secure (no rate limiting)
- ⚠️ Audit logging (not implemented)

---

## Conclusion

**Overall Security Rating:** ⚠️ **MEDIUM-HIGH**

The MFA tool has **solid cryptographic foundations** but **critical operational security gaps**:

**Strengths:**
- Strong encryption (Fernet/AES)
- Proper file permissions
- Secure random salt generation
- No plaintext storage

**Critical Weaknesses:**
- No rate limiting (brute force vulnerable)
- PBKDF2 iterations too low
- No input validation
- No security logging

**Risk Assessment:**
- **Low risk** if master password is strong (20+ chars, random)
- **Medium risk** with typical password (12-16 chars, dictionary words)
- **High risk** if password is weak (<12 chars, common words)

**Recommended Action:** Implement rate limiting and increase PBKDF2 iterations immediately.

---

**Audit completed:** January 17, 2026  
**Next review:** After implementing critical fixes
