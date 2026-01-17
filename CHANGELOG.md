# Changelog - MFA TOTP Tool

## [2.0.0] - 2026-01-17 - Security Enhanced Release

### 🔒 Security Improvements

#### Critical Fixes
- **PBKDF2 Iterations Increased**: 100,000 → 600,000 (OWASP 2023 compliant)
  - Automatic upgrade on first unlock
  - Full backward compatibility with existing storage
  - 6x harder to crack passwords

- **Rate Limiting**: Exponential backoff after failed attempts
  - Lockout after 3 failures: 2s, 4s, 8s, 16s, 32s...
  - Prevents brute force attacks
  - Automatic reset on successful unlock

- **Input Validation**: Comprehensive validation for all inputs
  - Key names: max 100 chars, alphanumeric + `_ - .` and spaces
  - TOTP secrets: validated base32 format
  - Prevents injection attacks and data corruption

- **Import Limits**: Protection against DoS attacks
  - Maximum 1,000 lines per import
  - Maximum 500 total keys in storage
  - Clear error messages when limits exceeded

#### Security Features Added
- **Security Event Logging**: All operations logged to `~/.mfa_security.log`
  - Unlock attempts (success/failure)
  - Key additions/deletions
  - Failed attempts tracking
  - Audit trail for forensics

- **Timing Attack Protection**: Constant-time responses
  - Minimum 100ms unlock time
  - Prevents statistical password analysis
  - Protects against side-channel attacks

### 🐛 Bug Fixes
- Fixed CLI command conflict with Python's built-in `list`
- Improved error messages for invalid inputs
- Better handling of corrupted storage files

### ✨ Enhancements
- Automatic security upgrade on first use
- Duplicate key detection with confirmation prompt
- Better progress feedback during import
- Cleaner secret formatting (auto-uppercase, strip spaces)

### 📝 Documentation
- Added `MFA_SECURITY_AUDIT.md` - Complete security analysis
- Added `SECURITY_UPGRADE_NOTES.md` - Upgrade guide
- Added `CHANGELOG.md` - Version history

### 🔄 Backward Compatibility
- ✅ Existing `.mfa_storage.enc` files work without modification
- ✅ Automatic one-time upgrade to new security level
- ✅ All existing TOTP keys preserved
- ✅ Same master password works
- ✅ Same command syntax

### 📊 Performance
- Unlock time: ~0.1s → ~0.5s (due to 600K iterations, one-time upgrade)
- Subsequent unlocks: ~0.5s (worth it for 6x security improvement)
- No impact on code generation speed

### 🔐 Security Metrics
| Metric | v1.0 | v2.0 |
|--------|------|------|
| PBKDF2 Iterations | 100,000 | 600,000 |
| Rate Limiting | None | Exponential |
| Input Validation | None | Full |
| Security Logging | None | Complete |
| Timing Protection | None | Yes |
| OWASP Compliance | Partial | Full |

---

## [1.0.0] - Initial Release

### Features
- Encrypted TOTP key storage using Fernet (AES-256)
- PBKDF2-HMAC-SHA256 key derivation (100K iterations)
- CLI interface with Click
- Commands: init, add, remove, list, code, import-keys
- File permissions: 0o600 (owner-only access)
- Rich console output with tables

### Security
- Encrypted storage at rest
- Secure password prompts (no bash history)
- Cryptographically secure salt generation
- JSON-based key storage

---

## Migration Guide: v1.0 → v2.0

### Automatic Migration
No manual steps required! The upgrade happens automatically:

1. Run any command (e.g., `./multifactor.py list`)
2. Enter your password
3. See "Upgrading key derivation security..."
4. Done! Storage now uses 600K iterations

### What Gets Upgraded
- ✅ PBKDF2 iterations (100K → 600K)
- ✅ Storage file re-encrypted with new iterations
- ✅ All keys preserved

### What Stays the Same
- ✅ Your master password
- ✅ Storage file location (`~/.mfa_storage.enc`)
- ✅ All TOTP keys and names
- ✅ Command syntax

### Rollback (if needed)
Before upgrading, backup your storage:
```bash
cp ~/.mfa_storage.enc ~/.mfa_storage.enc.v1.backup
cp ~/.mfa_storage.enc.salt ~/.mfa_storage.enc.salt.v1.backup
```

To rollback:
```bash
cp ~/.mfa_storage.enc.v1.backup ~/.mfa_storage.enc
cp ~/.mfa_storage.enc.salt.v1.backup ~/.mfa_storage.enc.salt
# Use v1.0 multifactor.py
```

---

## Testing v2.0

### Verify Upgrade
```bash
# Test unlock and upgrade
./multifactor.py list

# Check security log
tail ~/.mfa_security.log

# Verify all keys work
./multifactor.py code
```

### Test Rate Limiting
```bash
# Try wrong password 3 times
./multifactor.py list
# Enter wrong password 3x
# Should see lockout message
```

### Test Input Validation
```bash
# Try invalid key name
./multifactor.py add "invalid@#$name"
# Should reject with error message

# Try invalid secret
./multifactor.py add "test"
# Enter non-base32 secret
# Should reject with error message
```

---

## Known Issues

### None reported

---

## Future Enhancements (Planned)

- [ ] Backup/restore functionality
- [ ] Recovery codes for lost passwords
- [ ] Export to encrypted backup file
- [ ] QR code generation for easy mobile setup
- [ ] Hardware security module (HSM) support
- [ ] Argon2id key derivation option
- [ ] Multi-user support with separate storage
- [ ] Web interface option
- [ ] Mobile app integration

---

## Security Advisories

### None

If you discover a security vulnerability, please report it responsibly.

---

## Credits

- Security audit and enhancements: White Hat Security Analysis
- Original implementation: MFA Tool v1.0
- Cryptography: Python `cryptography` library (Fernet)
- TOTP: `pyotp` library
- CLI: `click` library
- UI: `rich` library

---

**Version 2.0.0 - Security Enhanced**  
Released: January 17, 2026
