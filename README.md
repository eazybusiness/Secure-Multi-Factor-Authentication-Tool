# Secure Multi-Factor Authentication Tool

Ein sicheres Kommandozeilen-Tool zur Verwaltung von TOTP-Schlüsseln mit verschlüsselter Speicherung.

## Features

- 🔐 **Verschlüsselte Speicherung**: TOTP-Schlüssel werden mit PBKDF2 und AES-256 verschlüsselt
- 🔒 **Keine Bash-Historie**: Passwörter und Secrets werden sicher eingegeben
- 🚀 **Schnelle Code-Generierung**: Einzeilige TOTP-Codes für alle Accounts
- 📋 **Schlüssel-Management**: Hinzufügen, Löschen und Auflisten von Accounts
- 📥 **Import-Funktion**: Einfacher Import von bestehenden Schlüsseln

## Installation

```bash
# Klonen des Repositories
git clone <repository-url>
cd multifactor

# Abhängigkeiten installieren
pip install -r requirements.txt

# Ausführbar machen
chmod +x multifactor.py
```

## Schnellstart

### 1. Initialisierung
```bash
./multifactor.py init
```
Geben Sie ein sicheres Master-Passwort ein. Dies wird zum Verschlüsseln aller Ihrer TOTP-Schlüssel verwendet.

### 2. Schlüssel hinzufügen
```bash
./multifactor.py add "Google Account"
# Geben Sie Ihren TOTP-Secret ein (base32 formatiert)
```

### 3. Codes generieren
```bash
# Code für einen spezifischen Account
./multifactor.py code "Google Account"

# Alle Codes auf einmal
./multifactor.py code
```

## Befehle

### `init`
Initialisiert die verschlüsselte Speicherung.
```bash
./multifactor.py init [--password PASSWORD]
```

### `add`
Fügt einen neuen TOTP-Schlüssel hinzu.
```bash
./multifactor.py add [--password PASSWORD] NAME [--secret SECRET]
```

### `remove`
Entfernt einen TOTP-Schlüssel.
```bash
./multifactor.py remove [--password PASSWORD] NAME
```

### `list`
Listet alle gespeicherten Schlüssel auf.
```bash
./multifactor.py list [--password PASSWORD]
```

### `code`
Generiert TOTP-Codes.
```bash
./multifactor.py code [--password PASSWORD] [NAME]
```

### `import-keys`
Importiert mehrere Schlüssel auf einmal.
```bash
./multifactor.py import-keys [--password PASSWORD]
```

## Sicherheit

### Verschlüsselung
- **Algorithmus**: PBKDF2 mit SHA-256 (100.000 Iterationen)
- **Verschlüsselung**: AES-256 im CBC-Modus (via Fernet)
- **Salt**: Zufälliger 16-Byte Salt für jede Installation

### Dateiberechtigungen
- Speicherdateien haben eingeschränkte Berechtigungen (0o600)
- Nur der Benutzer kann die Dateien lesen/schreiben

### Passwort-Sicherheit
- Passwörter werden nie in der Bash-Historie gespeichert
- Sichere Eingabe über `getpass` und Click-Prompts
- Keine Klartext-Speicherung

## Migration von oathtool

Wenn Sie bereits `oathtool --totp -b` verwenden:

1. Exportieren Sie Ihre Secrets:
```bash
# Beispiel für die Migration
echo "Google:JBSWY3DPEHPK3PXP" > keys.txt
echo "GitHub:JBSWY3DPEHPK3PXQ" >> keys.txt
```

2. Importieren Sie mit dem Tool:
```bash
./multifactor.py import-keys
# Fügen Sie die Zeilen aus keys.txt ein
```

## Beispiele

### Tägliche Nutzung
```bash
# Alle Codes für den Morgen-Check
./multifactor.py code

# Schnellen Code für eine Anmeldung
./multifactor.py code "GitHub"
```

### Schlüssel-Management
```bash
# Alle Accounts auflisten
./multifactor.py list

# Neuen Account hinzufügen
./multifactor.py add "AWS Console"

# Alten Account entfernen
./multifactor.py remove "Old Service"
```

## Speicherort

Standardmäßig werden die verschlüsselten Daten gespeichert unter:
- `~/.mfa_storage.enc` (verschlüsselte Schlüssel)
- `~/.mfa_storage.enc.salt` (Salt für die Schlüsselableitung)

## Backup

Erstellen Sie Backups der verschlüsselten Dateien:
```bash
cp ~/.mfa_storage.enc ~/.mfa_storage.enc.backup
cp ~/.mfa_storage.enc.salt ~/.mfa_storage.enc.salt.backup
```

**Wichtig**: Bewahren Sie Ihr Master-Passwort sicher auf! Ohne dieses Passwort können die Backups nicht entschlüsselt werden.

## Troubleshooting

### "Invalid password"
- Überprüfen Sie Ihr Master-Passwort
- Stellen Sie sicher, dass die Speicherdateien nicht beschädigt sind

### "Key not found"
- Überprüfen Sie den genauen Namen des Schlüssels mit `./multifactor.py list`
- Die Namen sind case-sensitive

### "Error adding key"
- Stellen Sie sicher, dass der Secret im korrekten Base32-Format vorliegt
- Testen Sie den Secret mit `oathtool --totp -b YOUR_SECRET`

## Lizenz

MIT License - siehe LICENSE Datei für Details.

## Contributing

Siehe CONTRIBUTING.md für Entwickler-Richtlinien.
