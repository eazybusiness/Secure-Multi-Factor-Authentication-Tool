# Contributing to Secure Multi-Factor Authentication Tool

Vielen Dank für Ihr Interesse an der Weiterentwicklung dieses sicheren MFA-Tools!

## Entwicklungs-Setup

### 1. Environment einrichten
```bash
# Repository klonen
git clone <repository-url>
cd multifactor

# Virtuelle Umgebung erstellen
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# oder venv\Scripts\activate  # Windows

# Abhängigkeiten installieren
pip install -r requirements.txt
pip install pytest pytest-cov black flake8  # Entwicklungs-Tools
```

### 2. Code-Style

Wir verwenden folgende Tools und Standards:

- **Black** für Code-Formatierung
- **Flake8** für Linting
- **Type Hints** für alle Funktionen
- **Docstrings** im Google Style

```bash
# Code formatieren
black multifactor.py

# Linting
flake8 multifactor.py
```

## Code-Struktur

### Hauptkomponenten

1. **SecureMFA Klasse**: Kernfunktionalität für Verschlüsselung und Schlüssel-Management
2. **CLI Interface**: Click-basierte Kommandozeilen-Befehle
3. **Sicherheits-Module**: Kryptographie-Funktionen und sichere Eingabe

### Sicherheits-Prinzipien

- **Defense in Depth**: Mehrere Sicherheitsschichten
- **Zero Trust**: Keine impliziten Annahmen über Sicherheit
- **Least Privilege**: Minimale Berechtigungen für Dateien
- **Secure by Default**: Sichere Standard-Konfigurationen

## Testing

### Unit Tests
```bash
# Tests ausführen
pytest tests/

# Mit Coverage
pytest --cov=multifactor tests/
```

### Sicherheits-Tests

- Verschlüsselungs-Validierung
- Passwort-Stärke-Tests
- Dateiberechtigungs-Checks
- Memory-Safety Tests

## Pull Request Prozess

### 1. Branch erstellen
```bash
git checkout -b feature/ihre-feature
```

### 2. Änderungen machen
- Folgen Sie dem Code-Style
- Fügen Sie Tests hinzu
- Dokumentieren Sie Änderungen

### 3. Pull Request
- Beschreiben Sie das Problem und die Lösung
- Zeigen Sie Test-Ergebnisse
- Erklären Sie Sicherheits-Implikationen

## Sicherheits-Reporting

### Gefundene Sicherheitsprobleme
**Bitte nicht öffentlich melden!**

Senden Sie eine E-Mail an: security@project.com

Inkludieren Sie:
- Beschreibung des Problems
- Schritt-für-Schritt Reproduktion
- Auswirkungen auf die Sicherheit

### Security-Checkliste für Contributions

- [ ] Keine Hardcodierten Passwörter/Keys
- [ ] Sichere Zufallszahlengenerierung
- [ ] Proper Input-Validierung
- [ ] Keine Information-Leaks in Fehlermeldungen
- [ ] Sichere Dateiberechtigungen
- [ ] Memory-Safety (keine Passwörter im RAM belassen)

## Features hinzufügen

### 1. Diskussion
- Eröffnen Sie ein Issue zur Diskussion
- Beschreiben Sie den Use Case
- Überlegen Sie Sicherheits-Implikationen

### 2. Implementierung
- Folgen Sie der existierenden Architektur
- Fügen Sie entsprechende Tests hinzu
- Dokumentieren Sie die Änderungen

### 3. Beispiele für neue Features

#### QR-Code Support
```python
def add_from_qr(self, qr_data: str) -> bool:
    """Add TOTP key from QR code data"""
    # Implementierung mit pyotp parsing
    pass
```

#### Backup/Restore
```python
def export_encrypted(self, export_password: str) -> bytes:
    """Export encrypted backup"""
    pass

def import_encrypted(self, backup_data: bytes, import_password: str) -> bool:
    """Import encrypted backup"""
    pass
```

## Dokumentation

### README Updates
- Neue Features beschreiben
- Beispiele hinzufügen
- Sicherheits-Hinweise aktualisieren

### Code-Dokumentation
- Docstrings für alle öffentlichen Funktionen
- Type Hints für bessere IDE-Unterstützung
- Kommentare für komplexe Logik

## Release-Prozess

### 1. Version bump
```bash
# Version in setup.py oder pyproject.toml aktualisieren
git tag -a v1.1.0 -m "Release version 1.1.0"
```

### 2. Changelog
- Neue Features auflisten
- Bug Fixes dokumentieren
- Sicherheits-Updates hervorheben

### 3. Testing
- Alle Tests bestehen
- Sicherheits-Tests durchführen
- Manuelle Tests auf verschiedenen Systemen

## Community

### Code of Conduct
- Respektvoller Umgang
- Konstruktive Kritik
- Hilfsbereite Haltung

### Kommunikation
- Deutsch und Englisch willkommen
- Klare, präzise Beschreibungen
- Sicherheits-Fokus

## Lizenz

Mit der Contribution stimmen Sie der MIT-Lizenz zu und garantieren, dass:
- Sie die Rechte an Ihrem Code haben
- Der Code keine Lizenzen verletzt
- Der Code sicher und getestet ist

Vielen Dank für Ihre Contribution zur sicheren Authentifizierung!
