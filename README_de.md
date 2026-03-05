# EnvSecure CLI

[![Python application](https://github.com/your-org/env-secure-cli/actions/workflows/python-app.yml/badge.svg)](https://github.com/your-org/env-secure-cli/actions/workflows/python-app.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Ein leistungsstarkes und sicheres Befehlszeilen-Dienstprogramm zum Verschlüsseln und Entschlüsseln von Umgebungsvariablen. Entwickelt für Entwickler- und Betriebsteams, hilft EnvSecure CLI Ihnen, sensible Konfigurationsdaten sicher zu verwalten und so eine versehentliche Offenlegung in der Quellcodeverwaltung oder in unsicheren Umgebungen zu verhindern.

## Funktionen

*   **Sichere Verschlüsselung**: Nutzt `cryptography.fernet` für robuste, symmetrische Verschlüsselung.
*   **Flexible Schlüsselverwaltung**: Laden Sie Verschlüsselungsschlüssel aus Umgebungsvariablen (für die Produktion empfohlen) oder lokalen Dateien.
*   **CLI-Schnittstelle**: Einfach zu bedienende Befehlszeilenschnittstelle, betrieben von `click`.
*   **Schlüsselgenerierung**: Generieren Sie neue Fernet-Verschlüsselungsschlüssel direkt über die CLI.
*   **Zweisprachige Dokumentation**: Umfassende Dokumentation in Englisch und Deutsch verfügbar.
*   **Enterprise-Ready**: Entwickelt nach Best Practices, einschließlich Typ-Hints, Docstrings und Unit-Tests.

## Inhaltsverzeichnis

*   [Installation](#installation)
*   [Schnellstart](#schnellstart)
*   [Schlüsselverwaltung](#schlüsselverwaltung)
    *   [Einen neuen Schlüssel generieren](#einen-neuen-schlüssel-generieren)
    *   [Schlüssel aus Umgebungsvariable laden (Empfohlen)](#schlüssel-aus-umgebungsvariable-laden-empfohlen)
    *   [Schlüssel aus Datei laden](#schlüssel-aus-datei-laden)
*   [Verwendung](#verwendung)
    *   [Einen Wert verschlüsseln](#einen-wert-verschlüsseln)
    *   [Einen Wert entschlüsseln](#einen-wert-entschlüsseln)
*   [Mitwirken](#mitwirken)
*   [Lizenz](#lizenz)
*   [Architektur](#architektur)

## Installation

1.  **Repository klonen:**
    ```bash
    git clone https://github.com/your-org/env-secure-cli.git
    cd env-secure-cli
    ```

2.  **Virtuelle Umgebung erstellen (empfohlen):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # Unter Windows: `venv\Scripts\activate`
    ```

3.  **Abhängigkeiten installieren:**
    ```bash
    pip install -r requirements.txt
    ```

## Schnellstart

### 1. Einen Schlüssel generieren

Generieren Sie zuerst einen sicheren Verschlüsselungsschlüssel. **Bewahren Sie diesen Schlüssel sicher und geheim auf!**

```bash
python main.py generate-key --output-path env_key.txt
# Oder nur auf der Konsole ausgeben (mit Vorsicht verwenden):
# python main.py generate-key --print-key
```

### 2. Den Schlüssel setzen (z.B. als Umgebungsvariable)

Für die Produktion wird dringend empfohlen, eine Umgebungsvariable zu verwenden.

```bash
export SECRET_KEY="$(cat env_key.txt)" # Unter Linux/macOS
# Für Windows PowerShell:
# $env:SECRET_KEY = (Get-Content -Raw env_key.txt)
```

### 3. Einen Wert verschlüsseln

```bash
python main.py encrypt --value "mein_geheimer_api_schlüssel_123" --key-source env
# Ausgabe: Verschlüsselter Wert: gAAAAABh... (Ihr verschlüsselter String)
```

### 4. Einen Wert entschlüsseln

```bash
python main.py decrypt --value "gAAAAABh..." --key-source env
# Ausgabe: Entschlüsselter Wert: mein_geheimer_api_schlüssel_123
```

## Schlüsselverwaltung

EnvSecure CLI unterstützt zwei primäre Methoden zur Bereitstellung des Verschlüsselungsschlüssels:

### Einen neuen Schlüssel generieren

```bash
python main.py generate-key [--output-path <pfad_zur_datei>] [--print-key]
```
*   `--output-path`: Speichert den generierten Schlüssel in der angegebenen Datei. Z.B. `env_key.txt`.
*   `--print-key`: Gibt den generierten Schlüssel auf der Standardausgabe aus. **Seien Sie vorsichtig, wenn Sie dies in Produktionsumgebungen verwenden, da Schlüssel protokolliert werden könnten.**

Wenn weder `--output-path` noch `--print-key` angegeben wird, wird der Schlüssel mit einer Warnung auf stdout ausgegeben.

### Schlüssel aus Umgebungsvariable laden (Empfohlen)

Für Produktionsbereitstellungen ist die Speicherung des Verschlüsselungsschlüssels in einer Umgebungsvariable (`SECRET_KEY`) die sicherste und empfohlene Methode. Dies verhindert, dass der Schlüssel in die Quellcodeverwaltung gelangt oder auf dem Dateisystem verbleibt.

```bash
export SECRET_KEY="Ihr_fernet_schlüssel_hier" # Linux/macOS
# $env:SECRET_KEY = "Ihr_fernet_schlüssel_hier" # Windows PowerShell

python main.py encrypt -v "mein_db_passwort" -s env
python main.py decrypt -v "gAAAAAB..." -s env
```

### Schlüssel aus Datei laden

Für die lokale Entwicklung oder spezifische Anwendungsfälle können Sie den Schlüssel in einer Datei speichern (z.B. `env_key.txt`). **Stellen Sie sicher, dass diese Datei von der Versionskontrolle ausgeschlossen ist (z.B. über `.gitignore`) und entsprechend gesichert wird.**

```bash
python main.py encrypt -v "mein_db_passwort" -s file -f env_key.txt
python main.py decrypt -v "gAAAAAB..." -s file -f env_key.txt
```
*   `--key-file` (`-f`): Gibt den Pfad zur Schlüsseldatei an. Standardmäßig `env_key.txt`.

## Verwendung

### Einen Wert verschlüsseln

```bash
python main.py encrypt --value "<IHR_ZU_VERSCHLÜSSELNDER_WERT>" --key-source <env|file> [--key-file <pfad_zur_schlüsseldatei>]
```

**Beispiel (mit Umgebungsvariable):**
```bash
export SECRET_KEY="$(python main.py generate-key --print-key)"
python main.py encrypt -v "super_geheimer_token" -s env
# Ausgabe: Verschlüsselter Wert: gAAAAABh...Cg==
```

### Einen Wert entschlüsseln

```bash
python main.py decrypt --value "<IHR_VERSCHLÜSSELTER_WERT>" --key-source <env|file> [--key-file <pfad_zur_schlüsseldatei>]
```

**Beispiel (mit Datei):**
```bash
python main.py generate-key -o my_app_key.txt
python main.py encrypt -v "db_benutzer_passwort" -s file -f my_app_key.txt
# (Den verschlüsselten Wert kopieren)
python main.py decrypt -v "gAAAAABi...YQ==" -s file -f my_app_key.txt
# Ausgabe: Entschlüsselter Wert: db_benutzer_passwort
```

## Mitwirken

Wir freuen uns über Beiträge! Bitte lesen Sie die Richtlinien in `CONTRIBUTING.md`.

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Details finden Sie in der Datei `LICENSE`.

## Architektur

Für ein detailliertes Verständnis der Projektarchitektur und der Designentscheidungen lesen Sie bitte `docs/architecture_de.md`.