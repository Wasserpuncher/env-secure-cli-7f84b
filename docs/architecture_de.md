# EnvSecure CLI Architektur

Dieses Dokument beschreibt das architektonische Design und die Schlüsselkomponenten des EnvSecure CLI-Dienstprogramms. Das Hauptziel ist es, ein sicheres, zuverlässiges und benutzerfreundliches Tool zur Verwaltung sensibler Umgebungsvariablen durch Verschlüsselung und Entschlüsselung bereitzustellen.

## Designprinzipien

1.  **Sicherheit zuerst**: Die Verschlüsselung wird von der `cryptography`-Bibliothek, insbesondere `Fernet`, gehandhabt, die eine starke, symmetrische Verschlüsselung gewährleistet. Die Schlüsselverwaltung ist von größter Bedeutung, mit starken Empfehlungen für Umgebungsvariablen in der Produktion.
2.  **Modularität**: Die Codebasis ist in separate Klassen organisiert, die Zuständigkeiten wie kryptografische Operationen von der CLI-Analyse und dem Laden von Schlüsseln trennen.
3.  **Benutzerfreundlichkeit**: Eine klare und intuitive Befehlszeilenschnittstelle, betrieben von `click`, macht das Tool einfach zu erlernen und zu verwenden.
4.  **Erweiterbarkeit**: Das modulare Design ermöglicht zukünftige Erweiterungen, wie die Unterstützung verschiedener Verschlüsselungsalgorithmen, Schlüsselrotation oder die Integration mit Geheimnisverwaltungsservices, ohne umfangreiche Refaktorierung.
5.  **Testbarkeit**: Jede Komponente ist so konzipiert, dass sie unabhängig testbar ist, was robuste Unit- und Integrationstests erleichtert.

## Kernkomponenten

Die EnvSecure CLI basiert auf zwei Hauptklassen und einer `click`-Befehlszeilenschnittstellenstruktur.

### 1. `EnvSecureCLIError` (Benutzerdefinierte Ausnahme)

*   **Zweck**: Eine benutzerdefinierte Ausnahmeklasse, abgeleitet von `Exception`, um eine spezifische Fehlerbehandlung für CLI-bezogene Probleme bereitzustellen. Dies ermöglicht klarere Fehlermeldungen und robustere Fehlerabläufe innerhalb der Anwendung.

### 2. `CipherHandler` Klasse

*   **Ort**: `main.py`
*   **Verantwortlichkeit**: Diese Klasse ist die direkte Schnittstelle zur `cryptography.fernet`-Bibliothek. Sie abstrahiert die Low-Level-Details der Verschlüsselung und Entschlüsselung.
*   **Schlüsselmethoden**:
    *   `__init__(self, key: bytes)`: Initialisiert den Handler mit einem gegebenen Fernet-Schlüssel. Es führt eine grundlegende Validierung des Schlüsselformats durch.
    *   `generate_key() -> bytes`: Eine statische Methode zur Erstellung eines neuen, URL-sicheren Base64-kodierten Fernet-Schlüssels.
    *   `encrypt(self, data: str) -> bytes`: Nimmt einen String, kodiert ihn in UTF-8 und verschlüsselt ihn mit dem initialisierten Fernet-Schlüssel.
    *   `decrypt(self, token: bytes) -> str`: Nimmt einen Byte-Token (verschlüsselte Daten), entschlüsselt ihn und dekodiert ihn zurück in einen UTF-8-String. Es beinhaltet Fehlerbehandlung für `InvalidToken` (z.B. falscher Schlüssel, manipulierter Token).
*   **Sicherheitsaspekt**: Durch die Kapselung der `Fernet`-Operationen stellt `CipherHandler` sicher, dass die Verschlüsselung/Entschlüsselung immer korrekt und konsistent mit dem empfohlenen `Fernet`-Primitiv durchgeführt wird.

### 3. `EnvSecureCLI` Klasse

*   **Ort**: `main.py`
*   **Verantwortlichkeit**: Dies ist die Hauptklasse der Geschäftslogik, die die Schlüsselverwaltung orchestriert, die `CipherHandler`-Instanz verwaltet und übergeordnete Methoden für Verschlüsselung und Entschlüsselung bereitstellt, die von den CLI-Befehlen aufgerufen werden.
*   **Schlüsselmethoden**:
    *   `__init__(self, key_source: Optional[str] = None, key_file_path: str = "env_key.txt")`: Initialisiert die CLI-Instanz. Sie kann optional einen Schlüssel sofort basierend auf `key_source` laden.
    *   `_load_key(self, key_source: str) -> None`: Eine private Hilfsmethode, die für das Abrufen des Verschlüsselungsschlüssels verantwortlich ist. Sie unterstützt das Laden aus:
        *   **Umgebungsvariable (`SECRET_KEY`)**: Empfohlen für Produktionsumgebungen, um Schlüssel auf der Festplatte zu vermeiden.
        *   **Lokale Datei (`env_key.txt` standardmäßig)**: Nützlich für die Entwicklung oder spezifische isolierte Bereitstellungen. Enthält Prüfungen auf Dateiexistenz und Inhalt.
    *   `generate_key_and_save(self, output_path: Optional[str] = None, print_key: bool = False) -> Tuple[str, bytes]`: Generiert einen neuen Schlüssel und speichert ihn optional in einer angegebenen Datei oder gibt ihn auf stdout aus. Es gibt Warnungen, wenn der Schlüssel nicht gespeichert wird.
    *   `encrypt_value(self, value: str) -> str`: Übergeordnete Methode zum Verschlüsseln eines gegebenen String-Wertes mit dem geladenen `CipherHandler`.
    *   `decrypt_value(self, encrypted_value: str) -> str`: Übergeordnete Methode zum Entschlüsseln eines gegebenen verschlüsselten String-Wertes mit dem geladenen `CipherHandler`.
*   **Fehlerbehandlung**: Methoden in `EnvSecureCLI` lösen `EnvSecureCLIError` für Probleme wie fehlende Schlüssel oder ungültige Schlüsselquellen aus, die dann von den `click`-Befehlshandlern abgefangen werden.

### 4. `click` CLI-Anwendung

*   **Ort**: `main.py` (Dekoratoren und Befehlsfunktionen)
*   **Verantwortlichkeit**: Definiert die Befehlszeilenschnittstelle mithilfe der `click`-Bibliothek. Sie verarbeitet die Argumentanalyse, Optionsvalidierung und Weiterleitung an die Methoden der `EnvSecureCLI`-Klasse.
*   **Befehle**:
    *   `cli()`: Der Hauptgruppenbefehl.
    *   `generate-key`: Befehl zum Generieren eines neuen Fernet-Schlüssels. Optionen umfassen `--output-path` (zum Speichern in einer Datei) und `--print-key` (zum Ausgeben auf der Konsole).
    *   `encrypt`: Befehl zum Verschlüsseln eines Wertes. Optionen umfassen `--value`, `--key-source` (`env` oder `file`) und `--key-file` (falls `key_source` `file` ist).
    *   `decrypt`: Befehl zum Entschlüsseln eines Wertes. Optionen ähneln denen von `encrypt`.
*   **Benutzerinteraktion**: Bietet Benutzerfeedback über `click.echo` für Erfolgsmeldungen, Warnungen und Fehlermeldungen.

## Schlüsselverwaltungsstrategie

Eine sichere Schlüsselverwaltung ist entscheidend für die Integrität der verschlüsselten Daten. EnvSecure CLI unterstützt zwei primäre Methoden, jede mit ihrem empfohlenen Anwendungsfall:

1.  **Umgebungsvariable (`SECRET_KEY`)**: Dies ist die **empfohlene Methode für Produktionsumgebungen**. Das Speichern des Schlüssels in einer Umgebungsvariable verhindert, dass er auf der Festplatte gespeichert wird (wo er versehentlich in die Versionskontrolle gelangen oder von unbefugten Prozessen abgerufen werden könnte). Es hängt von der Umgebung ab, in der die Anwendung ausgeführt wird (z.B. CI/CD-Pipelines, Container-Orchestrierung, Cloud-Geheimnismanager), um diese Variable sicher zu injizieren.
2.  **Lokale Datei (`env_key.txt` standardmäßig)**: Diese Methode eignet sich für die **lokale Entwicklung oder unkritische, isolierte Bereitstellungen**. Der Schlüssel wird aus einer angegebenen Datei gelesen. **Wichtig ist, dass jede Schlüsseldatei von der Versionskontrolle ausgeschlossen werden muss (z.B. über `.gitignore`) und mit entsprechenden Dateisystemberechtigungen geschützt werden muss.**

## Sicherheitsüberlegungen

*   **Schlüsselgeheimnis**: Der Fernet-Schlüssel ist der einzige Fehlerpunkt. Wenn der Schlüssel kompromittiert wird, können alle verschlüsselten Daten entschlüsselt werden. Behandeln Sie den Schlüssel immer als hochsensibel.
*   **Schlüsselspeicherung**: Vermeiden Sie das Festcodieren von Schlüsseln im Quellcode. Umgebungsvariablen werden für die Produktion gegenüber Dateien bevorzugt.
*   **`generate-key`-Ausgabe**: Die Option `--print-key` sollte in der Produktion mit äußerster Vorsicht verwendet werden, da sie den Schlüssel in Protokollen oder der Terminalhistorie offenlegen kann. Bevorzugen Sie `--output-path` und übertragen Sie den Schlüssel dann sicher in eine Umgebungsvariable.
*   **`cryptography`-Bibliothek**: Das Projekt basiert auf `cryptography.fernet`, einem hochrangigen symmetrischen Verschlüsselungsprimitiv, das für Benutzerfreundlichkeit und Sicherheit entwickelt wurde und auf starken zugrunde liegenden Algorithmen (AES im CBC-Modus mit HMAC) aufbaut.
*   **Keine Schlüsselrotation**: Die aktuelle Version unterstützt keine automatische Schlüsselrotation. Die Implementierung der Schlüsselrotation würde ein komplexeres Schlüsselverwaltungssystem erfordern (z.B. Speichern mehrerer Schlüssel, Versionierung verschlüsselter Daten), was über den Umfang eines grundlegenden CLI-Dienstprogramms hinausgeht, aber eine zukünftige Verbesserung sein könnte.

## Zukünftige Verbesserungen

*   **Konfigurationsdatei**: Implementieren Sie Unterstützung für eine `config.json`- oder `YAML`-Datei, um mehrere Schlüssel, verschiedene Verschlüsselungskontexte oder Standardeinstellungen für `key_file_path` zu verwalten.
*   **Schlüsselrotation**: Führen Sie Mechanismen zur Rotation von Verschlüsselungsschlüsseln und zur erneuten Verschlüsselung von Daten ein.
*   **Integration mit Cloud-Geheimnismanagern**: Fügen Sie Unterstützung für das direkte Abrufen von Schlüsseln von Diensten wie AWS Secrets Manager, Azure Key Vault oder HashiCorp Vault hinzu.
*   **Nicht-interaktiver Modus**: Ermöglichen Sie die Verschlüsselung/Entschlüsselung mehrerer Werte aus einer Datei oder stdin.
*   **Pre-commit Hooks**: Fügen Sie Pre-Commit-Hooks für Linting, Formatierung und grundlegende Sicherheitsprüfungen hinzu.