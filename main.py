import os
import json
from typing import Any, Dict, Optional, Tuple
import click
from cryptography.fernet import Fernet, InvalidToken

# Standardname der Konfigurationsdatei, die im aktuellen Verzeichnis gesucht wird.
DEFAULT_CONFIG_FILENAME = ".envsecure.json"
# Umgebungsvariable, die auf eine alternative Konfigurationsdatei zeigen kann.
CONFIG_ENV_VAR = "ENVSECURE_CONFIG"
# Erlaubte Schlüssel in der Konfigurationsdatei.
KNOWN_CONFIG_KEYS = {"key_source", "key_file", "output_path"}

class EnvSecureCLIError(Exception):
    """Basis-Ausnahme für EnvSecureCLI-Fehler."""
    pass

def _discover_config_path(cli_config_path: Optional[str]) -> Tuple[str, bool]:
    """Ermittelt den Pfad zur Konfigurationsdatei und ob er explizit gewünscht ist.

    Vorrang der Fundstelle: ``--config``-Flag > Umgebungsvariable ``ENVSECURE_CONFIG``
    > Standarddatei ``.envsecure.json`` im aktuellen Verzeichnis.

    Args:
        cli_config_path (Optional[str]): Der über ``--config`` übergebene Pfad.

    Returns:
        Tuple[str, bool]: Der aufzulösende Pfad und ein Flag, ob der Pfad explizit
                          angefordert wurde (dann ist eine fehlende Datei ein Fehler).
    """
    if cli_config_path:
        return cli_config_path, True
    env_config = os.getenv(CONFIG_ENV_VAR)
    if env_config:
        return env_config, True
    return DEFAULT_CONFIG_FILENAME, False

def load_config(cli_config_path: Optional[str] = None) -> Dict[str, Any]:
    """Lädt die JSON-Konfigurationsdatei (nur Standardbibliothek).

    Eine explizit angeforderte Datei (via ``--config`` oder ``ENVSECURE_CONFIG``) muss
    existieren; die implizite Standarddatei darf fehlen (dann wird ``{}`` geliefert).

    Args:
        cli_config_path (Optional[str]): Der über ``--config`` übergebene Pfad.

    Returns:
        Dict[str, Any]: Die geladenen Konfigurationswerte (leer, wenn keine Datei da ist).

    Raises:
        EnvSecureCLIError: Wenn die Datei fehlt (obwohl explizit angefordert),
                           ungültiges JSON enthält oder kein JSON-Objekt ist.
    """
    path, explicit = _discover_config_path(cli_config_path)
    if not os.path.exists(path):
        if explicit:
            raise EnvSecureCLIError(f"Configuration file '{path}' not found.")
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise EnvSecureCLIError(f"Could not read configuration file '{path}': {e}")
    if not isinstance(data, dict):
        raise EnvSecureCLIError(f"Configuration file '{path}' must contain a JSON object.")
    # Sicherheitshinweis: Es dürfen nur Pfade/Quellen konfiguriert werden, niemals der
    # geheime Schlüssel selbst. Ein versehentlich abgelegter Schlüssel wird abgelehnt.
    if 'secret_key' in data or 'key' in data:
        raise EnvSecureCLIError(
            "Configuration file must not contain a raw secret key. "
            "Use 'key_source'/'key_file' to reference the key instead."
        )
    return data

def resolve_setting(cli_value: Optional[str], config: Dict[str, Any], key: str,
                    env_var: Optional[str], default: Optional[str]) -> Optional[str]:
    """Löst eine einzelne Einstellung nach der Vorrangregel auf.

    Vorrang: CLI-Flag > Config-Datei > Umgebungsvariable > eingebauter Default.

    Args:
        cli_value (Optional[str]): Der auf der Kommandozeile übergebene Wert (oder None).
        config (Dict[str, Any]): Die geladene Konfiguration.
        key (str): Der Schlüssel in der Konfiguration.
        env_var (Optional[str]): Name der Umgebungsvariable oder None.
        default (Optional[str]): Der eingebaute Standardwert.

    Returns:
        Optional[str]: Der aufgelöste Wert.
    """
    if cli_value is not None:
        return cli_value
    if config.get(key) is not None:
        return config[key]
    if env_var:
        env_value = os.getenv(env_var)
        if env_value is not None:
            return env_value
    return default

class CipherHandler:
    """Verantwortlich für die Handhabung der Verschlüsselungs-/Entschlüsselungslogik.

    Dieser Handler kapselt die 'cryptography.fernet'-Bibliothek und bietet Methoden
    zum Generieren von Schlüsseln, Verschlüsseln und Entschlüsseln von Daten.
    """

    def __init__(self, key: bytes):
        """Initialisiert den CipherHandler mit einem Fernet-Schlüssel.

        Args:
            key (bytes): Der geheime Schlüssel, der für die Verschlüsselung verwendet wird.
        """
        try:
            # Versucht, ein Fernet-Objekt mit dem bereitgestellten Schlüssel zu initialisieren.
            self.fernet = Fernet(key)
        except ValueError as e:
            # Fängt ValueError ab, wenn der Schlüssel ungültig ist, und wirft eine benutzerdefinierte Ausnahme.
            raise EnvSecureCLIError(f"Ungültiger Schlüssel für die Verschlüsselung bereitgestellt: {e}")

    @staticmethod
    def generate_key() -> bytes:
        """Generiert einen neuen Fernet-Schlüssel.

        Returns:
            bytes: Ein neu generierter Fernet-Schlüssel.
        """
        # Erzeugt einen URL-sicheren Base64-kodierten Schlüssel.
        return Fernet.generate_key()

    def encrypt(self, data: str) -> bytes:
        """Verschlüsselt eine Zeichenkette.

        Args:
            data (str): Die zu verschlüsselnde Zeichenkette.

        Returns:
            bytes: Die verschlüsselten Daten als Bytes.
        """
        # Kodiert die Eingabezeichenkette in UTF-8 und verschlüsselt sie.
        return self.fernet.encrypt(data.encode('utf-8'))

    def decrypt(self, token: bytes) -> str:
        """Entschlüsselt einen Byte-Token.

        Args:
            token (bytes): Der zu entschlüsselnde Byte-Token.

        Returns:
            str: Die entschlüsselte Zeichenkette.

        Raises:
            EnvSecureCLIError: Wenn der Token ungültig ist oder die Entschlüsselung fehlschlägt.
        """
        try:
            # Entschlüsselt den Token und dekodiert das Ergebnis von Bytes in eine UTF-8-Zeichenkette.
            return self.fernet.decrypt(token).decode('utf-8')
        except InvalidToken:
            # Fängt InvalidToken ab, wenn der Schlüssel nicht mit dem Token übereinstimmt oder der Token manipuliert wurde.
            raise EnvSecureCLIError("Entschlüsselung fehlgeschlagen: Ungültiger Token oder falscher Schlüssel.")
        except Exception as e:
            # Fängt alle anderen unerwarteten Entschlüsselungsfehler ab.
            raise EnvSecureCLIError(f"Ein unerwarteter Fehler ist während der Entschlüsselung aufgetreten: {e}")

class EnvSecureCLI:
    """Hauptklasse für die CLI-Operationen zur Umgebungsverschlüsselung."""

    def __init__(self, key_source: Optional[str] = None, key_file_path: str = "env_key.txt"):
        """Initialisiert die CLI-Klasse und versucht, den Schlüssel zu laden.

        Args:
            key_source (Optional[str]): Die Quelle des Schlüssels ('env' für Umgebungsvariable, 'file' für Datei).
            key_file_path (str): Der Pfad zur Schlüsseldatei, falls 'key_source' auf 'file' gesetzt ist.
        """
        self.key_file_path = key_file_path
        self.cipher_handler: Optional[CipherHandler] = None
        if key_source:
            # Wenn eine Schlüsselquelle angegeben ist, versuchen wir, den Schlüssel zu laden.
            self._load_key(key_source)

    def _load_key(self, key_source: str) -> None:
        """Lädt den geheimen Schlüssel aus der angegebenen Quelle.

        Args:
            key_source (str): Die Quelle des Schlüssels ('env' für Umgebungsvariable, 'file' für Datei).

        Raises:
            EnvSecureCLIError: Wenn der Schlüssel nicht gefunden wird oder die Quelle ungültig ist.
        """
        key: Optional[bytes] = None
        if key_source == 'env':
            # Versucht, den Schlüssel aus der Umgebungsvariable 'SECRET_KEY' zu laden.
            env_key = os.getenv('SECRET_KEY')
            if env_key:
                key = env_key.encode('utf-8')
            else:
                # Fehler, wenn die Umgebungsvariable nicht gesetzt ist.
                raise EnvSecureCLIError("Umgebungsvariable 'SECRET_KEY' nicht gefunden.")
        elif key_source == 'file':
            # Versucht, den Schlüssel aus einer Datei zu laden.
            if os.path.exists(self.key_file_path):
                with open(self.key_file_path, 'rb') as f:
                    key = f.read().strip()
                if not key:
                    # Fehler, wenn die Schlüsseldatei leer ist.
                    raise EnvSecureCLIError(f"Schlüsseldatei '{self.key_file_path}' ist leer.")
            else:
                # Fehler, wenn die Schlüsseldatei nicht existiert.
                raise EnvSecureCLIError(f"Schlüsseldatei '{self.key_file_path}' nicht gefunden.")
        else:
            # Fehler bei einer unbekannten Schlüsselquelle.
            raise EnvSecureCLIError(f"Unbekannte Schlüsselquelle: {key_source}. Verwenden Sie 'env' oder 'file'.")

        if key:
            # Initialisiert den CipherHandler mit dem geladenen Schlüssel.
            self.cipher_handler = CipherHandler(key)

    def generate_key_and_save(self, output_path: Optional[str] = None, print_key: bool = False) -> Tuple[str, bytes]:
        """Generiert einen neuen Schlüssel und speichert ihn optional in einer Datei oder gibt ihn aus.

        Args:
            output_path (Optional[str]): Der Pfad, unter dem der Schlüssel gespeichert werden soll.
                                         Wenn None, wird er nicht gespeichert, es sei denn, print_key ist True.
            print_key (bool): Wenn True, wird der Schlüssel auf der Konsole ausgegeben.

        Returns:
            Tuple[str, bytes]: Ein Tupel, das den Pfad, wo der Schlüssel gespeichert wurde (oder 'stdout'),
                               und den generierten Schlüssel selbst enthält.
        """
        # Generiert einen neuen Schlüssel.
        key = CipherHandler.generate_key()
        key_str = key.decode('utf-8')
        
        save_location = "stdout"
        if output_path:
            # Speichert den Schlüssel in der angegebenen Datei.
            with open(output_path, 'wb') as f:
                f.write(key)
            save_location = output_path
            click.echo(f"Schlüssel erfolgreich gespeichert in: {output_path}")
        
        if print_key or not output_path:
            # Gibt den Schlüssel auf der Konsole aus, wenn angefordert oder wenn er nicht gespeichert wurde.
            click.echo(f"Neuer Schlüssel: {key_str}")
            if not output_path:
                click.echo("WARNUNG: Schlüssel wurde nicht in einer Datei gespeichert. Bitte notieren Sie ihn sicher!")
        
        return save_location, key

    def encrypt_value(self, value: str) -> str:
        """Verschlüsselt einen gegebenen Wert.

        Args:
            value (str): Der zu verschlüsselnde Wert.

        Returns:
            str: Der verschlüsselte Wert als Zeichenkette.

        Raises:
            EnvSecureCLIError: Wenn der CipherHandler nicht initialisiert ist (kein Schlüssel geladen).
        """
        if not self.cipher_handler:
            # Fehler, wenn kein CipherHandler vorhanden ist, d.h. kein Schlüssel geladen wurde.
            raise EnvSecureCLIError("Kein Verschlüsselungsschlüssel geladen. Bitte laden Sie einen Schlüssel mit --key-source.")
        # Verschlüsselt den Wert und dekodiert das Ergebnis für die Ausgabe.
        encrypted_value = self.cipher_handler.encrypt(value)
        return encrypted_value.decode('utf-8')

    def decrypt_value(self, encrypted_value: str) -> str:
        """Entschlüsselt einen gegebenen Wert.

        Args:
            encrypted_value (str): Der zu entschlüsselnde Wert (Base64-kodierte Bytes als Zeichenkette).

        Returns:
            str: Der entschlüsselte Wert als Zeichenkette.

        Raises:
            EnvSecureCLIError: Wenn der CipherHandler nicht initialisiert ist (kein Schlüssel geladen).
        """
        if not self.cipher_handler:
            # Fehler, wenn kein CipherHandler vorhanden ist.
            raise EnvSecureCLIError("Kein Entschlüsselungsschlüssel geladen. Bitte laden Sie einen Schlüssel mit --key-source.")
        # Kodiert den verschlüsselten Wert zurück in Bytes und entschlüsselt ihn.
        return self.cipher_handler.decrypt(encrypted_value.encode('utf-8'))

@click.group()
def cli():
    """Ein CLI-Dienstprogramm zum sicheren Verschlüsseln und Entschlüsseln von Umgebungsvariablen.

    Verwenden Sie 'env-secure-cli <command> --help' für weitere Informationen zu einem Befehl.
    """
    pass

@cli.command()
@click.option('--output-path', '-o', type=click.Path(), default=None,
              help='Optionaler Pfad zum Speichern des generierten Schlüssels. Standardmäßig wird er nicht gespeichert.')
@click.option('--print-key', '-p', is_flag=True, help='Gibt den generierten Schlüssel auf der Konsole aus.')
@click.option('--config', '-c', 'config_path', type=click.Path(), default=None,
              help='Pfad zu einer JSON-Konfigurationsdatei (Standard: .envsecure.json, falls vorhanden).')
def generate_key(output_path: Optional[str], print_key: bool, config_path: Optional[str]):
    """Generiert einen neuen Fernet-Verschlüsselungsschlüssel.

    Der Schlüssel kann optional in einer Datei gespeichert oder auf der Konsole ausgegeben werden.
    Der Standard-Ausgabepfad kann in der Konfigurationsdatei über 'output_path' gesetzt werden.
    SICHERHEITSHINWEIS: Speichern Sie diesen Schlüssel sicher! Er ist für die Verschlüsselung und Entschlüsselung unerlässlich.
    """
    try:
        # Konfiguration laden und den Ausgabepfad nach der Vorrangregel auflösen.
        config = load_config(config_path)
        output_path = resolve_setting(output_path, config, 'output_path',
                                      'ENVSECURE_OUTPUT', None)
        # Erstellt eine Instanz der EnvSecureCLI-Klasse, ohne sofort einen Schlüssel zu laden.
        cli_instance = EnvSecureCLI()
        cli_instance.generate_key_and_save(output_path, print_key)
    except EnvSecureCLIError as e:
        # Fängt benutzerdefinierte Fehler ab und gibt eine Fehlermeldung aus.
        click.echo(f"Fehler beim Generieren des Schlüssels: {e}", err=True)
        exit(1)

def _resolve_key_settings(key_source: Optional[str], key_file: Optional[str],
                          config_path: Optional[str]) -> Tuple[str, str]:
    """Lädt die Config und löst 'key_source'/'key_file' nach der Vorrangregel auf.

    Vorrang je Einstellung: CLI-Flag > Config-Datei > Umgebungsvariable > Default.
    Für 'key_source' wirkt ENVSECURE_KEY_SOURCE, für 'key_file' ENVSECURE_KEY_FILE.
    """
    config = load_config(config_path)
    key_source = resolve_setting(key_source, config, 'key_source',
                                 'ENVSECURE_KEY_SOURCE', 'env')
    key_file = resolve_setting(key_file, config, 'key_file',
                               'ENVSECURE_KEY_FILE', 'env_key.txt')
    if key_source not in ('env', 'file'):
        raise EnvSecureCLIError(
            f"Invalid key_source '{key_source}'. Use 'env' or 'file'."
        )
    return key_source, key_file

@cli.command()
@click.option('--value', '-v', required=True, help='Der Wert, der verschlüsselt werden soll.')
@click.option('--key-source', '-s', type=click.Choice(['env', 'file']), default=None,
              help='Quelle des Schlüssels: "env" für Umgebungsvariable SECRET_KEY, "file" für Schlüsseldatei.')
@click.option('--key-file', '-f', type=click.Path(), default=None,
              help='Pfad zur Schlüsseldatei, wenn --key-source auf "file" gesetzt ist.')
@click.option('--config', '-c', 'config_path', type=click.Path(), default=None,
              help='Pfad zu einer JSON-Konfigurationsdatei (Standard: .envsecure.json, falls vorhanden).')
def encrypt(value: str, key_source: Optional[str], key_file: Optional[str], config_path: Optional[str]):
    """Verschlüsselt einen gegebenen Wert mit dem bereitgestellten Schlüssel.

    Schlüsselquelle und -datei können per Flag, über eine JSON-Konfigurationsdatei
    oder über Umgebungsvariablen gesetzt werden (Vorrang: Flag > Config > Env > Default).
    """
    try:
        # Konfiguration laden und Einstellungen nach der Vorrangregel auflösen.
        key_source, key_file = _resolve_key_settings(key_source, key_file, config_path)
        # Initialisiert EnvSecureCLI und lädt den Schlüssel basierend auf den aufgelösten Optionen.
        cli_instance = EnvSecureCLI(key_source=key_source, key_file_path=key_file)
        encrypted_value = cli_instance.encrypt_value(value)
        click.echo(f"Verschlüsselter Wert: {encrypted_value}")
    except EnvSecureCLIError as e:
        # Fängt benutzerdefinierte Fehler ab und gibt eine Fehlermeldung aus.
        click.echo(f"Fehler beim Verschlüsseln: {e}", err=True)
        exit(1)

@cli.command()
@click.option('--value', '-v', required=True, help='Der Wert, der entschlüsselt werden soll.')
@click.option('--key-source', '-s', type=click.Choice(['env', 'file']), default=None,
              help='Quelle des Schlüssels: "env" für Umgebungsvariable SECRET_KEY, "file" für Schlüsseldatei.')
@click.option('--key-file', '-f', type=click.Path(), default=None,
              help='Pfad zur Schlüsseldatei, wenn --key-source auf "file" gesetzt ist.')
@click.option('--config', '-c', 'config_path', type=click.Path(), default=None,
              help='Pfad zu einer JSON-Konfigurationsdatei (Standard: .envsecure.json, falls vorhanden).')
def decrypt(value: str, key_source: Optional[str], key_file: Optional[str], config_path: Optional[str]):
    """Entschlüsselt einen gegebenen Wert mit dem bereitgestellten Schlüssel.

    Schlüsselquelle und -datei können per Flag, über eine JSON-Konfigurationsdatei
    oder über Umgebungsvariablen gesetzt werden (Vorrang: Flag > Config > Env > Default).
    """
    try:
        # Konfiguration laden und Einstellungen nach der Vorrangregel auflösen.
        key_source, key_file = _resolve_key_settings(key_source, key_file, config_path)
        # Initialisiert EnvSecureCLI und lädt den Schlüssel basierend auf den aufgelösten Optionen.
        cli_instance = EnvSecureCLI(key_source=key_source, key_file_path=key_file)
        decrypted_value = cli_instance.decrypt_value(value)
        click.echo(f"Entschlüsselter Wert: {decrypted_value}")
    except EnvSecureCLIError as e:
        # Fängt benutzerdefinierte Fehler ab und gibt eine Fehlermeldung aus.
        click.echo(f"Fehler beim Entschlüsseln: {e}", err=True)
        exit(1)

if __name__ == '__main__':
    # Der Einstiegspunkt für die CLI-Anwendung.
    cli()
