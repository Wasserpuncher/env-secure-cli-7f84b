import unittest
import os
import json
import tempfile
from unittest.mock import patch, mock_open
from click.testing import CliRunner
from main import (
    EnvSecureCLI, CipherHandler, EnvSecureCLIError,
    cli, load_config, resolve_setting,
)
from cryptography.fernet import Fernet

class TestCipherHandler(unittest.TestCase):
    """Testfälle für die CipherHandler-Klasse."""

    def setUp(self):
        """Wird vor jedem Testfall ausgeführt, um eine saubere Testumgebung zu schaffen."""
        # Generiert einen gültigen Fernet-Schlüssel für die Tests.
        self.valid_key = Fernet.generate_key()
        self.cipher_handler = CipherHandler(self.valid_key)
        # Eine Test-Nachricht.
        self.test_message = "Dies ist eine geheime Nachricht."

    def test_generate_key(self):
        """Testet, ob generate_key einen gültigen Fernet-Schlüssel erzeugt."""
        # Überprüft, ob der generierte Schlüssel gültig ist, indem versucht wird, ein Fernet-Objekt damit zu initialisieren.
        key = CipherHandler.generate_key()
        self.assertIsInstance(key, bytes)
        self.assertGreater(len(key), 0)
        # Ein ungültiger Schlüssel würde einen ValueError beim Initialisieren von Fernet auslösen.
        Fernet(key)

    def test_encrypt_decrypt_success(self):
        """Testet den erfolgreichen Verschlüsselungs- und Entschlüsselungsprozess."""
        # Verschlüsselt die Testnachricht.
        encrypted_token = self.cipher_handler.encrypt(self.test_message)
        self.assertIsInstance(encrypted_token, bytes)
        self.assertNotEqual(encrypted_token.decode('utf-8'), self.test_message)

        # Entschlüsselt den Token und überprüft, ob er mit der ursprünglichen Nachricht übereinstimmt.
        decrypted_message = self.cipher_handler.decrypt(encrypted_token)
        self.assertEqual(decrypted_message, self.test_message)

    def test_decrypt_invalid_token(self):
        """Testet die Entschlüsselung mit einem ungültigen Token."""
        # Ein manipulierter oder ungültiger Token sollte EnvSecureCLIError auslösen.
        invalid_token = b"invalid_token_data"
        with self.assertRaises(EnvSecureCLIError) as cm:
            self.cipher_handler.decrypt(invalid_token)
        self.assertIn("Ungültiger Token oder falscher Schlüssel", str(cm.exception))

    def test_cipher_handler_invalid_key_init(self):
        """Testet die Initialisierung von CipherHandler mit einem ungültigen Schlüssel."""
        # Ein ungültiger Schlüssel sollte EnvSecureCLIError beim Initialisieren des Handlers auslösen.
        with self.assertRaises(EnvSecureCLIError) as cm:
            CipherHandler(b"short_invalid_key")
        self.assertIn("Ungültiger Schlüssel für die Verschlüsselung bereitgestellt", str(cm.exception))

class TestEnvSecureCLI(unittest.TestCase):
    """Testfälle für die EnvSecureCLI-Klasse."""

    def setUp(self):
        """Setzt die Umgebung für jeden Test zurück."""
        # Generiert einen Fernet-Schlüssel für die Tests.
        self.test_key = Fernet.generate_key()
        self.test_key_str = self.test_key.decode('utf-8')
        self.test_message = "sensitive_data_123"
        # Erstellt eine temporäre Datei für Schlüssel.
        self.temp_key_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_key_file.write(self.test_key)
        self.temp_key_file.close()

    def tearDown(self):
        """Bereinigt nach jedem Test."""
        # Entfernt die temporäre Schlüsseldatei.
        os.remove(self.temp_key_file.name)
        # Stellt sicher, dass die Umgebungsvariable gelöscht wird.
        if 'SECRET_KEY' in os.environ:
            del os.environ['SECRET_KEY']

    def test_load_key_from_env_success(self):
        """Testet das erfolgreiche Laden des Schlüssels aus einer Umgebungsvariable."""
        # Setzt die Umgebungsvariable für den Test.
        os.environ['SECRET_KEY'] = self.test_key_str
        cli = EnvSecureCLI(key_source='env')
        self.assertIsNotNone(cli.cipher_handler)

    def test_load_key_from_env_not_found(self):
        """Testet den Fehlerfall, wenn die Umgebungsvariable nicht gefunden wird."""
        # Stellt sicher, dass die Umgebungsvariable nicht gesetzt ist.
        if 'SECRET_KEY' in os.environ:
            del os.environ['SECRET_KEY']
        with self.assertRaises(EnvSecureCLIError) as cm:
            EnvSecureCLI(key_source='env')
        self.assertIn("Umgebungsvariable 'SECRET_KEY' nicht gefunden.", str(cm.exception))

    def test_load_key_from_file_success(self):
        """Testet das erfolgreiche Laden des Schlüssels aus einer Datei."""
        cli = EnvSecureCLI(key_source='file', key_file_path=self.temp_key_file.name)
        self.assertIsNotNone(cli.cipher_handler)

    def test_load_key_from_file_not_found(self):
        """Testet den Fehlerfall, wenn die Schlüsseldatei nicht gefunden wird."""
        # Verwendet einen nicht existierenden Dateipfad.
        with self.assertRaises(EnvSecureCLIError) as cm:
            EnvSecureCLI(key_source='file', key_file_path="non_existent_key_file.txt")
        self.assertIn("Schlüsseldatei 'non_existent_key_file.txt' nicht gefunden.", str(cm.exception))

    def test_load_key_from_file_empty(self):
        """Testet den Fehlerfall, wenn die Schlüsseldatei leer ist."""
        # Erstellt eine leere temporäre Datei.
        empty_key_file = tempfile.NamedTemporaryFile(delete=False)
        empty_key_file.close()
        with self.assertRaises(EnvSecureCLIError) as cm:
            EnvSecureCLI(key_source='file', key_file_path=empty_key_file.name)
        self.assertIn(f"Schlüsseldatei '{empty_key_file.name}' ist leer.", str(cm.exception))
        os.remove(empty_key_file.name)

    def test_encrypt_decrypt_flow(self):
        """Testet den vollständigen Verschlüsselungs- und Entschlüsselungsfluss."""
        os.environ['SECRET_KEY'] = self.test_key_str
        cli = EnvSecureCLI(key_source='env')

        encrypted = cli.encrypt_value(self.test_message)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, self.test_message)

        decrypted = cli.decrypt_value(encrypted)
        self.assertEqual(decrypted, self.test_message)

    def test_encrypt_without_key_loaded(self):
        """Testet den Versuch der Verschlüsselung ohne geladenen Schlüssel."""
        cli = EnvSecureCLI() # Keine Schlüsselquelle angegeben
        with self.assertRaises(EnvSecureCLIError) as cm:
            cli.encrypt_value(self.test_message)
        self.assertIn("Kein Verschlüsselungsschlüssel geladen", str(cm.exception))

    def test_decrypt_without_key_loaded(self):
        """Testet den Versuch der Entschlüsselung ohne geladenen Schlüssel."""
        cli = EnvSecureCLI() # Keine Schlüsselquelle angegeben
        with self.assertRaises(EnvSecureCLIError) as cm:
            cli.decrypt_value("some_encrypted_value")
        self.assertIn("Kein Entschlüsselungsschlüssel geladen", str(cm.exception))

    @patch('main.click.echo')
    def test_generate_key_and_save_to_file(self, mock_echo):
        """Testet die Schlüsselerzeugung und das Speichern in einer Datei."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            output_path = tmp_file.name
        
        cli = EnvSecureCLI()
        save_location, generated_key = cli.generate_key_and_save(output_path=output_path, print_key=False)
        
        self.assertEqual(save_location, output_path)
        self.assertIsInstance(generated_key, bytes)
        self.assertTrue(os.path.exists(output_path))
        
        with open(output_path, 'rb') as f:
            saved_key = f.read()
        self.assertEqual(saved_key, generated_key)
        # Überprüft, ob die Erfolgsmeldung ausgegeben wurde.
        mock_echo.assert_any_call(f"Schlüssel erfolgreich gespeichert in: {output_path}")
        os.remove(output_path)

    @patch('main.click.echo')
    def test_generate_key_and_print_to_stdout(self, mock_echo):
        """Testet die Schlüsselerzeugung und die Ausgabe auf stdout."""
        cli = EnvSecureCLI()
        save_location, generated_key = cli.generate_key_and_save(output_path=None, print_key=True)
        
        self.assertEqual(save_location, "stdout")
        self.assertIsInstance(generated_key, bytes)
        # Überprüft, ob der Schlüssel auf der Konsole ausgegeben wurde.
        mock_echo.assert_any_call(f"Neuer Schlüssel: {generated_key.decode('utf-8')}")

    @patch('main.click.echo')
    def test_generate_key_no_save_no_print(self, mock_echo):
        """Testet die Schlüsselerzeugung ohne Speichern und ohne Ausgabe, sollte auf stdout ausgeben."""
        cli = EnvSecureCLI()
        save_location, generated_key = cli.generate_key_and_save(output_path=None, print_key=False)
        
        self.assertEqual(save_location, "stdout")
        self.assertIsInstance(generated_key, bytes)
        # Wenn kein Speicherpfad und kein --print-key angegeben ist, sollte der Schlüssel trotzdem auf stdout ausgegeben werden.
        mock_echo.assert_any_call(f"Neuer Schlüssel: {generated_key.decode('utf-8')}")
        mock_echo.assert_any_call("WARNUNG: Schlüssel wurde nicht in einer Datei gespeichert. Bitte notieren Sie ihn sicher!")


class TestLoadConfig(unittest.TestCase):
    """Testfälle für das Laden der JSON-Konfigurationsdatei."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return path

    def test_load_config_reads_json_object(self):
        """Eine gültige JSON-Config wird als Dictionary geladen."""
        path = self._write('cfg.json', json.dumps({"key_source": "file", "key_file": "k.key"}))
        config = load_config(path)
        self.assertEqual(config, {"key_source": "file", "key_file": "k.key"})

    def test_load_config_missing_explicit_raises(self):
        """Eine explizit angeforderte, fehlende Config ist ein Fehler."""
        with self.assertRaises(EnvSecureCLIError) as cm:
            load_config(os.path.join(self.tmp, "does_not_exist.json"))
        self.assertIn("not found", str(cm.exception))

    def test_load_config_invalid_json_raises(self):
        """Ungültiges JSON löst einen Fehler aus."""
        path = self._write('bad.json', "{not valid json}")
        with self.assertRaises(EnvSecureCLIError) as cm:
            load_config(path)
        self.assertIn("Could not read configuration file", str(cm.exception))

    def test_load_config_non_object_raises(self):
        """Eine JSON-Datei, die kein Objekt ist, wird abgelehnt."""
        path = self._write('list.json', json.dumps([1, 2, 3]))
        with self.assertRaises(EnvSecureCLIError) as cm:
            load_config(path)
        self.assertIn("must contain a JSON object", str(cm.exception))

    def test_load_config_rejects_raw_secret(self):
        """Ein roher Schlüssel in der Config wird aus Sicherheitsgründen abgelehnt."""
        path = self._write('secret.json', json.dumps({"secret_key": "leaked"}))
        with self.assertRaises(EnvSecureCLIError) as cm:
            load_config(path)
        self.assertIn("must not contain a raw secret key", str(cm.exception))

    def test_default_config_absent_returns_empty(self):
        """Fehlt die implizite Standarddatei, wird eine leere Config geliefert."""
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)  # Verzeichnis ohne .envsecure.json
            self.assertEqual(load_config(None), {})
        finally:
            os.chdir(cwd)


class TestResolveSetting(unittest.TestCase):
    """Testfälle für die Vorrangregel: CLI > Config > Env > Default."""

    def setUp(self):
        self._saved = os.environ.pop('ENVSECURE_TEST_VAR', None)

    def tearDown(self):
        if self._saved is not None:
            os.environ['ENVSECURE_TEST_VAR'] = self._saved
        else:
            os.environ.pop('ENVSECURE_TEST_VAR', None)

    def test_cli_flag_wins(self):
        os.environ['ENVSECURE_TEST_VAR'] = 'env'
        result = resolve_setting('cli', {'k': 'cfg'}, 'k', 'ENVSECURE_TEST_VAR', 'def')
        self.assertEqual(result, 'cli')

    def test_config_beats_env_and_default(self):
        os.environ['ENVSECURE_TEST_VAR'] = 'env'
        result = resolve_setting(None, {'k': 'cfg'}, 'k', 'ENVSECURE_TEST_VAR', 'def')
        self.assertEqual(result, 'cfg')

    def test_env_beats_default(self):
        os.environ['ENVSECURE_TEST_VAR'] = 'env'
        result = resolve_setting(None, {}, 'k', 'ENVSECURE_TEST_VAR', 'def')
        self.assertEqual(result, 'env')

    def test_default_when_nothing_set(self):
        os.environ.pop('ENVSECURE_TEST_VAR', None)
        result = resolve_setting(None, {}, 'k', 'ENVSECURE_TEST_VAR', 'def')
        self.assertEqual(result, 'def')


class TestConfigCLIIntegration(unittest.TestCase):
    """End-to-End-Tests, die das Config-Laden über den CLI-Aufruf prüfen."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.mkdtemp()
        # Gültigen Fernet-Schlüssel in eine Schlüsseldatei schreiben.
        self.key = Fernet.generate_key()
        self.key_file = os.path.join(self.tmp, 'my.key')
        with open(self.key_file, 'wb') as f:
            f.write(self.key)
        # Sicherstellen, dass keine störenden Umgebungsvariablen gesetzt sind.
        for var in ('SECRET_KEY', 'ENVSECURE_KEY_SOURCE', 'ENVSECURE_KEY_FILE', 'ENVSECURE_CONFIG'):
            os.environ.pop(var, None)

    def _write_config(self, data):
        path = os.path.join(self.tmp, 'cfg.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        return path

    def test_encrypt_uses_config_key_source_and_file(self):
        """encrypt liest key_source und key_file aus der Config."""
        cfg = self._write_config({"key_source": "file", "key_file": self.key_file})
        result = self.runner.invoke(cli, ['encrypt', '-v', 'hello', '-c', cfg])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Verschlüsselter Wert:", result.output)

    def test_config_roundtrip_encrypt_then_decrypt(self):
        """Mit Config verschlüsselter Wert lässt sich mit Config wieder entschlüsseln."""
        cfg = self._write_config({"key_source": "file", "key_file": self.key_file})
        enc = self.runner.invoke(cli, ['encrypt', '-v', 'roundtrip', '-c', cfg])
        self.assertEqual(enc.exit_code, 0, enc.output)
        token = enc.output.split("Verschlüsselter Wert:", 1)[1].strip()
        dec = self.runner.invoke(cli, ['decrypt', '-v', token, '-c', cfg])
        self.assertEqual(dec.exit_code, 0, dec.output)
        self.assertIn("Entschlüsselter Wert: roundtrip", dec.output)

    def test_cli_flag_overrides_config(self):
        """Ein CLI-Flag hat Vorrang vor der Config (Config zeigt auf falsche Datei)."""
        wrong = os.path.join(self.tmp, 'wrong.key')
        with open(wrong, 'wb') as f:
            f.write(Fernet.generate_key())
        cfg = self._write_config({"key_source": "file", "key_file": wrong})
        # Config sagt 'wrong.key', CLI-Flag zeigt auf die korrekte Datei -> Flag gewinnt.
        result = self.runner.invoke(
            cli, ['encrypt', '-v', 'hi', '-c', cfg, '-f', self.key_file]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Verschlüsselter Wert:", result.output)

    def test_config_env_var_locates_config(self):
        """ENVSECURE_CONFIG kann die Config-Datei bereitstellen (ohne --config)."""
        cfg = self._write_config({"key_source": "file", "key_file": self.key_file})
        try:
            os.environ['ENVSECURE_CONFIG'] = cfg
            result = self.runner.invoke(cli, ['encrypt', '-v', 'viaenv'])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Verschlüsselter Wert:", result.output)
        finally:
            os.environ.pop('ENVSECURE_CONFIG', None)

    def test_missing_explicit_config_errors(self):
        """Ein explizit angeforderter, fehlender Config-Pfad führt zu Exit-Code 1."""
        result = self.runner.invoke(
            cli, ['encrypt', '-v', 'x', '-c', os.path.join(self.tmp, 'nope.json')]
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not found", result.output)


if __name__ == '__main__':
    unittest.main()
