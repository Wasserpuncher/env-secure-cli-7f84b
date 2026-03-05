import unittest
import os
import tempfile
from unittest.mock import patch, mock_open
from main import EnvSecureCLI, CipherHandler, EnvSecureCLIError
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


if __name__ == '__main__':
    unittest.main()
