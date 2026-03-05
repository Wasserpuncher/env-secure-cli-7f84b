# EnvSecure CLI Architecture

This document outlines the architectural design and key components of the EnvSecure CLI utility. The primary goal is to provide a secure, reliable, and user-friendly tool for managing sensitive environment variables through encryption and decryption.

## Design Principles

1.  **Security First**: Encryption is handled by the `cryptography` library, specifically `Fernet`, which ensures strong, symmetric encryption. Key management is paramount, with strong recommendations for environment variables in production.
2.  **Modularity**: The codebase is organized into distinct classes, separating concerns like cryptographic operations from CLI parsing and key loading.
3.  **Usability**: A clear and intuitive command-line interface, powered by `click`, makes the tool easy to learn and use.
4.  **Extensibility**: The modular design allows for future enhancements, such as support for different encryption algorithms, key rotation, or integration with secret management services, without extensive refactoring.
5.  **Testability**: Each component is designed to be independently testable, facilitating robust unit and integration testing.

## Core Components

The EnvSecure CLI is built around two main classes and a `click` command-line interface structure.

### 1. `EnvSecureCLIError` (Custom Exception)

*   **Purpose**: A custom exception class derived from `Exception` to provide specific error handling for CLI-related issues. This allows for clearer error messages and more robust error flows within the application.

### 2. `CipherHandler` Class

*   **Location**: `main.py`
*   **Responsibility**: This class is the direct interface to the `cryptography.fernet` library. It abstracts away the low-level details of encryption and decryption.
*   **Key Methods**:
    *   `__init__(self, key: bytes)`: Initializes the handler with a given Fernet key. It performs basic validation of the key format.
    *   `generate_key() -> bytes`: A static method to create a new, URL-safe Base64-encoded Fernet key.
    *   `encrypt(self, data: str) -> bytes`: Takes a string, encodes it to UTF-8, and encrypts it using the initialized Fernet key.
    *   `decrypt(self, token: bytes) -> str`: Takes a byte token (encrypted data), decrypts it, and decodes it back to a UTF-8 string. It includes error handling for `InvalidToken` (e.g., wrong key, tampered token).
*   **Security Aspect**: By encapsulating `Fernet` operations, `CipherHandler` ensures that encryption/decryption is always performed correctly and consistently using the recommended `Fernet` primitive.

### 3. `EnvSecureCLI` Class

*   **Location**: `main.py`
*   **Responsibility**: This is the main business logic class that orchestrates key loading, manages the `CipherHandler` instance, and provides high-level methods for encryption and decryption that are called by the CLI commands.
*   **Key Methods**:
    *   `__init__(self, key_source: Optional[str] = None, key_file_path: str = "env_key.txt")`: Initializes the CLI instance. It can optionally load a key immediately based on `key_source`.
    *   `_load_key(self, key_source: str) -> None`: A private helper method responsible for retrieving the encryption key. It supports loading from:
        *   **Environment Variable (`SECRET_KEY`)**: Recommended for production environments to avoid keys on disk.
        *   **Local File (`env_key.txt` by default)**: Useful for development or specific isolated deployments. Includes checks for file existence and content.
    *   `generate_key_and_save(self, output_path: Optional[str] = None, print_key: bool = False) -> Tuple[str, bytes]`: Generates a new key and handles saving it to a specified file or printing it to stdout. It provides warnings if the key is not saved.
    *   `encrypt_value(self, value: str) -> str`: High-level method to encrypt a given string value using the loaded `CipherHandler`.
    *   `decrypt_value(self, encrypted_value: str) -> str`: High-level method to decrypt a given encrypted string value using the loaded `CipherHandler`.
*   **Error Handling**: Methods in `EnvSecureCLI` raise `EnvSecureCLIError` for issues like missing keys or invalid key sources, which are then caught by the `click` command handlers.

### 4. `click` CLI Application

*   **Location**: `main.py` (decorators and command functions)
*   **Responsibility**: Defines the command-line interface using the `click` library. It handles argument parsing, option validation, and dispatching to the `EnvSecureCLI` class methods.
*   **Commands**:
    *   `cli()`: The main group command.
    *   `generate-key`: Command to generate a new Fernet key. Options include `--output-path` (to save to file) and `--print-key` (to print to console).
    *   `encrypt`: Command to encrypt a value. Options include `--value`, `--key-source` (`env` or `file`), and `--key-file` (if `key_source` is `file`).
    *   `decrypt`: Command to decrypt a value. Options are similar to `encrypt`.
*   **User Interaction**: Provides user feedback via `click.echo` for success messages, warnings, and error messages.

## Key Management Strategy

Secure key management is crucial for the integrity of the encrypted data. EnvSecure CLI supports two primary methods, each with its recommended use case:

1.  **Environment Variable (`SECRET_KEY`)**: This is the **recommended method for production environments**. Storing the key in an environment variable prevents it from being persisted on disk (where it could be accidentally committed to version control or accessed by unauthorized processes). It relies on the environment where the application runs (e.g., CI/CD pipelines, container orchestration, cloud secret managers) to securely inject this variable.
2.  **Local File (`env_key.txt` by default)**: This method is suitable for **local development or non-critical, isolated deployments**. The key is read from a specified file. **Crucially, any key file must be excluded from version control (e.g., via `.gitignore`) and protected with appropriate file system permissions.**

## Security Considerations

*   **Key Secrecy**: The Fernet key is the single point of failure. If the key is compromised, all encrypted data can be decrypted. Always treat the key as highly sensitive.
*   **Key Storage**: Avoid hardcoding keys in source code. Environment variables are preferred over files for production.
*   **`generate-key` Output**: The `--print-key` option should be used with extreme caution in production, as it can expose the key in logs or terminal history. Prefer `--output-path` and then securely transfer the key to an environment variable.
*   **`cryptography` Library**: The project relies on `cryptography.fernet`, which is a high-level symmetric encryption primitive designed for ease of use and security, built on strong underlying algorithms (AES in CBC mode with HMAC).
*   **No Key Rotation**: The current version does not support automatic key rotation. Implementing key rotation would require a more complex key management system (e.g., storing multiple keys, versioning encrypted data), which is beyond the scope of a basic CLI utility but could be a future enhancement.

## Future Enhancements

*   **Configuration File**: Implement support for a `config.json` or `YAML` file to manage multiple keys, different encryption contexts, or default settings for `key_file_path`.
*   **Key Rotation**: Introduce mechanisms for rotating encryption keys and re-encrypting data.
*   **Integration with Cloud Secret Managers**: Add support for fetching keys directly from services like AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.
*   **Non-interactive Mode**: Allow encryption/decryption of multiple values from a file or stdin.
*   **Pre-commit Hooks**: Add pre-commit hooks for linting, formatting, and basic security checks.