# EnvSecure CLI

[![Python application](https://github.com/your-org/env-secure-cli/actions/workflows/python-app.yml/badge.svg)](https://github.com/your-org/env-secure-cli/actions/workflows/python-app.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful and secure command-line utility for encrypting and decrypting environment variables. Designed for developers and operations teams, EnvSecure CLI helps you manage sensitive configuration data safely, preventing accidental exposure in source control or insecure environments.

## Features

*   **Secure Encryption**: Utilizes `cryptography.fernet` for robust, symmetric encryption.
*   **Flexible Key Management**: Load encryption keys from environment variables (recommended for production) or local files.
*   **CLI Interface**: Easy-to-use command-line interface powered by `click`.
*   **Key Generation**: Generate new Fernet encryption keys directly from the CLI.
*   **Bilingual Documentation**: Comprehensive documentation available in both English and German.
*   **Enterprise-Ready**: Built with best practices, including type hints, docstrings, and unit tests.

## Table of Contents

*   [Installation](#installation)
*   [Quick Start](#quick-start)
*   [Key Management](#key-management)
    *   [Generating a New Key](#generating-a-new-key)
    *   [Loading Key from Environment Variable (Recommended)](#loading-key-from-environment-variable-recommended)
    *   [Loading Key from File](#loading-key-from-file)
*   [Usage](#usage)
    *   [Encrypting a Value](#encrypting-a-value)
    *   [Decrypting a Value](#decrypting-a-value)
*   [Contributing](#contributing)
*   [License](#license)
*   [Architecture](#architecture)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-org/env-secure-cli.git
    cd env-secure-cli
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Quick Start

### 1. Generate a Key

First, generate a secure encryption key. **Keep this key safe and secret!**

```bash
python main.py generate-key --output-path env_key.txt
# Or to print to console only (use with caution):
# python main.py generate-key --print-key
```

### 2. Set the Key (e.g., as Environment Variable)

For production, it's highly recommended to use an environment variable.

```bash
export SECRET_KEY="$(cat env_key.txt)" # On Linux/macOS
# For Windows PowerShell:
# $env:SECRET_KEY = (Get-Content -Raw env_key.txt)
```

### 3. Encrypt a Value

```bash
python main.py encrypt --value "my_secret_api_key_123" --key-source env
# Output: Verschlüsselter Wert: gAAAAABh... (your encrypted string)
```

### 4. Decrypt a Value

```bash
python main.py decrypt --value "gAAAAABh..." --key-source env
# Output: Entschlüsselter Wert: my_secret_api_key_123
```

## Key Management

EnvSecure CLI supports two primary methods for providing the encryption key:

### Generating a New Key

```bash
python main.py generate-key [--output-path <path_to_file>] [--print-key]
```
*   `--output-path`: Saves the generated key to the specified file. E.g., `env_key.txt`.
*   `--print-key`: Prints the generated key to standard output. **Be cautious when using this in production environments as keys can be logged.**

If neither `--output-path` nor `--print-key` is provided, the key will be printed to stdout with a warning.

### Loading Key from Environment Variable (Recommended)

For production deployments, storing the encryption key in an environment variable (`SECRET_KEY`) is the most secure and recommended method. This prevents the key from being committed to source control or residing on the filesystem.

```bash
export SECRET_KEY="your_fernet_key_here" # Linux/macOS
# $env:SECRET_KEY = "your_fernet_key_here" # Windows PowerShell

python main.py encrypt -v "my_db_password" -s env
python main.py decrypt -v "gAAAAAB..." -s env
```

### Loading Key from File

For local development or specific use cases, you can store the key in a file (e.g., `env_key.txt`). **Ensure this file is excluded from version control (e.g., via `.gitignore`) and secured appropriately.**

```bash
python main.py encrypt -v "my_db_password" -s file -f env_key.txt
python main.py decrypt -v "gAAAAAB..." -s file -f env_key.txt
```
*   `--key-file` (`-f`): Specifies the path to the key file. Defaults to `env_key.txt`.

## Usage

### Encrypting a Value

```bash
python main.py encrypt --value "<YOUR_VALUE_TO_ENCRYPT>" --key-source <env|file> [--key-file <path_to_key_file>]
```

**Example (using environment variable):**
```bash
export SECRET_KEY="$(python main.py generate-key --print-key)"
python main.py encrypt -v "super_secret_token" -s env
# Output: Verschlüsselter Wert: gAAAAABh...Cg==
```

### Decrypting a Value

```bash
python main.py decrypt --value "<YOUR_ENCRYPTED_VALUE>" --key-source <env|file> [--key-file <path_to_key_file>]
```

**Example (using file):**
```bash
python main.py generate-key -o my_app_key.txt
python main.py encrypt -v "db_user_password" -s file -f my_app_key.txt
# (Copy the encrypted value)
python main.py decrypt -v "gAAAAABi...YQ==" -s file -f my_app_key.txt
# Output: Entschlüsselter Wert: db_user_password
```

## Contributing

We welcome contributions! Please see `CONTRIBUTING.md` for guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Architecture

For a detailed understanding of the project's architecture and design decisions, please refer to `docs/architecture_en.md`.