# Contributing to EnvSecure CLI

We welcome contributions to EnvSecure CLI! By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md) (not implemented yet, but good practice).

## How to Contribute

There are several ways to contribute to EnvSecure CLI:

*   **Report Bugs**: If you find a bug, please open an issue on GitHub.
*   **Suggest Features**: Have an idea for a new feature or improvement? Open an issue to discuss it.
*   **Submit Code**: Implement new features, fix bugs, or improve documentation by submitting a Pull Request.

## Reporting Bugs

Before opening a new bug report, please check the existing issues to see if your bug has already been reported. When reporting a bug, please include:

*   A clear and concise description of the bug.
*   Steps to reproduce the behavior.
*   Expected behavior.
*   Actual behavior.
*   Your operating system and Python version.
*   Any relevant error messages or stack traces.

## Suggesting Features

When suggesting a new feature, please describe:

*   The problem you're trying to solve.
*   How the new feature would address this problem.
*   Any alternative solutions you've considered.

## Code Contributions

If you'd like to contribute code, please follow these steps:

1.  **Fork the repository** and clone it to your local machine.
2.  **Create a new branch** for your feature or bug fix:
    ```bash
    git checkout -b feature/your-feature-name
    # or
    git checkout -b bugfix/your-bug-fix
    ```
3.  **Set up your development environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    pip install flake8 pytest # Install dev dependencies
    ```
4.  **Make your changes**. Ensure your code adheres to the project's coding style (PEP 8).
5.  **Write unit tests** for your changes. All new features and bug fixes should have corresponding tests.
    ```bash
    python -m unittest discover
    ```
6.  **Run linters** (e.g., `flake8`) to ensure code quality.
    ```bash
    flake8 .
    ```
7.  **Update documentation** if your changes introduce new features or modify existing behavior.
8.  **Commit your changes** with a clear and descriptive commit message. Referencing the issue number (e.g., `Fix #123: ...`) is helpful.
9.  **Push your branch** to your forked repository.
10. **Open a Pull Request** against the `main` branch of the upstream repository. Please provide a clear description of your changes and why they are necessary.

## Code Style

*   Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code style.
*   Use type hints for function signatures.
*   Include clear docstrings for all classes, methods, and functions.
*   Inline comments should be in German as per the project's bilingual requirement.

## Licensing

By contributing to EnvSecure CLI, you agree that your contributions will be licensed under the MIT License. Please see the `LICENSE` file for details.

Thank you for contributing to EnvSecure CLI!