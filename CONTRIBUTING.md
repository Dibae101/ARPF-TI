# Contributing to ARPF-TI

Thank you for your interest in contributing to ARPF-TI! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in the Issues section
- Use the bug report template when creating a new issue
- Include detailed steps to reproduce the bug
- Describe the expected behavior and what actually happened
- Include screenshots if applicable

### Suggesting Features

- Check if the feature has already been suggested in the Issues section
- Use the feature request template when creating a new issue
- Clearly describe the feature and its benefits
- Provide examples of how the feature would be used

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests to ensure they pass
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin feature/your-feature-name`)
7. Open a Pull Request

## Development Setup

1. Clone your fork of the repository
2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development dependencies
   ```
4. Set up pre-commit hooks:
   ```
   pre-commit install
   ```

## Coding Standards

- Follow PEP 8 style guide for Python code
- Write docstrings for all functions, classes, and modules
- Include type hints where appropriate
- Write unit tests for new features and bug fixes
- Keep functions and methods small and focused on a single task

## Git Workflow

- Use descriptive commit messages
- Reference issue numbers in commit messages and PR descriptions
- Keep PRs focused on a single feature or bug fix
- Rebase your branch before submitting a PR

## Testing

- Write unit tests for all new features and bug fixes
- Ensure all tests pass before submitting a PR
- Include both positive and negative test cases

Thank you for contributing to ARPF-TI!