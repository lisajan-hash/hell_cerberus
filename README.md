# hell_cerberus

**hell_cerberus** is a tool designed to help analyze binary executable files and identify suspicious elements.

## Usage

1. Make sure `checker.sh` is executable:
    ```bash
    chmod +x checker.sh
    ```

2. Run the script with the target binary as an argument:
    ```bash
    ./checked.sh "command which need to executed"  /path/tologs
    ```

3. Review the output for any suspicious findings.

## Features

- Analyzes binary executables using strace
- Highlights potentially suspicious characteristics
