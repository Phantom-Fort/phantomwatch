# PhantomWatch

## Overview

PhantomWatch is a powerful security automation tool designed to streamline security operations, incident response, and threat intelligence analysis. It provides a modular approach, allowing cybersecurity professionals to integrate various tools and automate security workflows.

## Features

- **Modular Architecture**: Supports multiple security modules such as Incident Response, SIEM Correlation, Sigma Rules, Threat Intelligence, and YARA Scanning.
- **Database Integration**: Uses SQLite for storing configurations, logs, and results.
- **Configuration Management**: Utilizes `config.json` and `.env` for easy customization.
- **Command-Line Interface (CLI)**: Provides an interactive and easy-to-use interface for executing security commands.
- **Automated Installation**: Comes with an `install.sh` script for seamless setup.

## Installation

### Prerequisites

Ensure your system has the following installed:

- Python 3
- pip (Python package manager)
- SQLite3

### Steps

1. Clone the repository:

   ```sh
   git clone https://github.com/your-repo/phantomwatch.git
   cd phantomwatch
   ```

2. Run the installation script:

   ```sh
   chmod +x install.sh
   ./install.sh
   ```

3. Verify installation:

   ```sh
   phantomwatch --help
   ```

## Usage

### Listing Available Modules

```sh
phantomwatch list-modules
```

### Running a Module

```sh
phantomwatch run -m incident-response
```

### Viewing Help

```sh
phantomwatch --help
```

## Configuration

Modify `config/config.json` for custom settings. Sensitive credentials should be stored in `config/secrets.env`.

Example `config.json`:

```json
{
    "log_level": "info",
    "database_path": "database/phantomwatch.db"
}
```

Example `.env`:

```ini
API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here
```

## Contributing

1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them.
4. Push your changes and submit a pull request.

## License

This project is licensed under the MIT License.

## Contact

For issues and inquiries, contact `posiayoola102@gmail.com` or open an issue on GitHub.

