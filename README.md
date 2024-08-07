# Spyderisk Python Implementation

This is a Python package for Spyderisk.

## Build and Test Instructions

This project uses `make` to automate common tasks such as building the project,
running tests, etc. The `Makefile` in the root directory defines various
targets that you can use.

### Prerequisites

Make sure you have `make` installed on your system. For Windows, you can install
it via tools like MinGW or WSL, use `make --version` to verify installation.

In addition, you will need to provde a validated system model and its
corresponding domain model. Unittests are assuming that these models are named:

- *data/domain-network-6a6-1-2.zip* and
- *data/router.nq.gz*

Update the unit tests accordingly to reflect the new names.

After setting up your models and ensuring all prerequisites are met, run the
unit tests using the following command:

```sh
make test
```

### Available `make` targets

- **`make init`**: Create virtual environment and install dependencies
- **`make clean`**: Clean up unnecessary files
- **`make test`**: Run tests
- **`make lint`**: Lint code
- **`make build`**: Build spyderisk package
- **`make install`**: Install spyderisk package
- **`make uninstall`**: Uninstall spyderisk package
- **`make help`**: Display this help message

## Python spyderisk package structure:

```
.
├── docs/                      # Documentation for the python spyderisk project
├── examples/                  # Example scripts demonstrating how to use the package
│   └── example1.py
├── LICENSE                    # License file for the project
├── Makefile                   # Makefile for build automation tasks
├── README.md                  # Main README file with project overview and usage
├── requirements.txt           # List of dependencies (used for development or in lieu of setup.py)
├── setup.py                   # Script for packaging and installation
└── spyderisk/                 # Main Python package directory
    ├── core_model.py          # Core functionality of the package
    ├── domain_model.py        # Domain-specific models and logic
    ├── __init__.py            # Initializes the spyderisk package
    ├── system_model.py        # System-specific models and logic
    └── tests/                 # Unit tests for the package
        ├── data/              # Test data for unit tests
        │   ├── domain-network-6a6-1-2.zip*
        │   └── router.nq.gz*
        ├── __init__.py        # Makes tests a package (optional but useful)
        ├── test_domain_model.py  # Tests for domain_model.py
        └── test_system_model.py  # Tests for system_model.py
```

Note: The files *domain-network-6a6-1-2.zip* and *router.nq.gz* are example
domain and system models used for testing. These files are not included in this
repository. Use your own models instead and update the unit tests accordingly.

