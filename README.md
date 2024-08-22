# Spyderisk System Modeller Python Implementation

This Python package parses Spyderisk domain and system model NQ files and
represents the entities from these models as Python objects, offering a static,
read-only view of a system or domain model.

## Build and Test Instructions

This project uses `make` to automate common tasks such as building the project,
running tests, etc. The `Makefile` in the root directory defines various
targets that you can use.

### Prerequisites

Make sure you have `make` installed on your system. For Windows, you can install
it via tools like MinGW or WSL, use `make --version` to verify installation.

### Available `make` targets

- **`make init`**: Create virtual environment and install dependencies
- **`make clean`**: Clean up unnecessary files
- **`make test`**: Run tests
- **`make lint`**: Lint code
- **`make build`**: Build spyderisk package
- **`make install`**: Install spyderisk package
- **`make uninstall`**: Uninstall spyderisk package
- **`make uml`**: Create UML diagrams
- **`make help`**: Display this help message

**Note**: System and domain models for unit tests are not included in this
repository. You will need to provide your own models if you want to run the
unittests. Unit tests models are specified in *test_config.py* as:

- *TEST_DOMAIN_FILE* and
- *TEST_SYSTEM_FILE*

Update *test_config.py* accordingly to reflect your own model names.

After setting up your models and ensuring all prerequisites are met, run the
unit tests using the following command:

```sh
make test
```

To run specific tests pass the module name e.g. for
*TestDomainModel.test_version*:

```
make test TEST=spyderisk.tests.test_domain_model.TestDomainModel.test_version
```

## Python spyderisk package structure:

```
.
├── docs/                      # Documentation for the python spyderisk project
├── examples/                  # Example scripts demonstrating how to use the package
│   └── example1.py
├── LICENSE                    # License file for the project
├── Makefile                   # Makefile for build automation tasks
├── README.md                  # Main README file with project overview and usage
├── requirements.txt           # List of dependencies (used for development or in list of setup.py)
├── setup.py                   # Script for packaging and installation
└── spyderisk/                 # Main Python package directory
    ├── core_model.py          # Core functionality of the package
    ├── domain_model.py        # Domain-specific models and logic
    ├── __init__.py            # Initializes the spyderisk package
    ├── system_model.py        # System-specific models and logic
    ├── risk_vector.py         # Risk vector calculation and logic
    ├── config/                # Config module
    │   └── test_config.py     # Unit test configurable data resources
    └── tests/                 # Unit tests for the package
        ├── data/              # Test data for unit tests, e.g. domain and system models
        │   ├── domain-network-xxx.zip*
        │   └── system-model.nq.gz*
        ├── __init__.py        # Makes tests a package (optional but useful)
        ├── test_domain_model.py  # Tests for domain_model.py
        └── test_system_model.py  # Tests for system_model.py
```

