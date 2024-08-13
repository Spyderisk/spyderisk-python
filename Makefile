# virtual env vars
VENV_DIR = env
PYTHON = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
PACKAGE_NAME = spyderisk
VERSION = 0.1.0
DIST_DIR = dist

.PHONY: init clean test lint install help

TEST ?= spyderisk/tests

# create virtual env and install dependencies
init: $(VENV_DIR)/bin/activate

$(VENV_DIR)/bin/activate: requirements.txt
	python3 -m venv $(VENV_DIR)
	$(PIP) install -r requirements.txt
	touch $(VENV_DIR)/bin/activate

# clean up
clean:
	find . -name "*.pyc" -exec rm -f {} +
	find . -name "__pycache__" -exec rm -rf {} +
	rm -rf $(VENV_DIR)
	rm -rf $(DIST_DIR) build *.egg-info

# run tests
test: $(VENV_DIR)/bin/activate
	@echo "Running tests: $(TEST)"
	@if [ -d "$(TEST)" ]; then \
		$(PYTHON) -m unittest discover -s $(TEST); \
	else \
		$(PYTHON) -m unittest $(TEST); \
	fi

# lint code
lint: $(VENV_DIR)/bin/activate
	$(PYTHON) -m flake8 spyderisk

# build the package
build: clean
	@echo "building the package..."
	python3 setup.py sdist bdist_wheel
	@echo "package spyderisk build successfully"

# install package
install: build
	@echo "installing spyderisk..."
	pip install .
	@echo "package spyderisk installed successfully"

# uninstall package
uninstall:
	@echo "uninstalling spyderisk..."
	pip uninstall spyderisk 
	@echo "package spyderisk uninstalled successfully"

# show help
help:
	@echo "Available targets:"
	@echo "  init     - Create virtual environment and install dependencies"
	@echo "  clean    - Clean up unnecessary files"
	@echo "  test     - Run tests"
	@echo "  lint     - Lint code"
	@echo "  build    - Build spyderisk package"
	@echo "  install  - Install spyderisk package"
	@echo "  uninstall - Uninstall spyderisk package"
	@echo "  help     - Display this help message"

