# Makefile for NEXUS Core
# ------------------------------------------------------------------------------
# Provides convenience targets for common development tasks.

# Use bash for all shell commands
SHELL := /bin/bash

# Define the virtual environment directory
VENV_DIR := venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

.PHONY: all install run test test-unit test-integration lint clean help

all: help

# Target: install - Creates a virtual environment and installs dependencies
install: $(VENV_DIR)/bin/activate
$(VENV_DIR)/bin/activate: requirements.txt
	@echo "--> Creating virtual environment in $(VENV_DIR)..."
	@python3 -m venv $(VENV_DIR)
	@echo "--> Installing dependencies from requirements.txt..."
	@$(PIP) install --upgrade pip > /dev/null
	@$(PIP) install -r requirements.txt
	@touch $(VENV_DIR)/bin/activate
	@echo "✅ Installation complete."

# Target: run - Runs the main NEXUS application
run:
	@echo "--> Activating virtual environment and running NEXUS Core..."
	@source $(VENV_DIR)/bin/activate && $(PYTHON) main.py

# Target: test - Runs all tests with coverage report
test:
	@echo "--> Running all tests with coverage..."
	@$(PYTHON) -m pytest tests/ -v --cov=. --cov-report=term-missing

# Target: test-unit - Runs only unit tests
test-unit:
	@echo "--> Running unit tests..."
	@$(PYTHON) -m pytest tests/unit/ -v -m unit

# Target: test-integration - Runs only integration tests
test-integration:
	@echo "--> Running integration tests..."
	@$(PYTHON) -m pytest tests/integration/ -v -m integration

# Target: lint - Compiles core Python files to check for syntax errors
lint:
	@echo "--> Checking Python syntax (linting)..."
	@$(PYTHON) -m py_compile core/orchestrator.py core/event_bus.py state/manager.py utils/logger.py utils/security.py agents/base.py agents/registry.py llm/abstraction.py main.py
	@echo "✅ Syntax check passed."

# Target: clean - Removes temporary files and directories
clean:
	@echo "--> Cleaning up temporary files..."
	@rm -rf __pycache__ .pytest_cache .coverage logs/
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "✅ Cleanup complete."

# Target: help - Displays this help message
help:
	@echo "Available targets:"
	@echo "  install          - Create a virtual environment and install dependencies."
	@echo "  run              - Run the main NEXUS application."
	@echo "  test             - Run all tests with coverage."
	@echo "  test-unit        - Run only unit tests."
	@echo "  test-integration - Run only integration tests."
	@echo "  lint             - Check Python syntax of core files."
	@echo "  clean            - Remove temporary files and caches."
	@echo "  help             - Show this help message."
