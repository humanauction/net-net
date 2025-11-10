# Makefile because dev lives matter

# Usage:
# make						# Build all binaries
# make activate				# Instructions to activate the virtual environment
# make venv					# Set up the virtual environment
# make build				# Build the project
# make run-daemon-offline	# Run the daemon in the foreground
# make run-daemon-online	# Run the daemon in the background 
# make clean				# Clean all build artifacts
# make test					# Run all tests

VENV=.venv-netnet
PYTHON=$(VENV)/bin/python3
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

BUILD_DIR=build
DAEMON=$(BUILD_DIR)/netnet
CONFIG=examples/sample-config.yaml
PCAP=tests/fixtures/sample.pcap

all: build test

activate:
    @echo "Run: source .venv-netnet/bin/activate"

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt || true

build:
	cmake -S . -B $(BUILD_DIR)
	$(MAKE) -C $(BUILD_DIR)

run-daemon-offline:
	$(DAEMON) --config $(CONFIG)

test: venv build
	$(PYTEST) tests/integration/test_api.py

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all venv build run-daemon-offline test clean

