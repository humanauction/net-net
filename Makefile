# Makefile because dev lives matter

# Usage:
# make						# Build all binaries
# make activate				# Instructions to activate the virtual environment
# make venv					# Set up the virtual environment
# make build				# Build the project
# make run-daemon-online	# Run the daemon online (live capture)
# make run-daemon-offline	# Run the daemon offline (pcap replay)
# make clean				# Clean all build artifacts
# make test					# Run all tests

VENV=.venv-netnet
PYTHON=$(VENV)/bin/python3
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

BUILD_DIR=build
DAEMON=$(BUILD_DIR)/netnet-daemon
CONFIG=examples/sample-config.yaml
PCAP=tests/fixtures/sample.pcap
ICMP=tests/fixtures/icmp_sample.pcap

all: build test

activate:
	@echo "Run: source .venv-netnet/bin/activate"

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt || true

build:
	cmake -S . -B build -G "Unix Makefiles"
	cmake --build build

run-daemon-online:
	sudo $(DAEMON) --config $(CONFIG)

run-daemon-offline:
	$(DAEMON) --config $(CONFIG) --offline $(PCAP)

test: venv build
	$(PYTEST) tests/integration/test_api.py

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all activate venv build run-daemon-online run-daemon-offline test clean

