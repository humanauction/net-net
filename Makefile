# Here Makefile Here - because dev lives matter too

# Usage:
# make                      # Build all binaries
# make activate             # Instructions to activate the virtual environment
# make venv                 # Set up the virtual environment
# make build                # Build the project
# make rebuild              # Clean and rebuild
# make run-daemon-online    # Run the daemon online (live capture)
# make run-daemon-offline   # Run the daemon offline (pcap replay)
# make test                 # Run ALL tests (C++ + Python) with coverage
# make test-cpp             # Run C++ tests only
# make test-python          # Run Python tests only
# make coverage             # Generate HTML coverage report
# make clean                # Clean all build artifacts

VENV=.venv-netnet
PYTHON=$(VENV)/bin/python3
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

BUILD_DIR=build
DAEMON=$(BUILD_DIR)/netnet-daemon
CONFIG=examples/sample-config.yaml
CONFIG_CI=examples/sample-config.ci.yaml
PCAP=tests/fixtures/sample.pcap
ICMP=tests/fixtures/icmp_sample.pcap

# Platform detection for coverage viewer
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	OPEN_CMD = open
else
	OPEN_CMD = xdg-open
endif

# Environment variables for CI config
NETNET_IFACE ?= lo0
NETNET_USER ?= nobody
NETNET_GROUP ?= nobody

.PHONY: clean-coverage
clean-coverage:
	@echo "🧹 Cleaning coverage data..."
	@find $(BUILD_DIR) -name "*.gcda" -delete 2>/dev/null || true
	@find $(BUILD_DIR) -name "*.gcno" -delete 2>/dev/null || true
	@echo "✅ Coverage data cleaned"

all: build

activate:
	@echo "Run: source .venv-netnet/bin/activate"

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt || true


coverage: clean-coverage test
	@echo "📊 Generating coverage report..."
	@cd $(BUILD_DIR) && gcovr --root .. \
	  --exclude '.*tests/.*' \
	  --exclude '.*vendor/.*' \
	  --exclude '.*googletest/.*' \
	  --print-summary

build:
	@echo "==> Building project with coverage instrumentation..."
	cmake -S . -B $(BUILD_DIR) \
		-G "Unix Makefiles" \
		-DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DIR)

rebuild: clean build

config-ci:
	@echo "==> Generating CI config..."
	env NETNET_IFACE=$(NETNET_IFACE) NETNET_USER=$(NETNET_USER) NETNET_GROUP=$(NETNET_GROUP) \
		envsubst < examples/sample-config.yaml > $(CONFIG_CI)

run-daemon-online: config-ci
	@echo "==> Running daemon with config: $(CONFIG_CI)"
	sudo $(DAEMON) --config $(CONFIG_CI)

run-daemon-offline:
	@echo "==> Running daemon in offline mode..."
	$(DAEMON) --config $(CONFIG) --offline $(PCAP)

test: config-ci venv build
	@echo "==> Running C++ unit and integration tests..."
	cd $(BUILD_DIR) && ctest --output-on-failure --verbose
	@echo ""
	@echo "==> Running Python API integration tests..."
	$(PYTEST) tests/integration/test_api.py -v
	@echo ""
	@echo "==> Generating coverage report..."
	cd $(BUILD_DIR) && \
		lcov --capture --directory . --output-file coverage.info \
			--ignore-errors inconsistent,unsupported,format && \
		lcov --remove coverage.info '/usr/*' '*/tests/*' '*/vendor/*' '*/googletest/*' '*/include/net-net/vendor/*' \
			--output-file coverage_filtered.info \
			--ignore-errors inconsistent,unsupported,format,unused && \
		(lcov --list coverage_filtered.info | grep -E "NetMonDaemon|StatsPersistence|PcapAdapter" || true)
	@echo ""
	@echo "==> Coverage summary:"
	@cd $(BUILD_DIR) && lcov --summary coverage_filtered.info

test-cpp: build
	@echo "==> Running C++ tests only..."
	cd $(BUILD_DIR) && ctest --output-on-failure --verbose

test-python: config-ci venv
	@echo "==> Running Python tests only..."
	$(PYTEST) tests/integration/test_api.py -v

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(CONFIG_CI)

.PHONY: all activate venv build rebuild run-daemon-online run-daemon-offline \
		test test-cpp test-python coverage coverage-html config-ci clean clean-coverage
