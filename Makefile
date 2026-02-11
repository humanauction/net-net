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
# make coverage             # make HTML coverage report
# make clean                # Clean all build artifacts

VENV=.venv-netnet
PYTHON=$(VENV)/bin/python3
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

CMAKE ?= cmake
BUILD_DIR ?= build
BUILD_TYPE ?= Debug

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
NETNET_IFACE ?= en0
NETNET_USER ?= nobody
NETNET_GROUP ?= nobody
NETNET_BPF_FILTER ?=

.DEFAULT_GOAL := all

all: build

activate:
	@echo "Run:"
	@echo "  source $(VENV)/bin/activate"

venv:
	@test -d "$(VENV)" || python3 -m venv "$(VENV)"
	@$(PIP) install -U pip
	@test -f requirements.txt && $(PIP) install -r requirements.txt || true

config-ci:
	@echo "==> Generating CI config: $(CONFIG_CI)"
	@NETNET_IFACE="$(NETNET_IFACE)" NETNET_USER="$(NETNET_USER)" NETNET_GROUP="$(NETNET_GROUP)" NETNET_BPF_FILTER="$(NETNET_BPF_FILTER)" \
		envsubst < "$(CONFIG)" > "$(CONFIG_CI)"

build:
	@echo "==> Configuring (type=$(BUILD_TYPE))..."
	@$(CMAKE) -S . -B "$(BUILD_DIR)" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE="$(BUILD_TYPE)"
	@echo "==> Building..."
	@$(CMAKE) --build "$(BUILD_DIR)" -- -j$(sysctl -n hw.ncpu)
rebuild: clean build

.PHONY: clean-coverage
clean-coverage:
	@echo "🧹 Cleaning coverage data..."
	@find "$(BUILD_DIR)" -name "*.gcda" -delete 2>/dev/null || true
	@echo "✅ Coverage data cleaned"

rebuild-coverage: clean
	@echo "==> Rebuilding project with coverage instrumentation..."
	@$(CMAKE) -S . -B "$(BUILD_DIR)" -G "Unix Makefiles" \
		-DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_CXX_FLAGS="--coverage -g -O0" \
		-DCMAKE_EXE_LINKER_FLAGS="--coverage"
	@$(CMAKE) --build "$(BUILD_DIR)" -- -j$(sysctl -n hw.ncpu)
	@echo "==> Copying test fixtures..."
	@mkdir -p "$(BUILD_DIR)/tests/fixtures"
	@cp -r tests/fixtures/* "$(BUILD_DIR)/tests/fixtures/"

remove-vendor-coverage:
	@echo "🧹 Removing vendor coverage files..."
	@find "$(BUILD_DIR)" -path "*/vendor/*" -name "*.gcda" -delete 2>/dev/null || true
	@find "$(BUILD_DIR)" -path "*/_deps/*" -name "*.gcda" -delete 2>/dev/null || true
	@find "$(BUILD_DIR)" -path "*/_deps/*" -name "*.gcno" -delete 2>/dev/null || true
	@echo "✅ Vendor coverage files removed"

# Check if gcovr is available
GCOVR := $(shell command -v gcovr 2> /dev/null || echo "python3 -m gcovr")

coverage: rebuild-coverage
	@echo "==> Running tests with coverage..."
	@cd "$(BUILD_DIR)" && ctest --output-on-failure || true
	@echo "==> Generating coverage report..."
	@$(GCOVR) --root . --filter src/ --exclude src/main.cpp --exclude src/daemon/Main.cpp \
		--exclude '.*/_deps/.*' --exclude '.*/vendor/.*' --print-summary

coverage-html: rebuild-coverage
	@echo "==> Running tests with coverage..."
	@cd "$(BUILD_DIR)" && ctest --output-on-failure || true
	@echo "==> Generating HTML coverage report..."
	@$(GCOVR) --root . --filter src/ --exclude src/main.cpp --exclude src/daemon/Main.cpp \
		--exclude '.*/_deps/.*' --exclude '.*/vendor/.*' --html --html-details -o coverage.html
	@echo "✅ Coverage report: coverage.html"
	@$(OPEN_CMD) coverage.html 2>/dev/null || echo "Open coverage.html manually"

demon: config-ci build
	@echo "==> Running daemon with config: $(CONFIG_CI)"
	@sudo "$(DAEMON)" --config "$(CONFIG_CI)"

demon-stop:
	@echo "==> Stopping daemon..."
	@sudo pkill -f "$(DAEMON)" || echo "Daemon not running."

demon-offl: build
	@echo "==> Running daemon in offline mode..."
	@"$(DAEMON)" --config "$(CONFIG)" --offline "$(PCAP)"

test: config-ci venv build
	@echo "==> Running C++ tests..."
	@cd "$(BUILD_DIR)" && ctest --output-on-failure --verbose
	@echo ""
	@echo "==> Running Python integration tests..."
	@$(PYTEST) tests/integration/test_api.py -v

test-cpp: build
	@echo "==> Running C++ tests only..."
	@cd "$(BUILD_DIR)" && ctest --output-on-failure --verbose

test-python: config-ci venv
	@echo "==> Running Python tests only..."
	@$(PYTEST) tests/integration/test_api.py -v

clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf "$(BUILD_DIR)"
	@rm -f "$(CONFIG_CI)"

back:
	@echo "starting backend server..."
	@cd www && python3 -m http.server 8083

.PHONY: all activate venv config-ci build rebuild \
	run-daemon-online run-daemon-offline test test-cpp test-python \
	coverage coverage-html clean clean-coverage remove-vendor-coverage rebuild-coverage
