# ESP32 Tang Server Makefile
# Convenient shortcuts for ESP-IDF development tasks

.DEFAULT_GOAL := help

# Configuration variables
PORT ?= /dev/ttyUSB0
BAUD ?= 115200
TARGET ?= esp32

# Help target
.PHONY: help
help:
	@echo "ESP32 Tang Server Development Commands"
	@echo "====================================="
	@echo ""
	@echo "Setup:"
	@echo "  setup-target    Set ESP32 as build target"
	@echo "  menuconfig      Open configuration menu"
	@echo ""
	@echo "Build:"
	@echo "  build           Build the project"
	@echo "  clean           Clean build files"
	@echo "  fullclean       Full clean (including config)"
	@echo ""
	@echo "Flash & Monitor:"
	@echo "  flash           Flash to device"
	@echo "  monitor         Open serial monitor"
	@echo "  flash-monitor   Flash and immediately monitor"
	@echo ""
	@echo "Development:"
	@echo "  size            Show binary size analysis"
	@echo "  erase           Erase flash completely"
	@echo "  bootloader      Flash bootloader only"
	@echo ""
	@echo "Board Management:"
	@echo "  list-boards     List connected boards"
	@echo "  detect-port     Detect serial ports"
	@echo "  board-info      Show board information"
	@echo ""
	@echo "Environment variables:"
	@echo "  PORT=/dev/ttyUSB0  (default serial port)"
	@echo "  BAUD=115200        (default baud rate)"
	@echo "  TARGET=esp32       (default target)"

# Setup commands
.PHONY: setup-target
setup-target:
	idf.py set-target $(TARGET)

.PHONY: menuconfig
menuconfig:
	idf.py menuconfig

# Build commands
.PHONY: build
build:
	idf.py build

.PHONY: clean
clean:
	idf.py clean

.PHONY: fullclean
fullclean:
	idf.py fullclean

# Flash and monitor commands
.PHONY: flash
flash:
	idf.py -p $(PORT) -b $(BAUD) flash

.PHONY: monitor
monitor:
	idf.py -p $(PORT) -b $(BAUD) monitor

.PHONY: flash-monitor
flash-monitor:
	idf.py -p $(PORT) -b $(BAUD) flash monitor

# Development utilities
.PHONY: size
size:
	idf.py size

.PHONY: size-components
size-components:
	idf.py size-components

.PHONY: size-files
size-files:
	idf.py size-files

.PHONY: erase
erase:
	idf.py -p $(PORT) erase-flash

.PHONY: bootloader
bootloader:
	idf.py -p $(PORT) bootloader-flash

# Show partition table
.PHONY: partition-table
partition-table:
	idf.py partition-table

# Generate compilation database for IDE support
.PHONY: compile-commands
compile-commands:
	idf.py build --cmake-args="-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"

# Development shortcuts
.PHONY: dev
dev: build flash-monitor

.PHONY: quick
quick: build flash

# Board management
.PHONY: list-boards
list-boards:
	idf.py -p $(PORT) board_info || echo "Connect board to $(PORT)"

.PHONY: detect-port
detect-port:
	@echo "Scanning for ESP32 devices..."
	@if ls /dev/ttyUSB* >/dev/null 2>&1; then \
		echo "Found USB serial devices:"; \
		ls -la /dev/ttyUSB* | head -5; \
	elif ls /dev/ttyACM* >/dev/null 2>&1; then \
		echo "Found ACM serial devices:"; \
		ls -la /dev/ttyACM* | head -5; \
	else \
		echo "No serial devices found. Make sure ESP32 is connected."; \
	fi

.PHONY: board-info
board-info:
	@echo "Board Information:"
	@echo "=================="
	@echo "Target: $(TARGET)"
	@echo "Port: $(PORT)"
	@echo "Baud: $(BAUD)"
	@echo ""
	@echo "ESP-IDF Version:"
	@idf.py --version
	@echo ""
	@echo "Project status:"
	@idf.py show-port-info -p $(PORT) 2>/dev/null || echo "No device connected to $(PORT)"

# Show ESP-IDF version and tools
.PHONY: version
version:
	@echo "ESP-IDF Version Information:"
	@idf.py --version
	@echo ""
	@echo "Toolchain versions:"
	@xtensa-esp32-elf-gcc --version | head -1 || echo "Toolchain not found"
	@python3 --version
	@cmake --version | head -1

# Validate project structure
.PHONY: validate
validate:
	@echo "Validating ESP-IDF project structure..."
	@if [ ! -f "CMakeLists.txt" ]; then \
		echo "Error: CMakeLists.txt not found"; \
		exit 1; \
	fi
	@if [ ! -d "main" ]; then \
		echo "Error: main directory not found"; \
		exit 1; \
	fi
	@echo "Project validation passed!"

# Full development cycle
.PHONY: full-setup
full-setup: setup-target menuconfig build
	@echo ""
	@echo "Full setup complete! You can now:"
	@echo "  make flash      # Flash to device"
	@echo "  make monitor    # View serial output"
	@echo "  make dev        # Flash and monitor"
