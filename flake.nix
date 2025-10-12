{
  description = "ESP32 Tang Server Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs-esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
  };

  outputs = { self, nixpkgs, flake-utils, nixpkgs-esp-dev }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system}.extend nixpkgs-esp-dev.overlays.default;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "esp32-tang-dev";

          buildInputs = with pkgs; [
            # ESP-IDF with full toolchain
            esp-idf-full

            # Development tools
            gnumake
            cmake
            ninja
            ccache

            # Serial communication tools
            picocom
            screen
            minicom

            # Development utilities
            curl
            wget
            unzip
            file
            which
            jq

            # Text processing tools
            gawk
            gnused
            gnugrep

            # Optional development tools
            clang-tools
            bear
          ] ++ lib.optionals stdenv.isLinux [
            # Linux-specific packages for USB device access
            udev
            libusb1
          ];

          shellHook = ''
            echo "🚀 ESP32 Tang Server Development Environment"
            echo "============================================="
            echo
            echo "ESP-IDF: $(idf.py --version 2>/dev/null || echo 'Ready')"
            echo "Python: $(python3 --version)"
            echo "CMake: $(cmake --version | head -1)"
            echo
            echo "Available commands:"
            echo "  📦 idf.py build         - Build the project"
            echo "  📡 idf.py flash         - Flash to device"
            echo "  💻 idf.py monitor       - Serial monitor"
            echo "  🔧 idf.py flash monitor - Flash and monitor"
            echo "  ⚙️  idf.py menuconfig   - Configuration menu"
            echo "  🎯 idf.py set-target    - Set target (esp32)"
            echo
            echo "Or use the Makefile shortcuts:"
            echo "  make setup-target      - Set ESP32 target"
            echo "  make build             - Build project"
            echo "  make flash-monitor     - Flash and monitor"
            echo "  make menuconfig        - Configuration"
            echo
            echo "Quick start:"
            echo "  1. Set target:         make setup-target"
            echo "  2. Configure:          make menuconfig"
            echo "  3. Build:              make build"
            echo "  4. Flash & Monitor:    make flash-monitor PORT=/dev/ttyUSB0"
            echo

            # Set up development environment
            export IDF_TOOLS_PATH="$HOME/.espressif"
            export CCACHE_DIR="$HOME/.ccache"

            # Create necessary directories
            mkdir -p "$IDF_TOOLS_PATH"
            mkdir -p "$CCACHE_DIR"

            # Check for serial devices
            if ls /dev/ttyUSB* >/dev/null 2>&1; then
              echo "📡 Found USB serial devices:"
              ls -la /dev/ttyUSB* 2>/dev/null | head -3
            elif ls /dev/ttyACM* >/dev/null 2>&1; then
              echo "📡 Found ACM serial devices:"
              ls -la /dev/ttyACM* 2>/dev/null | head -3
            else
              echo "📡 No serial devices found. Connect your ESP32 board."
            fi

            # Check serial permissions
            if ! groups | grep -q dialout 2>/dev/null && ! groups | grep -q uucp 2>/dev/null; then
              echo
              echo "⚠️  Note: You may need to add your user to the 'dialout' group"
              echo "   to access serial devices:"
              echo "   sudo usermod -a -G dialout $USER"
              echo "   Then log out and log back in."
            fi

            echo
            echo "Ready for ESP32 development with Arduino support! 🎯"
            echo
          '';

          # Environment variables
          IDF_TOOLS_PATH = "$HOME/.espressif";
          CCACHE_DIR = "$HOME/.ccache";

          # Prevent Python from creating __pycache__ directories
          PYTHONDONTWRITEBYTECODE = "1";

          # Enable colored output
          FORCE_COLOR = "1";

          # Set locale to avoid issues
          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
        };

        devShells.minimal = pkgs.mkShell {
          name = "esp32-tang-minimal";

          buildInputs = with pkgs; [
            esp-idf-full
            git
            picocom
          ];

          shellHook = ''
            echo "⚡ ESP32 Tang Server (Minimal Environment)"
            echo "========================================"
            echo "Ready for ESP32 development!"
            echo

            export IDF_TOOLS_PATH="$HOME/.espressif"
            export CCACHE_DIR="$HOME/.ccache"
            mkdir -p "$CCACHE_DIR"
          '';
        };
      }
    );
}
