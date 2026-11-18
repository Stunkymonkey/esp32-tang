{
  description = "Tang server for ESP32 as an ESPHome component";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    #nixpkgs-esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
    nixpkgs-esp-dev.url = "github:Stunkymonkey/nixpkgs-esp-dev/fix-remote-builders";
    # ESPHome for the tang_server component. Separate from nixpkgs, because
    # esp-idf-full, which ESPHome builds with here, does not evaluate on a
    # current nixpkgs.
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, flake-utils, nixpkgs-esp-dev, nixpkgs-unstable }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system}.extend nixpkgs-esp-dev.overlays.default;
        # ESPHome builds with the esp-idf-full from this shell (IDF_PATH),
        # because the toolchain it would download cannot run on NixOS. It runs
        # idf.py with the first python on PATH, and its Nix wrapper puts its
        # own Python there, which lacks ESP-IDF's packages. So take the
        # wrapper's environment (esptool and the other Python packages), put
        # ESP-IDF's Python first, and run the unwrapped script.
        esphome = let
          upstream = nixpkgs-unstable.legacyPackages.${system}.esphome;
        in pkgs.writeShellScriptBin "esphome" ''
          idf_python="''${IDF_PYTHON_ENV_PATH:?esphome needs the dev shell}/bin"
          source <(grep -v '^exec ' ${upstream}/bin/esphome)
          export PATH="$idf_python:$PATH"
          exec -a "$0" ${upstream}/bin/.esphome-wrapped "$@"
        '';

        # verify_tang.py with its Python dependencies pinned. A separate
        # command rather than a python3 in the dev shell, which would shadow
        # the one ESP-IDF brings and the esphome wrapper relies on.
        verify-tang = pkgs.writeShellApplication {
          name = "verify-tang";
          runtimeInputs = [
            (pkgs.python3.withPackages (ps: [ ps.requests ps.cryptography ]))
          ];
          text = ''
            exec python3 ${./verify_tang.py} "$@"
          '';
        };
      in
      {
        packages = {
          inherit verify-tang;
        } // nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # Not a check: the test needs the ESP32 on the network, which the
          # sandbox blocks. See tests/luks-clevis.nix for how to run it.
          luks-clevis-test = nixpkgs.legacyPackages.${system}.testers.runNixOSTest ./tests/luks-clevis.nix;
        };

        # Talks to the device, so it is an app rather than a check.
        apps.verify = {
          type = "app";
          program = "${verify-tang}/bin/verify-tang";
          meta.description = "Check a running ESP32 Tang server against the Tang protocol";
        };

        # esphome config on the examples and the test configuration, with
        # dummy secrets: catches schema errors without a device or a build.
        # The upstream esphome is enough, as validation does not run idf.py.
        checks.examples = pkgs.runCommand "tang-server-examples"
          { nativeBuildInputs = [ nixpkgs-unstable.legacyPackages.${system}.esphome ]; } ''
            export HOME=$TMPDIR
            cp -r ${./components} components
            mkdir example tests
            cp ${./example}/*.yaml example/
            cp ${./tests}/*.yaml tests/
            for dir in example tests; do
              cat > $dir/secrets.yaml <<EOF
            wifi_ssid: ssid
            wifi_password: password
            api_encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ota_password: ota
            tang_admin_token: token
            EOF
            done
            chmod -R u+w .
            for config in example/tang-ram.yaml example/tang-nvs.yaml \
                          example/tang-nvs-password.yaml tests/tang-test.yaml; do
              echo "esphome config $config"
              esphome config $config > /dev/null
            done
            touch $out
          '';

        # tang_crypto and key_store built for the host with sanitizers, and
        # checked against Python's cryptography; see tests/host/run.sh.
        checks.host-tests = pkgs.stdenv.mkDerivation {
          name = "tang-server-host-tests";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./components ./tests/host ./verify_tang.py ];
          };
          buildInputs = [ pkgs.mbedtls ];
          nativeBuildInputs = [
            (pkgs.python3.withPackages (ps: [ ps.cryptography ps.requests ]))
          ];
          # ESPHome pins this ArduinoJson for its json component.
          ARDUINOJSON = pkgs.fetchurl {
            url = "https://github.com/bblanchon/ArduinoJson/releases/download/v7.4.3/ArduinoJson-v7.4.3.h";
            hash = "sha256-q1+7gmi4RrX0vFpf7hG7LJb3uLhG9b72VAr7apzHals=";
          };
          dontConfigure = true;
          buildPhase = ''
            OUT_DIR=$TMPDIR/host bash tests/host/run.sh
          '';
          installPhase = "touch $out";
        };

        devShells.default = pkgs.mkShell {
          name = "esp32-tang-dev";

          buildInputs = with pkgs; [
            # ESPHome builds with this ESP-IDF; see the esphome wrapper above.
            esp-idf-full
            esphome
            cmake
            ninja

            # Keys, the tests and talking to the device
            jose
            clevis
            verify-tang
            curl
            jq
            picocom

            clang-tools
          ];

          shellHook = ''
            echo "ESP32 Tang server: esphome compile example/tang-nvs.yaml," \
              "esphome run example/tang-nvs.yaml --device /dev/ttyUSB0"
          '';

          # Prevent Python from creating __pycache__ directories
          PYTHONDONTWRITEBYTECODE = "1";
        };
      }
    );
}
