# Boots a VM whose root filesystem is LUKS-encrypted and unlocked in the
# initrd by clevis, with the ESP32 as the tang server.
#
# The VM reaches the real device through QEMU's user-mode network, which the
# Nix sandbox blocks, so run the test driver directly instead of building the
# check:
#
#   nix build .#luks-clevis-test.driver
#   TANG_URL=http://<esp32-ip> TANG_TOKEN=<admin_token> ./result/bin/nixos-test-driver
#
# TANG_TOKEN is the device's admin_token; leave it out if none is set. Set
# TANG_PASSWORD for a require_password device; the test stores the keys
# with it.
#
# The test wipes the ESP32, provisions fresh keys and deactivates it at the
# end.
{ lib, ... }:
{
  name = "esp32-tang-luks-clevis";

  nodes.machine =
    { pkgs, ... }:
    {
      virtualisation = {
        emptyDiskImages = [ 512 ];
        useBootLoader = true;
        useEFIBoot = true;
        # The encrypted root starts out empty, so the store comes from the host.
        mountHostNixStore = true;
        # Only keep the user-mode uplink (eth0), which NATs through the host.
        vlans = [ ];
      };
      boot.loader.systemd-boot.enable = true;
      boot.initrd.systemd.enable = true;

      networking.interfaces.eth0.useDHCP = true;

      environment.systemPackages = with pkgs; [
        clevis
        cryptsetup
        curl
        jose
        jq
      ];

      # Installing the bootloader while building the image requires every
      # initrd secret to exist. The test overwrites this with the real JWE and
      # installs the bootloader again.
      environment.etc."clevis/cryptroot.jwe" = {
        text = "placeholder";
        mode = "0600";
      };

      specialisation.boot-luks.configuration = {
        boot.initrd.luks.devices = lib.mkVMOverride {
          cryptroot.device = "/dev/vdb";
        };
        boot.initrd.clevis = {
          enable = true;
          useTang = true;
          devices.cryptroot.secretFile = "/etc/clevis/cryptroot.jwe";
        };
        boot.initrd.systemd.network = {
          enable = true;
          networks."10-uplink" = {
            matchConfig.Name = "e*";
            networkConfig.DHCP = "ipv4";
          };
        };
        virtualisation.rootDevice = "/dev/mapper/cryptroot";
        virtualisation.fileSystems."/".autoFormat = true;
      };
    };

  testScript = ''
    import json
    import os

    tang_url = os.environ.get("TANG_URL", "").rstrip("/")
    if not tang_url:
        raise Exception("Set TANG_URL to the ESP32, e.g. TANG_URL=http://192.168.178.63")
    token = os.environ.get("TANG_TOKEN", "")
    password = os.environ.get("TANG_PASSWORD", "")
    auth = f"-H 'Authorization: Bearer {token}'" if token else ""

    def post(path, body='""'):
        # --json sets Content-Type, which the device needs for a body, and
        # Content-Length, which it needs even for an empty one.
        return machine.succeed(f"curl -fsS {auth} --json {body} {tang_url}{path}")

    machine.wait_for_unit("multi-user.target")
    machine.systemctl("start network-online.target")
    machine.wait_for_unit("network-online.target")

    with subtest("Provision the ESP32 with fresh keys"):
        post("/wipe")
        machine.succeed(
            "jose jwk gen -i '{\"alg\":\"ES512\"}' -o /tmp/sig.jwk",
            "jose jwk gen -i '{\"alg\":\"ECMR\"}' -o /tmp/exc.jwk",
            "jq -n --slurpfile s /tmp/sig.jwk --slurpfile e /tmp/exc.jwk"
            " '{keys: [$s[0], $e[0]]}' > /tmp/provision.json",
        )
        post("/provision", "@/tmp/provision.json")
        thp = machine.succeed("jose jwk thp -i /tmp/sig.jwk").strip()

        # With key_storage: nvs, the keys are served once /activate stores
        # them, encrypted with the password if the device requires one.
        status = json.loads(machine.succeed(f"curl -fsS {auth} {tang_url}/status"))
        if status.get("key_storage") == "nvs":
            if password:
                machine.succeed(
                    f"jq -n --arg p {json.dumps(password)} '{{password: $p}}' > /tmp/activate.json"
                )
                post("/activate", "@/tmp/activate.json")
            else:
                post("/activate")
        assert json.loads(machine.succeed(f"curl -fsS {tang_url}/status"))["state"] == "active"

    with subtest("Bind the encrypted root to the ESP32"):
        machine.succeed("echo -n supersecret | cryptsetup luksFormat -q --iter-time=1 /dev/vdb -")
        # Pin the signing key's thumbprint, so clevis verifies the advertisement
        # instead of trusting it blindly.
        pin = json.dumps({"url": tang_url, "thp": thp})
        machine.succeed(
            "rm -f /etc/clevis/cryptroot.jwe",
            f"echo -n supersecret | clevis encrypt tang '{pin}' > /etc/clevis/cryptroot.jwe",
        )
        assert machine.succeed("clevis decrypt < /etc/clevis/cryptroot.jwe") == "supersecret"

        # Append the real JWE to the specialisation's initrd, then boot it.
        machine.succeed("/run/current-system/bin/switch-to-configuration boot")
        machine.succeed("bootctl set-default nixos-generation-1-specialisation-boot-luks.conf")
        machine.succeed("sync")
        machine.crash()

    with subtest("The initrd unlocks the root via the ESP32"):
        machine.wait_for_unit("multi-user.target")
        assert "/dev/mapper/cryptroot on / type ext4" in machine.succeed("mount")
        machine.succeed("journalctl -b -u cryptsetup-clevis-cryptroot.service --grep 'Finished'")
        machine.succeed("echo persisted > /marker && sync")

    with subtest("Without keys on the ESP32 the initrd falls back to the passphrase"):
        # /adv and /rec now answer 503, which clevis treats as a failure.
        post("/deactivate")
        machine.crash()
        machine.start()
        machine.wait_for_console_text("Please enter")
        machine.send_console("supersecret\n")
        machine.wait_for_unit("multi-user.target")
        assert "/dev/mapper/cryptroot on / type ext4" in machine.succeed("mount")
        assert machine.succeed("cat /marker").strip() == "persisted"
  '';
}
