# nix build .#checks.x86_64-linux.e2e-http -L
{ pkgs, self, headscale }:
let
  policy = sources: pkgs.writeText "golink-policy.json" (builtins.toJSON {
    acls = [{
      action = "accept";
      src = sources;
      dst = [ "*:*" ];
    }];
  });
  peer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = [ pkgs.curl ];
    services.tailscale.openFirewall = true;
  };
in
pkgs.testers.runNixOSTest {
  name = "golink-headscale-http";
  # The production module installs its package through an overlay.
  node.pkgsReadOnly = false;
  globalTimeout = 600;
  nodes = {
    headscale = {
      imports = [ headscale.nixosModules.testkit ];
      environment.etc = {
        "allow.json".source = policy [ "*" ];
        "deny-bob.json".source = policy [ "alice@" ];
      };
    };
    server = { lib, nodes, ... }: {
      imports = [ self.nixosModules.default ];
      # Unprivileged tsnet binds sockets to the default-route interface.
      networking.dhcpcd.denyInterfaces = [ "eth0" ];
      networking.defaultGateway = {
        address = nodes.headscale.networking.primaryIPAddress;
        interface = "eth1";
      };
      services.golink = {
        enable = true;
        controlUrl = "http://headscale";
        tailscaleAuthKeyFile = "/var/lib/golink/authkey";
      };
      systemd.services.golink = {
        # Enrollment needs the key issued after Headscale starts.
        wantedBy = lib.mkForce [ ];
        environment.TS_NO_LOGS_NO_SUPPORT = "1";
      };
      # tsnet chooses its own UDP port; no host TCP listener is exposed.
      networking.firewall.allowedUDPPortRanges = [{ from = 1024; to = 65535; }];
    };
    alice = peer;
    bob = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
  };
  testScript = ''
    import json
    import shlex
    from urllib.parse import urlencode

    url = "http://go.tailnet"


    def request(peer, path="/", data=None, status=200):
        args = [
            "curl",
            "-sS",
            "--max-time",
            "5",
            "-D",
            "/tmp/headers",
            "-o",
            "/tmp/body",
            "-w",
            "%{http_code}",
        ]
        if data is not None:
            args += ["-H", "Sec-Golink: test", "--data", urlencode(data)]
        actual = peer.succeed(shlex.join(args + [url + path]))
        body = peer.succeed("cat /tmp/body")
        assert actual == str(status), (peer.name, path, actual, body)
        return body


    def save(peer, short, long="https://example.com/", status=200, **fields):
        body = request(peer, data=dict(short=short, long=long, **fields), status=status)
        return json.loads(body) if status == 200 else body


    def golink_node():
        peers = json.loads(alice.succeed("tailscale status --json"))["Peer"]
        return next(node for node in peers.values() if node["HostName"] == "go")


    start_all()
    server.wait_for_unit("multi-user.target")
    server.succeed("ip -4 route show default | grep -E '^default via .* dev eth1( |$)'")
    for peer in (alice, bob):
        key = headscale.succeed(f"hs-authkey {peer.name}").strip()
        peer.succeed("hs-join " + shlex.quote(key))
    headscale.succeed("headscale policy set -f /etc/allow.json")
    key = headscale.succeed("hs-authkey server").strip()
    server.succeed(
        "install -o golink -g golink -m 600 /dev/null /var/lib/golink/authkey",
        "printf %s " + shlex.quote(key) + " > /var/lib/golink/authkey",
        "systemctl start golink",
    )
    for peer in (alice, bob):
        peer.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)

    with subtest("unprivileged service handles direct requests with WhoIs identity"):
        server.succeed(
            "test $(systemctl show -p User --value golink) = golink",
            "grep -Eq '^CapEff:[[:space:]]+0+$' /proc/$(pgrep -x golink)/status",
        )
        alice.wait_until_succeeds(
            "tailscale ping -c 1 --timeout=3s go | grep 'via .*:'", timeout=60
        )
        assert save(alice, "owned")["Owner"] == "alice"
        request(alice, "/owned", status=302)
        assert "Location: https://example.com/" in alice.succeed("cat /tmp/headers")
        assert golink_node()["CurAddr"]

    with subtest("forced DERP preserves WhoIs and ordinary ownership permissions"):
        bob.wait_until_succeeds(
            "tailscale ping --until-direct=false -c 1 --timeout=3s go | grep 'via DERP(headscale)'",
            timeout=60,
        )
        save(alice, "identity", "https://example.com/{{.User}}/{{.Path}}")
        request(bob, "/identity/item", status=302)
        assert "Location: https://example.com/bob/item" in bob.succeed("cat /tmp/headers")
        save(bob, "owned", "https://example.com/denied", status=403)
        request(bob, "/.delete/owned", data={}, status=403)
        assert (
            json.loads(request(alice, "/.detail/owned"))["Long"] == "https://example.com/"
        )
        assert save(bob, "bob-control")["Owner"] == "bob"
        assert save(alice, "owned", owner="bob")["Owner"] == "bob"
        save(alice, "owned", status=403)
        assert (
            save(bob, "owned", "https://example.com/persist", owner="alice")["Owner"]
            == "alice"
        )

    with subtest("live ACL denies Bob while Alice stays healthy, then allows Bob"):
        ip = alice.succeed("tailscale ip -4 go").strip()
        # Keep DNS visibility changes from masquerading as packet-filter enforcement.
        probe = (
            f"curl -sS --max-time 3 --resolve go.tailnet:80:{ip} "
            f"-o /dev/null -w '%{{http_code}}' {url}/.detail/owned 2>/tmp/acl-error"
        )
        assert bob.succeed(probe) == "200"
        headscale.succeed("headscale policy set -f /etc/deny-bob.json")
        bob.wait_until_fails(probe, timeout=60)
        request(alice, "/.detail/owned")
        code, output = bob.execute(probe)
        assert code in (7, 28) and output == "000", (code, output)
        headscale.succeed("headscale policy set -f /etc/allow.json")
        bob.wait_until_succeeds(probe + " | grep '^200$'", timeout=60)
        request(bob, "/owned", status=302)

    with subtest("restart preserves identity and data without an auth key"):
        node = golink_node()
        saved = json.loads(request(alice, "/.detail/owned"))
        assert node["ID"] and node["TailscaleIPs"]
        assert saved["Long"] == "https://example.com/persist" and saved["Owner"] == "alice"
        server.succeed(
            "systemctl stop golink",
            "truncate -s 0 /var/lib/golink/authkey",
            "systemctl start golink",
        )
        for peer in (alice, bob):
            peer.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)
        restarted = golink_node()
        assert (node["ID"], node["TailscaleIPs"]) == (
            restarted["ID"],
            restarted["TailscaleIPs"],
        )
        assert json.loads(request(alice, "/.detail/owned")) == saved
        request(bob, "/owned", status=302)
        assert "Location: https://example.com/persist" in bob.succeed("cat /tmp/headers")
        save(bob, "owned", status=403)
        save(alice, "owned", "https://example.com/after-restart")
  '';
}
