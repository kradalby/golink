{ pkgs, self, headscale, https ? true }:
let
  policy = admin: blocked: pkgs.writeText "golink-policy.json" (builtins.toJSON {
    tagOwners."tag:golink" = [ "admin@" ];
    tagOwners."tag:client" = [ "admin@" ];
    acls = [{
      action = "accept";
      src = if blocked then [ "alice@" "admin@" "tag:client" ] else [ "*" ];
      dst = [ "*:*" ];
    }];
    grants = pkgs.lib.optional admin {
      src = [ "admin@" ];
      dst = [ "tag:golink" ];
      app."tailscale.com/cap/golink" = [{ admin = true; }];
    };
  });
  peer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
    environment.variables.CURL_CA_BUNDLE = "/tmp/app.crt";
    networking.firewall.trustedInterfaces = [ "tailscale0" ];
    services.tailscale.openFirewall = true;
  };
in
pkgs.testers.runNixOSTest {
  name = "golink-headscale-${if https then "https" else "http"}";
  # The production module installs its package through an overlay.
  node.pkgsReadOnly = false;
  globalTimeout = 900;
  nodes = {
    headscale = {
      imports = [ headscale.nixosModules.testkit ];
      # This pin omits golink from its public Tailscale app-capability allowlist.
      services.headscale.package = headscale.packages.${pkgs.stdenv.hostPlatform.system}.headscale.overrideAttrs (old: {
        patches = (old.patches or [ ]) ++ [ ./headscale-golink-cap.patch ];
      });
      services.headscale.settings.dns = pkgs.lib.optionalAttrs https {
        certificates.enabled = true;
        # Cached application certificates avoid public ACME and DNS challenges.
        challenge.provider = {
          name = "rfc2136";
          server = "127.0.0.1:53";
          key_name = "test";
          key_alg = "hmac-sha256";
          key = "c2VjcmV0";
        };
      };
      environment.etc = {
        "policy.json".source = policy true false;
        "no-admin.json".source = policy false false;
        "blocked.json".source = policy true true;
      };
    };
    server = { lib, ... }: {
      imports = [ self.nixosModules.default ];
      environment.systemPackages = [ pkgs.openssl ];
      services.golink = {
        enable = true;
        verbose = true;
        controlUrl = "http://headscale";
        tailscaleAuthKeyFile = "/var/lib/golink/authkey";
      };
      systemd.services.golink = {
        wantedBy = lib.mkForce [ ];
        environment.TS_NO_LOGS_NO_SUPPORT = "1";
        environment.GOLINK_DISABLE_NETWORK_NAMESPACES = "1";
        environment.TS_ADVERTISE_TAGS = "tag:golink";
        environment.SSL_CERT_FILE = "/var/lib/golink/test-ca.crt";
      };
      # tsnet chooses its own UDP port; no host TCP listener is exposed.
      networking.firewall.allowedUDPPortRanges = [{ from = 1024; to = 65535; }];
    };
    alice = peer;
    bob = peer;
    admin = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
  };
  testScript = "tls_enabled = ${if https then "True" else "False"}\n" +
    builtins.readFile ./e2e.py;
}
