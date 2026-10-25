import csv
import json
import re
import shlex
from urllib.parse import urlencode

url = "https://go.tailnet" if tls_enabled else "http://go.tailnet"


def request(peer, path="/", data=None, headers=(), status=200):
    args = [
        "curl",
        "-sS",
        "--max-time",
        "10",
        "-D",
        "/tmp/headers",
        "-o",
        "/tmp/body",
        "-w",
        "%{http_code}",
    ]
    for header in headers:
        args += ["-H", header]
    if data is not None:
        args += ["--data", urlencode(data)]
    args += [url + path]
    actual = peer.succeed(shlex.join(args))
    body = peer.succeed("cat /tmp/body")
    assert actual == str(status), (peer.name, path, actual, body)
    return body


def save(peer, short, long="https://example.com/", status=200, **fields):
    body = request(
        peer,
        data=dict(short=short, long=long, **fields),
        headers=["Sec-Golink: test"],
        status=status,
    )
    return json.loads(body) if status == 200 else body


def token(peer, short):
    body = request(peer, "/.detail/" + short, headers=["Accept: text/html"])
    match = re.search(r'name="xsrf" value="([^"]+)"', body)
    assert match is not None, body
    return match[1]


def detail(short):
    return json.loads(request(alice, "/.detail/" + short))


def policy(name):
    headscale.succeed(f"headscale policy set -f /etc/{name}.json")


start_all()
server.wait_for_unit("multi-user.target")
certdir = "/var/lib/golink/.config/tsnet-golink/certs"
server.succeed(
    f"install -d -o golink -g golink -m 700 {certdir}",
    "openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=go.tailnet "
    f"-addext subjectAltName=DNS:go.tailnet -keyout {certdir}/go.tailnet.key "
    f"-out {certdir}/go.tailnet.crt",
    f"cp {certdir}/go.tailnet.crt /var/lib/golink/test-ca.crt",
    "chown -R golink:golink /var/lib/golink",
    f"chmod 600 {certdir}/go.tailnet.key",
)
cert = server.succeed("cat /var/lib/golink/test-ca.crt")
for peer in (alice, bob, admin):
    peer.succeed("printf %s " + shlex.quote(cert) + " > /tmp/app.crt")
keys = {
    name: headscale.succeed(f"hs-authkey {name}").strip()
    for name in ("alice", "bob", "admin")
}
policy("policy")
with subtest("Headscale still rejects unrecognized reserved capabilities"):
    headscale.succeed(
        "sed 's@tailscale.com/cap/golink@tailscale.com/cap/not-a-public-app@g' /etc/policy.json > /tmp/reserved.json"
    )
    code, output = headscale.execute("headscale policy set -f /tmp/reserved.json 2>&1")
    assert (
        code != 0
        and "capability name must not be in the tailscale.com domain" in output
    ), (code, output)
for peer in (alice, bob, admin):
    peer.succeed("hs-join " + shlex.quote(keys[peer.name]))

with subtest("invalid authentication cannot publish the application"):
    server.succeed(
        "install -o golink -g golink -m 600 /dev/null /var/lib/golink/authkey",
        "echo invalid-auth-key > /var/lib/golink/authkey",
        "systemctl start golink",
    )
    server.wait_until_succeeds(
        "journalctl -u golink -o cat | grep -F 'invalid pre auth key'",
        timeout=60,
    )
    alice.fail("timeout 5 tailscale ping go")
    # A working control-plane operation rules out an unavailable fixture.
    alice.succeed("tailscale ping --until-direct=false --timeout=5s bob")
    server.succeed(
        "timeout 15 systemctl stop golink",
        "test $(systemctl show -p Result --value golink) = success",
    )

key = headscale.succeed("hs-authkey admin --tags tag:golink").strip()
server.succeed(
    "printf '%s\\n' " + shlex.quote(key) + " > /var/lib/golink/authkey",
    "systemctl start golink",
)
alice.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)
for peer in (bob, admin):
    peer.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)

with subtest("automatic HTTPS selection and certificate verification"):
    if tls_enabled:
        alice.succeed(
            "curl -sS --max-time 5 -D /tmp/redirect -o /dev/null 'http://go.tailnet/owned?q=test'"
        )
        redirect = alice.succeed("cat /tmp/redirect")
        assert "302" in redirect
        assert "Location: https://go.tailnet/owned?q=test" in redirect
        code, output = alice.execute(
            "CURL_CA_BUNDLE= curl -fsS --max-time 5 https://go.tailnet/"
        )
        assert code == 60, output
        request(alice)
        assert "Strict-Transport-Security: max-age=31536000" in alice.succeed(
            "cat /tmp/headers"
        )
        ip = alice.succeed("tailscale ip -4 go").strip()
        code, output = alice.execute(
            f"curl -fsS --max-time 5 --cacert /tmp/app.crt --resolve go:443:{ip} https://go/"
        )
        assert code == 60, output
    else:
        request(alice)
        alice.fail("curl -fsS --max-time 5 https://go.tailnet/")

with subtest("real unprivileged package, tagged server and direct transport"):
    server.succeed(
        "test $(systemctl show -p User --value golink) = golink",
        "test $(stat -c %U /var/lib/golink/golink.db) = golink",
        "grep -Eq '^CapEff:[[:space:]]+0+$' /proc/$(pgrep -x golink)/status",
        "test -z \"$(ss -H -ltn '( sport = :80 or sport = :443 )')\"",
    )
    alice.wait_until_succeeds(
        "tailscale ping -c 1 --timeout=3s go | grep 'via .*:'", timeout=60
    )
    alice.succeed(
        'tailscale status --json | jq -e \'.Peer[] | select(.HostName == "go") | (.Tags | index("tag:golink")) != null and .CurAddr != ""\''
    )
    assert save(alice, "owned")["Owner"] == "alice"
    request(alice, "/owned", status=302)
    assert "Location: https://example.com/" in alice.succeed("cat /tmp/headers")
    assert "Referrer-Policy: no-referrer" in alice.succeed("cat /tmp/headers")
    save(alice, "identity", "https://example.com/{{.User}}/{{.Path}}")
    request(bob, "/identity/item", status=302)
    assert "Location: https://example.com/bob/item" in bob.succeed("cat /tmp/headers")
    for family in ("--ipv4", "--ipv6"):
        address = alice.succeed(f"tailscale ip -{family[-1]} go").strip()
        if family == "--ipv6":
            address = f"[{address}]"
        port = 443 if tls_enabled else 80
        saved = alice.succeed(
            f"curl -fsS --max-time 5 {family} --resolve 'go.tailnet:{port}:{address}' -H 'Sec-Golink: test' "
            f"--data 'short=identity-{family[2:]}&long=https://example.com/' {url}/"
        )
        assert json.loads(saved)["Owner"] == "alice"

with subtest("owner permissions, identity spoofing and XSRF"):
    assert "owned" in request(bob, "/.all")
    assert "owned" in request(alice, "/.search?q=owner:alice")
    request(alice, "/.search?q=unsupported", status=400)
    request(alice, "/missing", status=404)
    request(
        bob,
        data=dict(short="owned", long="https://evil.example/"),
        headers=[
            "Sec-Golink: test",
            "Tailscale-User-Login: alice",
            "X-Forwarded-For: 100.64.0.1",
        ],
        status=403,
    )
    save(bob, "bob-control")
    request(bob, "/.delete/owned", data=dict(xsrf=token(alice, "owned")), status=403)
    request(alice, data=dict(short="owned", long="https://evil.example/"), status=400)
    request(alice, "/.delete/owned", data={}, headers=["Sec-Golink: test"], status=400)
    assert detail("owned")["Long"] == "https://example.com/"
    save(alice, "owned", "https://example.com/updated")
    save(alice, "owned", owner="nonexistent", status=400)
    assert save(alice, "owned", owner="bob")["Owner"] == "bob"
    save(alice, "owned", status=403)
    save(bob, "owned", owner="alice")

with subtest("forced DERP application traffic and real admin grant"):
    admin.wait_until_succeeds(
        "tailscale ping --until-direct=false -c 1 --timeout=3s go | grep 'via DERP(headscale)'",
        timeout=60,
    )
    assert (
        save(admin, "owned", "https://example.com/admin", owner="alice")["Owner"]
        == "alice"
    )
    request(admin, "/owned", status=302)
    save(alice, "admin-delete")
    request(
        admin, "/.delete/admin-delete", data=dict(xsrf=token(admin, "admin-delete"))
    )
    request(alice, "/.detail/admin-delete", status=404)

with subtest("live grant revocation preserves ordinary allowed operations"):
    revocation_data = dict(
        short="owned", long="https://example.com/admin", owner="alice"
    )
    # A probe before map propagation must not grant the caller ownership.
    request(admin, data=revocation_data, headers=["Sec-Golink: test"])
    assert detail("owned")["Owner"] == "alice"
    policy("no-admin")
    admin.wait_until_succeeds(
        f"curl -sS --max-time 5 -o /dev/null -w '%{{http_code}}' -H 'Sec-Golink: test' --data {shlex.quote(urlencode(revocation_data))} {url}/ | grep '^403$'",
        timeout=60,
    )
    save(admin, "admin-control")
    save(alice, "owned", "https://example.com/persist")
    request(admin, "/.delete/owned", data={}, status=403)
    policy("policy")
    admin.wait_until_succeeds(
        f"curl -sS --max-time 5 -o /dev/null -w '%{{http_code}}' -H 'Sec-Golink: test' --data 'short=owned&long=https://example.com/persist&owner=alice' {url}/ | grep '^200$'",
        timeout=60,
    )

with subtest("network denial has allowed control and recovery"):
    ip = alice.succeed("tailscale ip -4 go").strip()
    port = 443 if tls_enabled else 80
    probe = (
        f"curl -sS --max-time 3 --resolve go.tailnet:{port}:{ip} "
        f"-o /tmp/denied-body -w '%{{http_code}}' {url}/.export 2>/tmp/denied-error"
    )
    assert bob.succeed(probe) == "200"
    policy("blocked")
    bob.wait_until_fails(probe, timeout=60)
    request(alice, "/.export")
    request(admin, "/owned", status=302)
    code, output = bob.execute(probe)
    assert code in (7, 28) and output == "000", (code, output)
    policy("policy")
    bob.wait_until_succeeds(probe + " | grep '^200$'", timeout=60)

with subtest("SQLite, click stats and node identity survive restart without auth key"):

    def clicks():
        return sum(
            int(row[2])
            for row in csv.reader(request(alice, "/.export-stats").splitlines())
            if row[0] == "owned"
        )

    before = json.loads(alice.succeed("tailscale status --json"))
    node = next(p for p in before["Peer"].values() if p["HostName"] == "go")
    clicks_before = clicks()
    request(alice, "/owned", status=302)
    server.succeed(
        "systemctl stop golink",
        "truncate -s 0 /var/lib/golink/authkey",
        "systemctl start golink",
    )
    alice.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)
    after = json.loads(alice.succeed("tailscale status --json"))
    restarted = next(p for p in after["Peer"].values() if p["HostName"] == "go")
    assert (node["ID"], node["TailscaleIPs"]) == (
        restarted["ID"],
        restarted["TailscaleIPs"],
    )
    assert detail("owned")["Long"] == "https://example.com/persist"
    assert detail("owned")["Owner"] == "alice"
    assert clicks() == clicks_before + 1
    save(bob, "owned", status=403)
    save(alice, "restart-control")

with subtest("control outage leaves established application traffic usable"):
    bob.wait_until_succeeds("tailscale ping -c 1 --timeout=3s go", timeout=60)
    headscale.succeed("systemctl stop headscale")
    request(alice, "/owned", status=302)
    code, output = admin.execute(probe)
    assert code in (7, 28) and output == "000", (code, output)
    save(bob, "owned", status=403)
    save(alice, "offline-control")
    headscale.succeed(
        "systemctl start headscale", "HEADSCALE_CLI_TIMEOUT=60s headscale health"
    )
    admin.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=60)

with subtest("owner deletion requires user-bound XSRF token"):
    save(bob, "bob-delete")
    request(
        bob,
        "/.delete/bob-delete",
        data=dict(xsrf=token(admin, "bob-delete")),
        status=400,
    )
    request(bob, "/.delete/bob-delete", data=dict(xsrf=token(bob, "bob-delete")))
    save(alice, "delete-me")
    request(alice, "/.delete/delete-me", data=dict(xsrf=token(alice, "delete-me")))
    request(alice, "/delete-me", status=404)
    request(alice, "/owned", status=302)

with subtest("departed owners and tagged clients"):
    bob_id = next(
        n["id"]
        for n in json.loads(headscale.succeed("headscale nodes list -o json"))
        if n["name"] == "bob"
    )
    bob.succeed("tailscale logout")
    headscale.succeed(f"headscale nodes delete --identifier {bob_id} --force")
    headscale.succeed("headscale users destroy --name bob --force")
    # Orphan detection uses the real LocalAPI user map, which updates asynchronously.
    alice.wait_until_succeeds(
        f"curl -sS --max-time 5 -o /dev/null -w '%{{http_code}}' -H 'Sec-Golink: test' --data 'short=bob-control&long=https://example.com/reclaimed' {url}/ | grep '^200$'",
        timeout=60,
    )
    assert detail("bob-control")["Owner"] == "alice"
    tagged_key = headscale.succeed("hs-authkey admin --tags tag:client").strip()
    bob.succeed("hs-join " + shlex.quote(tagged_key))
    bob.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=60)
    assert save(bob, "tagged")["Owner"] == "tagged-devices"
    save(bob, "owned", status=403)
    save(alice, "tagged")
    assert detail("tagged")["Owner"] == "alice"

with subtest("invalid service configuration fails closed and recovers"):
    server.succeed(
        "systemctl stop golink",
        "mkdir -p /run/systemd/system/golink.service.d",
        "printf '[Service]\\nEnvironment=TS_SERVICE_NAME=invalid\\n' > /run/systemd/system/golink.service.d/service.conf",
        "systemctl daemon-reload",
        "systemctl start golink",
    )
    server.wait_until_succeeds(
        "journalctl -u golink -o cat | grep -F \"service name must start with 'svc:' prefix\"",
        timeout=60,
    )
    alice.fail(f"curl -fsS --max-time 5 {url}/")
    alice.succeed("tailscale ping --until-direct=false --timeout=5s admin")
    server.succeed(
        "systemctl stop golink",
        "rm /run/systemd/system/golink.service.d/service.conf",
        "systemctl daemon-reload",
        "systemctl start golink",
    )
    alice.wait_until_succeeds(f"curl -fsS --max-time 5 {url}/", timeout=120)
    request(alice, "/owned", status=302)
