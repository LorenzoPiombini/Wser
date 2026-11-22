# Certbot automatic renewal for Wser

This guide configures a production Wser HTTPS service with automatic
Let's Encrypt renewal on Linux with systemd.

The intended trust and reload flow is:

```text
public ACME request
        |
        v
Wser serves the challenge file only
        |
        v
Certbot validates and installs the renewed certificate
        |
        v
root-owned deploy hook copies the certificate for Wser
        |
        v
systemctl reload wser.service
        |
        v
Wser supervisor sends SIGHUP to the TLS process
        |
        v
TLS process validates new contexts, swaps them in, then frees the old contexts
```

An HTTP request must never send `SIGHUP`. A challenge request only proves that
the requested challenge file is reachable; it does not prove that Certbot has
finished installing a valid certificate.

## Before starting

This guide uses two conspicuous placeholders:

- `YOUR_DOMAIN_HERE`: the exact hostname passed to Wser, for example
  `lorenzopiombini.com`.
- `YOUR_CERTBOT_CERT_NAME`: the lineage name reported by `certbot certificates`.
  It is often the domain, but it can have a suffix such as `-0001`.

Replace every placeholder before starting the service. Do not deploy the
literal placeholder or a sample domain such as `example.com`.

The following must also be true:

- The domain's DNS `A` and, if present, `AAAA` records point to the server.
- Incoming TCP ports 80 and 443 are allowed by the provider firewall and the
  host firewall.
- Wser contains the trusted `SIGHUP` implementation: systemd signals the main
  process, the main process signals the TLS child, and the TLS child builds new
  contexts before discarding the working contexts.
- The public ACME response code contains no `kill(..., SIGHUP)` call.

## 1. Install Certbot

On Ubuntu or Debian:

```bash
apt update
apt install certbot
```

On Fedora:

```bash
dnf install certbot
```

Run the remaining administrative commands as `root`, or prefix them with
`sudo`.

## 2. Create an unprivileged service account

Check whether the account already exists:

```bash
id wser
```

If it does not exist, create it:

```bash
useradd \
  --system \
  --user-group \
  --home-dir /var/lib/wser \
  --create-home \
  --shell /usr/sbin/nologin \
  wser
```

The numeric UID and GID do not matter. Confirm that the configured home is
`/var/lib/wser`:

```bash
getent passwd wser
```

Create the runtime, website, ACME, and certificate directories:

```bash
install -d -o wser -g wser -m 0750 /var/lib/wser
install -d -o wser -g wser -m 0750 /var/lib/wser/www

install -d -o root -g wser -m 0750 /var/lib/wser/acme
install -d -o root -g wser -m 0750 \
  /var/lib/wser/acme/.well-known/acme-challenge

install -d -o root -g wser -m 0750 /etc/wser
install -d -o root -g wser -m 0750 /etc/wser/certs
install -d -o root -g wser -m 0750 \
  /etc/wser/certs/YOUR_DOMAIN_HERE
```

Wser receives permission to read only its copied certificate. Do not make
`/etc/letsencrypt` broadly readable and do not run Wser as `root`.

## 3. Configure Wser

When systemd runs Wser as `User=wser`, Wser loads this file:

```text
/var/lib/wser/.wser.conf
```

It does not load `/root/.wser.conf`. Wser selects the configuration using the
home directory of its effective UID, not the shell's `$HOME` variable.

Create `/var/lib/wser/.wser.conf` with these contents:

```ini
CERT_PATH=/etc/wser/certs/
ACME_WEBROOT=/var/lib/wser/acme
SERVER_LOG_PATH=/var/lib/wser/server.log
```

Each key and value must be on the same physical line. The trailing slash in
`CERT_PATH` is required. Wser constructs the certificate pathname as:

```text
<CERT_PATH><domain>/fullchain.pem
<CERT_PATH><domain>/privkey.pem
```

Protect the configuration:

```bash
chown root:wser /var/lib/wser/.wser.conf
chmod 0640 /var/lib/wser/.wser.conf
```

To display physical line endings while troubleshooting:

```bash
sed -n 'l' /var/lib/wser/.wser.conf
```

## 4. Obtain the initial certificate

Wser cannot start in HTTPS mode until a certificate exists. For the first
issuance, make sure no process is using port 80, then use Certbot's temporary
standalone server:

```bash
systemctl stop wser.service 2>/dev/null || true

certbot certonly \
  --standalone \
  --preferred-challenges http \
  --cert-name YOUR_DOMAIN_HERE \
  -d YOUR_DOMAIN_HERE \
  --email YOUR_EMAIL_HERE \
  --agree-tos
```

Inspect the exact lineage name and paths:

```bash
certbot certificates
```

For example, Certbot might report either:

```text
/etc/letsencrypt/live/YOUR_DOMAIN_HERE/fullchain.pem
```

or:

```text
/etc/letsencrypt/live/YOUR_DOMAIN_HERE-0001/fullchain.pem
```

Use the reported lineage in the deploy hook. Do not guess it.

If a valid certificate already exists, skip issuance and use its existing
lineage.

## 5. Install the trusted deploy hook

Create this executable file:

```text
/etc/letsencrypt/renewal-hooks/deploy/reload-wser
```

Use the following script after replacing both placeholders:

```sh
#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

WSER_DOMAIN='YOUR_DOMAIN_HERE'
EXPECTED_LINEAGE='/etc/letsencrypt/live/YOUR_CERTBOT_CERT_NAME'
DESTINATION="/etc/wser/certs/$WSER_DOMAIN"

# Certbot runs every executable deploy hook for every renewed lineage.
# Ignore certificates that do not belong to this Wser service.
if [ "${RENEWED_LINEAGE:-}" != "$EXPECTED_LINEAGE" ]; then
    exit 0
fi

install -d -o root -g wser -m 0750 "$DESTINATION"

# Write complete temporary files in the destination filesystem first.
install -o root -g wser -m 0640 \
    "$RENEWED_LINEAGE/fullchain.pem" \
    "$DESTINATION/fullchain.pem.new"

install -o root -g wser -m 0640 \
    "$RENEWED_LINEAGE/privkey.pem" \
    "$DESTINATION/privkey.pem.new"

# Publish the complete files only after both copies succeeded.
mv -f "$DESTINATION/fullchain.pem.new" \
      "$DESTINATION/fullchain.pem"

mv -f "$DESTINATION/privkey.pem.new" \
      "$DESTINATION/privkey.pem"

# Initial installation can happen before the service exists or is active.
if systemctl is-active --quiet wser.service; then
    systemctl reload wser.service
fi
```

Protect the hook so the Wser account cannot modify code that Certbot executes
as `root`:

```bash
chown root:root /etc/letsencrypt/renewal-hooks/deploy/reload-wser
chmod 0750 /etc/letsencrypt/renewal-hooks/deploy/reload-wser
```

Use a deploy hook, not a post hook. Certbot invokes the deploy hook only after
it successfully installs a newly issued or renewed certificate.

### Install the initial certificate copy

Invoke the hook once with the exact lineage reported by Certbot:

```bash
RENEWED_LINEAGE=/etc/letsencrypt/live/YOUR_CERTBOT_CERT_NAME \
  /etc/letsencrypt/renewal-hooks/deploy/reload-wser
```

Confirm that Wser can read and parse both files:

```bash
runuser -u wser -- openssl x509 \
  -in /etc/wser/certs/YOUR_DOMAIN_HERE/fullchain.pem \
  -noout -subject -issuer -dates

runuser -u wser -- openssl pkey \
  -in /etc/wser/certs/YOUR_DOMAIN_HERE/privkey.pem \
  -noout -check
```

Never print or paste the private key itself.

## 6. Configure the systemd service

Install the Wser binary as a root-owned executable:

```bash
install -o root -g root -m 0755 ./wser /usr/local/bin/wser
```

Create `/etc/systemd/system/wser.service` after replacing
`YOUR_DOMAIN_HERE`:

```ini
[Unit]
Description=Wser HTTPS server
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=wser
Group=wser
Environment=HOME=/var/lib/wser
WorkingDirectory=/var/lib/wser

# Run in the foreground under systemd. Do not use Wser's background flag.
ExecStart=/usr/local/bin/wser -sl YOUR_DOMAIN_HERE
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=2s
KillMode=control-group
TimeoutStopSec=10s
UMask=0027

# Bind ports 80 and 443 without running the web server as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/wser
ReadOnlyPaths=/etc/wser/certs
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

The domain following `-sl` must exactly match the destination directory. If
the service uses `-sl example.com`, Wser will attempt to open
`/etc/wser/certs/example.com/fullchain.pem` even if the certificate belongs to
another domain.

Load and start the unit:

```bash
systemd-analyze verify /etc/systemd/system/wser.service
systemctl daemon-reload
systemctl enable --now wser.service
systemctl status wser.service --no-pager
```

Inspect startup logs:

```bash
journalctl -u wser.service -n 50 --no-pager
```

## 7. Change future renewals from standalone to webroot

The initial certificate used standalone mode because Wser could not start
without a certificate. Once Wser is active on port 80, ask a current Certbot
version to validate and save webroot renewal settings:

```bash
certbot reconfigure \
  --cert-name YOUR_CERTBOT_CERT_NAME \
  --webroot-path /var/lib/wser/acme
```

Certbot will create challenge files below:

```text
/var/lib/wser/acme/.well-known/acme-challenge/
```

Wser must serve that route over plain HTTP on port 80. All other HTTP traffic
may redirect to HTTPS.

If the installed Certbot does not support `reconfigure`, upgrade Certbot rather
than manually editing files below `/etc/letsencrypt/renewal/`.

## 8. Enable and test automatic renewal

Ubuntu and Debian packages normally install `certbot.timer`. Enable it if it
is present:

```bash
systemctl enable --now certbot.timer
systemctl status certbot.timer --no-pager
systemctl list-timers --all | grep -E 'certbot|snap.certbot'
```

A Certbot snap can instead use a snap-managed timer. Do not configure a second
timer when one automatic renewal mechanism is already active.

First test Wser's reload path without changing the certificate:

```bash
systemctl reload wser.service
systemctl status wser.service --no-pager
journalctl -u wser.service -n 30 --no-pager
```

Then test the complete Certbot validation and deploy-hook path against the
Let's Encrypt staging environment:

```bash
certbot renew --dry-run --run-deploy-hooks
```

`--run-deploy-hooks` is required when the installed Certbot normally suppresses
deploy hooks during a dry run.

Finally, inspect the certificate served by Wser:

```bash
openssl s_client \
  -connect YOUR_DOMAIN_HERE:443 \
  -servername YOUR_DOMAIN_HERE </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -serial -dates
```

## Troubleshooting

### Wser repeatedly restarts

Stop the loop before diagnosing it:

```bash
systemctl stop wser.service
systemctl reset-failed wser.service
```

Do not start it again until the configuration and certificate checks pass. The
unit's start limit prevents an unlimited rapid restart loop.

### `cannot load certificate chain`

The pathname in the Wser log is authoritative. Check all of the following:

```bash
systemctl show wser.service -p User -p Group -p ExecStart
grep -E '^(CERT_PATH|ACME_WEBROOT)=' /var/lib/wser/.wser.conf
certbot certificates
namei -l /etc/wser/certs/YOUR_DOMAIN_HERE/fullchain.pem
```

Common causes are:

- `YOUR_DOMAIN_HERE` or `example.com` was left in the systemd unit.
- The domain passed to `-sl` differs from the certificate directory.
- `CERT_PATH` has no trailing slash.
- A configuration value was placed on the line after its key.
- `EXPECTED_LINEAGE` does not match the name reported by Certbot.
- A symlink was copied instead of the certificate contents.

The TLS child currently reports fatal startup failure to the supervisor using
`SIGINT`, so systemd can show exit status 130 for an initial TLS failure.

### The ACME challenge returns 404

Verify:

- Port 80 is publicly reachable for every published `A` and `AAAA` address.
- `ACME_WEBROOT=/var/lib/wser/acme` is on one physical configuration line.
- Certbot writes below `.well-known/acme-challenge/` under that directory.
- The Wser account can traverse the complete path.
- The challenge request does not redirect before Wser checks the ACME route.

### Renewal succeeds but Wser keeps the old certificate

Check:

```bash
ls -l /etc/letsencrypt/renewal-hooks/deploy/reload-wser
journalctl -u wser.service --since '1 hour ago' --no-pager
```

Confirm that the hook's `EXPECTED_LINEAGE` matches `RENEWED_LINEAGE`, that the
hook copied both files, and that `systemctl reload wser.service` succeeds.

`SIGHUP` only tells Wser to reload files already installed on disk. It does not
request or renew a certificate itself.

## Security checklist

- Wser runs as the dedicated `wser` account, not `root`.
- Only systemd/Certbot can initiate a certificate reload.
- Public HTTP requests never signal a process.
- The deploy hook is owned by `root` and is not writable by `wser`.
- The private key copy is `0640 root:wser` inside `0750 root:wser`
  directories.
- The service cannot modify `/etc/wser/certs`.
- New TLS contexts are fully loaded and validated before replacing the old
  contexts.
- A failed reload keeps the previous working certificate and records the
  OpenSSL error in the journal.
