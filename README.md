# V2 OpenCode Web Login Module

A standalone login and security gateway in front of OpenCode. It connects to the OpenCode HTTP API without modifying OpenCode's source files. The systemd installer also enables a separate privileged administration service.

Repository: [hgn389/v2-opencode-web-login-module](https://github.com/hgn389/v2-opencode-web-login-module).
Prepared package version: **1.3.0-beta.1**. This is release preparation, not a claim that a public tag or downloadable release exists. Check the repository before using release URLs.

## Features

- Login with the existing OpenCode credentials, server-side sessions, logout and session revocation.
- Persistent failed-login counters, image CAPTCHA after five incorrect credentials and IP blocking after ten. Shared IPs share counters; this is not MFA.
- Origin/CSRF checks, trusted-proxy handling, authenticated SSE and terminal WebSocket forwarding.
- Web administration for password rotation, module updates, manual OpenCode update/downgrade and OpenAI-compatible custom providers for OpenCode v2.
- Provider model discovery through `GET /models` and browser-local model visibility preferences. Discovery does not prove permission to invoke a model.
- Bundled translations for 63 languages, including right-to-left layouts. No external translation service is called at runtime.

The settings integration is injected by the gateway on the same origin. It is not an official OpenCode GUI extension and may need adjustment when upstream UI structure changes. Direct administration routes remain available.

## Requirements

- Node.js **24 or newer**, npm and Git.
- OpenCode already installed using an official installation method, with credentials configured and a working service. Supported backends are stable OpenCode v2 and stable v1 from `1.18.20`.
- Linux with systemd and administrator access for the managed installation. Web OpenCode updates require `flock` and `runuser` from `util-linux`.
- For systemd installations, keep Node.js and the OpenCode binary in stable locations outside `/root`, `/home` and temporary directories. The shell and service must use the same OpenCode installation.

Install and configure OpenCode first. The module does not install OpenCode or create a separate login account. Keep its backend bound to loopback and do not expose its port publicly.

```sh
node --version
npm --version
command -v opencode
sudo systemctl status opencode.service
```

Paths, service names, accounts and ports vary by machine and instance. The examples below assume `/usr/local/bin/opencode`, `opencode.service`, gateway port `4096` and backend port `4097`; replace them with the actual values.

## Install From Source

After the repository is available, clone the source and inspect the revision before installation. A branch may contain unreleased changes; use a reviewed tag or commit when deploying.

```sh
git clone https://github.com/hgn389/v2-opencode-web-login-module.git /opt/opencode-web-login-src
cd /opt/opencode-web-login-src
npm ci --omit=dev --ignore-scripts
node bin/opencode-web-login.mjs --help
sudo node bin/opencode-web-login.mjs install \
  --opencode-bin /usr/local/bin/opencode \
  --opencode-service opencode.service \
  --host 127.0.0.1 --port 4096 --backend-port 4097 \
  --dry-run
```

Use appropriate ownership or administrator access when creating directories under `/opt`. Inspect the dry-run result, then repeat the installation command without `--dry-run` to apply it. For HTTPS, include the public origin and trusted proxy options described below in both commands.

The installer prepares locked dependencies, creates a dedicated unprivileged gateway account, moves the backend to loopback, installs the gateway and privileged administration services, and checks authentication. It preserves session/IP-block data on reinstall and uses private Git backups to restore changed files and service state if installation fails. Backups can contain credentials and must remain private.

Default managed paths are examples, not universal locations:

| Purpose | Default Example |
| --- | --- |
| Runtime code | `/opt/opencode-login` |
| Gateway environment | `/etc/opencode-login.env` |
| Session and IP state | `/var/lib/opencode-login/security.sqlite` |
| Administration configuration | `/etc/opencode-login-admin.json` |
| Administration state | `/var/lib/opencode-login-admin/` |
| Administration socket | `/run/opencode-login-admin/control.sock` |
| Backend password environment | `/etc/opencode-login-backend-password.env` |
| Installation backups | `/var/lib/opencode-login-install-backup/` |

Custom `--name` and `--install-dir` values change these paths. Check `install --help` and the installed units rather than assuming the defaults.

```sh
sudo systemctl status opencode.service opencode-login.service opencode-login-admin.service
sudo node /opt/opencode-login/bin/opencode-web-login.mjs doctor --config /etc/opencode-login.env
```

`doctor` checks configuration and the backend authentication response; it does not test a password or guarantee compatibility with every future OpenCode release. The installer prints a login URL using the configured port. Open `/login` and use your OpenCode credentials; `/logout` revokes the current session.

For direct LAN access, bind `--host` to the server's LAN IP and restrict the firewall. **HTTP is unencrypted: credentials and session traffic can be intercepted. Use it only on a trusted network or inside a secure tunnel. Use HTTPS for Internet access.** Binding all interfaces does not configure a firewall. Restart the gateway if interface IPs change.

## Nginx And HTTPS

Nginx and certificate provisioning are separate administrator tasks, not performed by this module. Point DNS at your server, install nginx, obtain a certificate using your chosen ACME client, and configure a dedicated virtual host. Keep gateway and backend ports private.

For a same-host reverse proxy, include these options when installing or reinstalling:

```sh
--public-origins https://coding.example.com --trusted-proxies 127.0.0.1,::1
```

Equivalent gateway settings are `LOGIN_PUBLIC_ORIGINS=https://coding.example.com` and `LOGIN_TRUSTED_PROXIES=127.0.0.1,::1`. Rerun the installer with all existing options when changing host, ports, origins or proxy trust so administration retains the correct installation parameters.

Example nginx configuration after obtaining a valid certificate (replace domain and certificate paths):

```nginx
# Place map in the nginx http context.
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 80;
    server_name coding.example.com;
    location / { return 301 https://coding.example.com$request_uri; }
}
server {
    listen 443 ssl;
    server_name coding.example.com;
    ssl_certificate /etc/letsencrypt/live/coding.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/coding.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:4096;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

This example overwrites client-supplied forwarding headers at the first trusted proxy. For multiple proxies, explicitly validate the forwarding chain and trust only controlled IPs/CIDRs. Test with `sudo nginx -t` before reloading nginx. Check external client IP handling, login, SSE and WebSockets before exposing the service.

### Optional IP Certificates

A domain is not mandatory if you obtain a publicly trusted certificate for your public IP. With Let's Encrypt, use **Certbot 5.4 or newer**, an IP identifier and the **shortlived** profile. For example, where supported by the installed Certbot and ACME service:

```sh
sudo certbot certonly --webroot -w /var/www/acme \
  --ip-address YOUR_PUBLIC_IP --required-profile shortlived
```

Create and serve that webroot on port 80 at `/.well-known/acme-challenge/` before requesting the certificate; preserve that location outside the HTTP-to-HTTPS redirect. Use the actual certificate paths printed by Certbot, configure nginx for that IP, and set the module's public origin to `https://YOUR_PUBLIC_IP`. The example does not configure IPv6 listeners or the ACME location for you.

Short-lived IP certificates require **automatic renewal**. Enable and verify the Certbot renewal timer or equivalent scheduler, arrange an nginx reload deploy hook, and test `certbot renew --dry-run`. Monitor expiry and renewal failures. An IP certificate does not make plain HTTP safe, and private/LAN IPs are not publicly certifiable this way.

## Web Administration

After logging in, use the Web Login Module settings entries or these exact gateway paths:

| Route | Purpose |
| --- | --- |
| `/web-login/password` | Rotate the OpenCode password; all sessions are revoked |
| `/web-login/updates` | Module update checks, channel and automatic-update preferences |
| `/web-login/opencode` | Manual OpenCode update or downgrade |
| `/web-login/providers` | OpenCode v2 custom providers and model visibility |

Administration requires the managed systemd installation, an active session accepted by OpenCode, origin/CSRF validation and confirmation for disruptive changes. It does not ask for the current password again. Save work before restarting or updating services. Passwords must be 16 to 128 characters. Standalone/library use does not gain privileged administration automatically.

Module automatic updates are **off by default** and the default channel is stable. When enabled, checks run hourly. The beta channel permits prereleases; stable excludes them. Only newer versions are accepted from published GitHub Releases of `hgn389/v2-opencode-web-login-module`, never from a branch snapshot. The updater requires the exact versioned asset path, an uploaded asset with a GitHub API `sha256:` digest, matching size and digest, an allowlisted archive and matching package/shrinkwrap identities. It then invokes the installer with backup/rollback. A digest protects integrity relative to trusted GitHub metadata, not against a compromised maintainer account.

OpenCode updates remain separate and manual. They use official npm packages `@opencode/cli` (v2) or `opencode-ai` (v1), SHA-512 verification from `registry.npmjs.org` and version discovery from `anomalyco/opencode`. They do not use this module's fork as an OpenCode source. Web updates require a supported root-managed global npm installation. Other official installation methods may need their own terminal upgrade flow. Downgrading can affect database compatibility; keep backups, and do not assume conversations migrate between v1 and v2 databases.

Custom provider discovery sends a Bearer key only to the configured endpoint, does not follow redirects, and limits response size/time and request rate. Private-network discovery and unencrypted HTTP require separate confirmations. Keys are not filled back into the browser. Changing the endpoint requires replacing or clearing the key. Visibility preferences are browser/origin-local and do not delete configured models.

## Security And Operations

- Sessions expire after eight hours maximum or 30 minutes without authenticated activity. Logout revokes them server-side. SSE/WebSocket sessions are rechecked periodically.
- Failed-credential counters and IP blocks survive restarts. CAPTCHA is single-use with a five-minute lifetime; CAPTCHA/session failures do not count as wrong credentials.
- HTTPS origins use Secure, HttpOnly, SameSite=Strict `__Host-` cookies. Proxy trust must be correct for client IP enforcement.
- Keep environment files, administration configuration, SQLite/WAL/SHM files, encryption keys, provider secrets, logs and private backups out of Git and release assets. State directories require private ownership/permissions; do not weaken symlink or permission checks to bypass errors.
- The root administration service is a privileged security boundary. Keep its socket private and never expose it through nginx. Do not expose the OpenCode backend to bypass the gateway.
- If credentials were ever published, revoke/rotate them first. Removing a current file does not remove Git history or existing release assets.

Run maintenance commands as the state-owning account and use your actual instance paths:

```sh
sudo -u opencode-login node /opt/opencode-login/bin/opencode-web-login.mjs blocked --config /etc/opencode-login.env
sudo -u opencode-login node /opt/opencode-login/bin/opencode-web-login.mjs unblock 192.0.2.10 --config /etc/opencode-login.env
sudo -u opencode-login node /opt/opencode-login/bin/opencode-web-login.mjs revoke-sessions --config /etc/opencode-login.env
journalctl -u opencode-login.service --since today
```

## Standalone And Library Use

Start a credential-protected OpenCode backend on loopback, copy `environment.example` to a private environment file, configure it and run:

```sh
node bin/opencode-web-login.mjs serve --config /absolute/path/login.env
```

For library use, install this local package and import `createLoginServer` from `v2-opencode-web-login-module`. Importing does not open a port or create a database. Call `listen()` to start and `close()` to stop; configuration helpers are exported from `v2-opencode-web-login-module/config`. Choose a private absolute state path and distinct gateway/backend endpoints.

## Upgrade And Release Packaging

Migration from `opencode-web-login` requires a **manual installation**: old updaters target the old repository and reject the new identity. Do not disable their safety checks. Use a reviewed source revision or a verified new release package, then rerun `install` with all the previous host, port, service, origin, proxy and path options. Updating a clone or global CLI alone does not update the running service.

The original repository published an npm-format `.tgz` plus a `.tgz.sha256` sidecar as GitHub Release attachments. This project preserves that approach with the new identity. GitHub's automatic source archives are not compatible updater assets. There is no existing release workflow; `release:pack` is a local packaging command and does not publish anything.

```sh
npm ci --ignore-scripts
npm test
npm run release:pack -- /absolute/path/release-output
git diff --check
```

The packaging command runs `npm pack --ignore-scripts`, validates the entire archive through the real updater (including exact runtime manifest, package identity and dependency locks), then writes:

```text
v2-opencode-web-login-module-1.3.0-beta.1.tgz
v2-opencode-web-login-module-1.3.0-beta.1.tgz.sha256
```

Only runtime files in the updater allowlist may appear. Tests, the local live-check script, handoff notes, packaging scripts, repository metadata and operational state are excluded. The font and its existing license notice remain included. Dependencies are fetched from npm at installation, not bundled from local `node_modules`.

Publication is a separate, explicitly authorized step: create a matching version tag/release, mark beta versions as prereleases, attach the validated archive and checksum, and verify GitHub reports the exact asset URL, size and `sha256:` digest matching the local checksum. A sidecar alone cannot satisfy the web updater. No commit, push, tag, npm publication or GitHub Release is performed by the packaging command.

After an authorized release exists, users can download both attachments from the repository's release page and verify before installation:

```sh
sha256sum --check v2-opencode-web-login-module-1.3.0-beta.1.tgz.sha256
sudo npm install -g --ignore-scripts ./v2-opencode-web-login-module-1.3.0-beta.1.tgz
opencode-web-login --help
```

The command name remains `opencode-web-login`. Replacing an older global package may require removing its conflicting global CLI first; do not use forced overwrites or remove service data. Run `opencode-web-login install` with the existing installation options to update the service after updating the CLI.

## Attribution And License

Derived from [hgn389/opencode-web-login-module](https://github.com/hgn389/opencode-web-login-module). OpenCode is a separate upstream project maintained at [anomalyco/opencode](https://github.com/anomalyco/opencode). Existing package license metadata is **UNLICENSED**; this preparation does not grant a new open-source license or alter upstream rights. Third-party components retain their own licenses. The bundled DejaVu font notice is preserved at `assets/LICENSE-fonts.txt`.
