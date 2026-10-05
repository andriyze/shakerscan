# Security policy

ShakerScan is a security tool, and we treat vulnerabilities in it seriously. Thank you for helping
keep its users safe.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/andriyze/shakerscan/security/advisories/new)
(repository **Security** tab → **Report a vulnerability**).

Please include:

- the affected version (`shakerscan status` or the `VERSION` file) and deployment mode
  (localhost, `--lan`, `--remote`, fleet);
- the component (API, UI, worker, installer, client, container image);
- steps to reproduce, a proof of concept, and the impact you observed;
- any suggested fix or mitigation.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation for high/critical issues | as fast as practical, normally within 30 days |
| Public advisory | after a fixed release is available, coordinated with you |

We credit reporters in the advisory unless you prefer to stay anonymous.

## Supported versions

Security fixes are made for the latest release on the stable installer channel. Please upgrade
before reporting, and reproduce on the latest release where possible.

| Version | Supported |
|---|---|
| Latest 2.x release | Yes |
| Older releases | No |

## Scope

In scope:

- the ShakerScan engine (API, workers, scheduler, UI) and its default Docker Compose deployment;
- the installer (`install.shakerscan.com`, `install/`) and the `shakerscan` client package;
- published container images and release artifacts;
- ways ShakerScan could be made to attack a target outside the operator's authorized scope, leak
  stored credentials, or execute attacker-controlled commands.

Out of scope:

- findings that ShakerScan reports about *your* targets (those are its job);
- vulnerabilities in third-party tools it bundles (please report them upstream; see
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)), unless ShakerScan's integration makes them
  exploitable;
- the documented trust boundaries below, unless you can cross them in a way the documentation does
  not describe;
- denial of service that requires authenticated operator access, and social engineering.

## Safe harbor

We will not pursue or support legal action against good-faith research that follows this policy:
test only your own installation, do not access or modify other people's data, do not degrade
services for others, and give us reasonable time to fix an issue before disclosure.

## Deployment trust boundaries

Understanding these helps you deploy ShakerScan safely and helps reporters focus on real issues.

- **The open-source API has no login.** Anyone who can reach the API port can operate the engine.
  Fresh installs bind the UI and API to `127.0.0.1`. `--lan` and `--remote` expose them only to
  the chosen private network or tailnet and add no authentication, so use them only on networks
  whose users you trust, and restrict the ports with a firewall. Do not expose them to the
  Internet.
- **The API container can reach the Docker socket** to stage scanner images and manage workers.
  Reaching the API is therefore equivalent to administrative access on the Docker host. This is
  a further reason to keep the API on loopback or a trusted network.
- **SSH and saved actions run commands on remote hosts.** A Hunt's `ssh.exec`, the live SSH
  console and saved SSH actions use the SSH credentials stored for a target. Remote commands
  need an explicit `ssh.exec` grant on the credential and active testing, host keys are pinned
  (a changed key is refused), and the connection is bound to the target's authorized address.
  Because the API has no login, anyone who can reach it can use those grants, so treat a stored
  SSH credential with exec rights as reachable by every API client.
- **Browser protections.** CORS admits only the deployment's own UI origins, cross-origin
  browser writes are refused, and requests addressed to an unrecognised public host name are
  refused to stop DNS rebinding (see `SHAKERSCAN_ALLOWED_HOSTS` in
  [docs/lan-access.md](docs/lan-access.md)).
- **Scanner workers process hostile content.** Workers parse responses from the targets you scan.
  They run in containers without host mounts beyond the results directory, and outbound traffic
  is bound to the authorized target: DNS answers are frozen at admission and re-checked, and
  cloud-metadata and link-local addresses are always refused.
- **Secrets at rest.** Target credentials and SSH keys, request-collection secrets, AI provider
  keys, AI request-template and header secrets, and the raw headers and bodies recorded in the
  HTTP archive are encrypted with one key generated on first start and kept as an owner-only file
  in the results directory on the host. Anyone who can read that file can decrypt them, so protect
  the host accordingly. Backups leave the key out by default (`backup --include-key` adds it), so
  keep `results/.credential_enc.key` separately: a backup restored without it keeps its scans and
  findings but cannot decrypt the stored secrets.
- **Raw HTTP archive export.** Verbatim HAR (captured credentials included) is available by
  default only while the API is published on loopback; a LAN or tailnet deployment must opt in
  with `SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1`, and `0` disables it everywhere.
  Loopback describes the listener, not access through a reverse proxy or tunnel; the HAR gate
  cannot detect that forwarding. Set `SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=0` when forwarding the API
  beyond the local host, and authenticate and restrict access at the proxy or tunnel.
- **Datastores** (PostgreSQL, Redis, optional MinIO) bind to loopback and use generated passwords.

Hardening ideas, and reports that help us narrow these boundaries (for example a scoped Docker
socket proxy, non-root workers, or optional API authentication), are welcome through the same
private channel or as a feature request.
