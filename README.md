# CYBERDELIA: Container Security Assessment and Hardening

A consultancy-style assessment and remediation of a deliberately vulnerable
three-tier Docker application, produced as coursework for a postgraduate
Cloud Infrastructure and Operations module (marked 93/100). This repo holds
the sanitised writeup and the policy-as-code layer. The full technical
report (findings register, threat model, CI/CD design, cost model, incident
response playbook) is summarised below.

> **Scope note.** This repo contains the security analysis, the OPA/Rego
> policy gate, and the architecture documentation. The hardened
> `docker-compose.yml`, Dockerfiles, and CI workflow referenced throughout
> are not included yet. Drop your own hardened build files into
> `implementation/` (see **Adding the implementation files** below) to make
> the repo fully runnable. The writeup and policy file stand on their own
> either way.

## Executive summary

The prototype is competent application development running on unsafe
infrastructure and cannot be deployed as supplied. Of 23 weaknesses found,
6 individually let an anonymous internet user reach remote code execution,
and 2 escalate from container to host. Three fixes carry almost all the
value: remove `--privileged`, stop publishing ports that don't need
publishing, and stop putting secrets in image layers.

| Severity | Count | Representative findings |
|---|---|---|
| Critical | 6 | Docker API exposed on 2375, `--privileged` database, SSH `root:toor` baked in, trust auth from `0.0.0.0/0`, superuser app role, stored template injection |
| High | 8 | SQL injection, secrets baked into an image layer, `debug=True`, full env dump on an unauthenticated route, admin function reachable on GET, EOL Python 3.6, EOL PostgreSQL 11, every process running as root |
| Medium | 6 | World-writable app code (`chmod -R 777`), stored XSS, no CSRF control, obfuscated `exec()` call, no resource limits, no data persistence |
| Low | 3 | Server version disclosure, unused dependency, no `.dockerignore` |

## Method

The review covered the whole archive: reading every file, building and
running the stack, and inspecting the live containers. That last step
mattered. Two of the most significant findings are invisible from source
and only appear at runtime (see **Verifying claims against the running
system** below). Findings are classified with MITRE's CWE, mapped to the
CIS Docker Benchmark and NIST SP 800-190, and scored with CVSS v3.1.

## What was wrong

**The build process performed a deployment instead of defining one.**
The original stack was brought up by imperative shell commands wired into
a Makefile: a 5-flag `docker run` invocation typed by hand, whose failures
were silenced (`-` prefixes telling `make` to ignore errors) and whose
readiness check was a `sleep 10`. Posture depended entirely on which flags
someone remembered to type that day. Nothing made a missing `cap_drop` or
a stray `--privileged=true` visible in review.

**Two containers, one flat network, five open ports.** `cyberdelia_web`
ran nginx, a Flask dev server, and an OpenSSH daemon, three processes, all
as UID 0. `cyberdelia_db` ran PostgreSQL 11 with `--privileged`, all ~40
Linux capabilities, no seccomp, no AppArmor, and unrestricted `/dev`
access. The Docker Engine API itself was exposed on port 2375 with no
authentication: a single unauthenticated HTTP request is enough to start
a container that mounts the host's root filesystem and get persistent
root on the host, no container escape required.

**Application-layer weaknesses made the infrastructure holes reachable.**
The most serious was a stored server-side template injection: user input
was concatenated directly into a Jinja2 template *source* rather than
passed in as data, so any visitor could post template syntax and have it
evaluated for every subsequent viewer of the page. A documented sandbox
escape chains this straight to arbitrary Python execution. Alongside it:
unparameterised SQL reaching a database role with `SUPERUSER` and `GRANT
ALL`, a debug console left enabled in a public deployment, an
unauthenticated endpoint that dumped every environment variable
(passwords included), and an unauthenticated admin function reachable
with a plain `GET`.

## Verifying claims against the running system

Two findings could not have been caught by reading the repository, because
the repository actively misrepresented the running state:

- A "hardened-looking" `pg_hba.conf` was committed to version control and
  copied to a path PostgreSQL never reads (`/postgres/` instead of
  `$PGDATA`, which doesn't exist at build time). Both files were inert.
  The server ran on stock trust-authentication defaults the whole time,
  provable only by querying the live server (`SHOW hba_file;`).
- An nginx directive (`server_tokens on`) was commented as "required for
  keepalive to work, do not disable." This is false: `server_tokens` only
  controls the version string in the `Server` header, and keepalive is a
  separate directive entirely. The comment protected a setting that
  handed an attacker exact version information for free.

The lesson generalises: a fix only counts if it changes the running
system, not the file that describes it. This is why the remediation below
leans on `docker inspect`-level verification rather than diffing config
files.

## The hardened architecture

The remediation replaces the hand-run Makefile with a single
`docker-compose.yml`. Compose is declarative: `up` converges toward the
described state rather than accumulating side effects, and a shared YAML
anchor applies the security baseline to every service at once, so
weakening a container now requires *writing down* an exception rather than
just forgetting a flag:

```yaml
x-hardening: &hardening
  security_opt: [no-new-privileges:true]
  cap_drop: [ALL]
  pids_limit: 200
```

Six independent layers of defence, each individually enforced and each
independently verifiable against the live containers:

| Layer | Prototype | Hardened |
|---|---|---|
| **Network** | One flat bridge, 5 ports published | Two networks, backend marked `internal: true`, database publishes nothing, only 127.0.0.1:8052 reaches the host |
| **Identity** | UID 0 for every process | Dedicated non-root system account, `nologin` shell, set in both the Dockerfile `USER` and Compose `user:` |
| **Kernel** | `--privileged`, seccomp and AppArmor off, ~40 capabilities | `cap_drop: ALL` everywhere, database adds back exactly 5 named capabilities to initialise its data directory, `no-new-privileges:true` throughout |
| **Filesystem** | `chmod -R 777`, writable everywhere | `read_only: true` on app and proxy, code copied root-owned with world-write bits stripped, `/tmp` mounted `noexec` |
| **Data** | App role was `SUPERUSER` with `GRANT ALL` | Role holds `SELECT`/`INSERT` on one table only, `scram-sha-256` auth restricted to the internal subnet, `PUBLIC` privileges revoked |
| **Application** | SQLi, stored SSTI, stored XSS | Parameterised queries, pre-compiled autoescaped templates, signed double-submit CSRF token |

Image hardening cut the attack surface sharply. The base moved from
`python:3.6` (end-of-life since December 2021, 966 MB, 313 CRITICAL/HIGH
Trivy findings) to `python:3.12-slim-bookworm` behind a multi-stage build
(179 MB, 6 CRITICAL/18 HIGH, all inherited, unpatched Debian base-OS
packages with no upstream fix and none reachable from the application's
request path). Incidental attacker tooling (`nmap`, `netcat`, `telnet`, a
compiler) that had been installed deliberately "to poke prod sometimes"
was removed entirely.

## Policy as code

Hardening only holds if something stops it from being deleted. A future
change under deadline pressure could remove `read_only: true` in one
keystroke, and nothing in a purely manually-reviewed build would object.
[`policy/compose.rego`](policy/compose.rego) is the enforcement mechanism:
an [Open Policy Agent](https://www.openpolicyagent.org/) policy evaluated
against the fully-resolved `docker compose config` output (what will
actually be applied, not the template), wired into CI as a pull-request
gate:

```yaml
- name: Policy gate
  run: |
    docker compose config --format json > /tmp/resolved.json
    conftest test --policy policy/ /tmp/resolved.json
```

The policy denies a pull request that reintroduces `--privileged`, drops
`no-new-privileges`, removes `read_only` from a non-database service, lets
a service run as root, publishes a secret through an environment
variable, or publishes a port from anything other than the proxy on
anything other than loopback. A security decision becomes a security
invariant: the same regression is caught the same way whether it's a
careless edit or a deliberate one, and the enforcement history lives in
the CI log rather than in anyone's memory.

Enforcement runs at three layers, cheapest first: pre-commit (`hadolint`
on Dockerfiles, `gitleaks` on the diff, about 2 seconds locally), pull
request (the Rego policy above via Conftest, plus Checkov, about 20
seconds, blocks the merge), and pre-deployment (Trivy and `pip-audit` as
build gates that fail the build on any CRITICAL or HIGH finding). A scan
that reports without blocking is a report, not a gate.

## Production deployment strategy

The hardened build is sufficient for a demonstration on a single Docker
host but insufficient for production, where one host is one point of
failure. The recommended target is AWS ECS Fargate, chosen over EC2 +
Docker (reproduces the host-hardening burden this report exists to solve),
Elastic Beanstalk (re-platforms an artefact that's already a correctly
built OCI image), and EKS (a large amount of control-plane and
Kubernetes-security-model machinery to secure for a two-service
application). Fargate removes the host OS from the client's
responsibility entirely: no patching, no Docker daemon, no SSH server
that should never have existed in the first place.

The production architecture spans three Availability Zones with no single
point of failure: an internet-facing ALB in public subnets, Fargate tasks
in private subnets on ARM64 Graviton, and Multi-AZ RDS for PostgreSQL with
automatic failover in 60 to 120 seconds. Supporting services (Secrets
Manager, ECR, CloudWatch Logs) are reached over VPC endpoints, never the
public internet. Deployment goes commit, static analysis, build, scan
gate, sign and push, blue/green deploy, verify, all in GitHub Actions,
authenticated via OIDC so no long-lived AWS credential exists in the
repository at all (the same principle that removed `.env` from the image,
applied one level up). Estimated steady-state cost after the
optimisations discussed in the full report is approximately $243/month.

## Verification, not assertion

Every factual claim about the running system in the full report is
reproducible: a `make evidence` target regenerates the complete evidence
set (image digests before/after, `docker history` output showing no baked
secrets, vulnerability scan deltas, a live process listing proving the
application runs as an unprivileged UID), and a regression suite
(`tests/test_security.py`, 32 assertions) fails the build if any fixed
weakness (SQL injection, template injection, missing CSRF protection) is
ever reintroduced.

## Adding the implementation files

This repo currently holds the writeup and the policy gate. To make it a
runnable hardened build, add:

- `docker-compose.yml`: the declarative three-container stack described
  above, using the `x-hardening` anchor
- `webserver/Dockerfile`, `dbserver/Dockerfile`: multi-stage, minimal
  base, non-root `USER`
- `tests/test_security.py`: the regression suite
- `.github/workflows/`: the CI/CD pipeline (static analysis, build, scan
  gate, sign, deploy, verify)

and check them against the policy in `policy/compose.rego` with:

```bash
docker compose config --format json > /tmp/resolved.json
conftest test --policy policy/ /tmp/resolved.json
```

## Standards referenced

- MITRE CWE Top 25 (2024)
- CIS Docker Benchmark v1.7.0
- NIST SP 800-190: Application Container Security Guide
- OWASP Top 10:2021

---

*Assessment methodology, findings, and remediation design are the
author's own work for a university module. Identifying and administrative
details (student ID, submission metadata) have been removed for public
publication; this doesn't affect the technical content above.*
