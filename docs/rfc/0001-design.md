# RFC 0001: linux-hardening-auditor design

- **Status:** Accepted for M1
- **Author:** EquinoxWN
- **Created:** 2026-11-11

## Problem

Most Linux servers run with defaults or one-off changes that nobody checked against a baseline:
root logins over SSH, `NOPASSWD` sudo rules left by cloud-init, PAM stacks that accept empty
passwords, kernel parameters that forward packets, world-readable `/etc/shadow`, legacy services
still listening. Reading these settings correctly is harder than it looks: sshd keeps the *first*
value it reads and reads `Include` files in place, so a drop-in can silently override the main
file; sudo skips include-dir files whose names contain a dot; PAM files differ between Debian and
RHEL families.

Users: system administrators and platform or security engineers who look after a handful to a few
hundred Linux hosts and want a readable, reviewable baseline check without installing an agent.

### Critical-to-quality measures (Define)

| CTQ | Target for M1 | How it is checked |
|---|---|---|
| Correct verdicts on known configurations | 100% of planted weaknesses found, 0 false failures on a hardened tree | End-to-end tests on three fixture trees with the exact expected failing set |
| Effective value, not the first match in one file | sshd first-value-wins, in-place `Include`, `Match` not global; sudo include rules | Parser tests, including a randomised comparison with a naive model |
| Never changes the audited host | 0 writes; only `cat`, `stat`, `ls`, `systemctl list-units` | Code review, the SSH command tests, read-only `Host` interface |
| Rules are data, validated before use | Every malformed rule rejected with a reason | 18 rule tests, `lha rules validate` in the local check |
| Failure is visible | A read failure becomes an `error` finding and exit 3, never a pass | Tests for permission errors, timeouts and bounded retries |

## Goals

- M1: read SSH, sudo, PAM, sysctl, file permission and running-service configuration from a
  fixture tree, the local Linux host, or a remote host over SSH.
- M1: each control is a YAML rule with an id, a check, a severity, a rationale and a fix.
- M2: a host score and a plain-language report; fixes generated as Ansible snippets for review.
- M3: exceptions with a reason and an expiry date; Vagrant lab VMs (Ubuntu, Rocky) audited before
  and after hardening and compared with Lynis.

## Non-goals

- Changing any host. The auditor reads; fixes are text for a person to review (M1) and generated
  files for review (M2), never applied by the tool.
- Being a complete CIS benchmark implementation. The rules are CIS-style controls, not certified
  CIS content, and do not carry CIS section numbers.
- An agent, a daemon or a hosted service.

## Design

```
rules/*.yaml --load + validate--> Rule(id, title, severity, rationale, fix, Check)
                                                              |
Host (read-only) <--------------- Check.evaluate(host) <------+
  TreeHost.fixture(dir)   files from dir, modes from .lha-meta/stat.tsv,
                          services from .lha-meta/services.txt
  TreeHost.local()        files and os.stat from /, services from systemctl (Linux only)
  SshHost(target)         ssh -o BatchMode=yes: cat, stat -c, ls -1A, systemctl list-units
                                                              |
                         Finding(status: pass | fail | not_applicable | error, evidence)
                                                              |
                         text table, JSON report (atomic write), exit code 0 / 1 / 2 / 3
```

- **Host interface.** Four read operations: `read_text`, `stat`, `list_dir`,
  `running_services`. Every path is validated (absolute, safe characters, no `..`); the tree host
  refuses anything that resolves outside its root (symlinks and junctions included); files over
  1 MiB are refused; command output is read incrementally and the process is killed once it
  passes 1 MiB.
- **Fixture trees.** A directory stands in for `/`. Windows cannot hold Linux modes, owners or a
  running systemd, so each fixture records them the way they would be captured on a host: a
  `stat -c '%a\t%u\t%g\t%n'` manifest and `systemctl list-units` output. The same parser reads
  the captured output and the live output.
- **SSH.** The system `ssh` client in batch mode (no password prompts), one command per read,
  a per-call timeout, retries only on transport failures (exit 255 or timeout) with exponential
  backoff, at most 5 retries. The target is validated so it cannot start with `-` and become an
  ssh option; every path is shell-quoted. See [ADR 0002](../adr/0002-system-ssh-client-and-read-only-host.md).
- **Check kinds** (six, declarative): `sshd_option`, `sysctl`, `file_mode`, `pam_module`,
  `sudoers`, `services_not_running`. Rules cannot run commands. See
  [ADR 0003](../adr/0003-declarative-check-kinds.md).
- **Parsers follow the daemons.** sshd: keywords case-insensitive, first value wins, `Include`
  globs expanded in lexical order and read in place, options after `Match` are not global, sshd's
  built-in default used when unset. sudo: `#include`/`@include`, `#includedir`/`@includedir` (relative paths resolve against the
  including file's directory; `%h` is reported as unsupported)
  skipping names with `.` or ending in `~`, last `Defaults` wins, `!` negates, scoped Defaults and
  aliases are not global (but a scoped `!authenticate` counts as `NOPASSWD`; the binding list is
  split by sudo's grammar, trailing comments are stripped (`#` before `-?\d` is a uid, not a
  comment), `NOPASSWD` is also checked before comment stripping, and any `!authenticate` token the parse
  misses is flagged to be safe); Defaults items are
  split respecting double quotes and backslash escapes. PAM: bracketed controls, `-` prefixed types, module basename.
- **Outcomes.** `not_applicable` when the subject is absent (no sshd, no gshadow, no such sysctl);
  `error` when it cannot be read. Exit code: 0 clear, 1 at least one failure, 2 bad input or rules,
  3 at least one read error.

## Alternatives considered

| Option | Why not (yet) |
|---|---|
| Wrap Lynis or OpenSCAP and parse their output | Lynis is shell with its own control set and scoring; OpenSCAP needs SCAP content and an `oscap` binary on each host. Neither gives small, reviewable YAML rules with the exact evidence line. Lynis stays the comparison point for M3. |
| Ansible facts plus `assert` tasks as the check engine | Needs Ansible on the control node for every audit and turns each control into a playbook task; verdicts would depend on Ansible's fact gathering. Ansible is the right output format for fixes (M2), not for reading. |
| Paramiko (in-process SSH) instead of the `ssh` client | A dependency with its own host-key and agent handling; the system client already honours the user's `~/.ssh/config`, agent, jump hosts and known_hosts. Trade-off in ADR 0002. |
| Python expressions or shell commands inside YAML rules | Most flexible, but a rule file becomes code that runs as root on every audited host. Declarative kinds keep rules reviewable by non-programmers (ADR 0003). |

## Measurement plan

- M1 (done, see [docs/results/m1.md](../results/m1.md)): test counts, exact verdict sets on three
  fixture trees, hand mutation score, lint, types and dependency audit; a read-only audit of the
  GitHub Ubuntu runner in CI (not yet run).
- M3: before/after scores on Ubuntu and Rocky Vagrant VMs, and agreement with Lynis on the
  overlapping checks (share of controls where both tools agree).

## Milestones

- **M1:** The auditor reads configuration (SSH, sudo, PAM, sysctl, file permissions, running services) locally or over SSH. Each control is a YAML rule with a check, severity, rationale and fix.
- **M2:** Hosts get a score and a report explaining each failed control in plain language. Fixes are generated as Ansible snippets to review and apply, never changed silently.
- **M3:** Exceptions are recorded with a reason and an expiry date. Vagrant lab VMs (Ubuntu and Rocky) are audited before and after hardening and compared with Lynis.

## Risks and open questions

- Fixture trees can drift from real distributions. Mitigation: the CI `live` job audits a real
  Ubuntu runner; M3 audits real Ubuntu and Rocky VMs.
- sshd `Match` blocks are not evaluated, so a setting that applies only to some users or
  addresses is not reported. `sshd -T` on the host would give the exact effective values but needs
  root and a running sshd binary; considered for M2 as an optional source.
- Reading `/etc/sudoers` and `/etc/shadow` metadata needs root on most hosts; without it the
  affected rules report `error`, not `pass`.
- Paths with spaces are rejected by design; none of the shipped rules need them.
