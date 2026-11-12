# ADR 0002: Read hosts through a read-only interface, and reach remote hosts with the system ssh client

- **Status:** Accepted

## Context

M1 must read the same settings from three places: a fixture tree (the only source used on the
author's Windows machine), the local Linux host, and a remote host over SSH. The tool must never
change what it audits, and a remote audit must not hang or retry forever.

For SSH there are two practical choices: Paramiko (an in-process SSH library) or the OpenSSH
`ssh` client run as a subprocess.

## Decision

- Checks see only a `Host` with four read operations: `read_text`, `stat`, `list_dir` and
  `running_services`. There is no write operation, so no check can change a host.
- `SshHost` runs the system `ssh` with `BatchMode=yes` and `ConnectTimeout`, one command per read
  (`cat`, `stat -c '%a %u %g'`, `ls -1A`, `systemctl list-units`), each behind `test -f/-e/-d` so a
  missing path is exit 3, distinct from a failure. Exit 255 or a timeout is retried with backoff
  (0.5 s, 1 s, ...), at most 5 retries; any other non-zero exit is an error at once.
- The target is checked against `[user@]host` and placed after `--`, so it cannot be read as an
  ssh option (for example `-oProxyCommand=...`); paths are validated and shell-quoted.

## Consequences

- Good: no SSH dependency; the user's `~/.ssh/config`, agent, jump hosts and `known_hosts` apply
  unchanged; host-key checking stays OpenSSH's job.
- Good: the fake runner in the tests drives every branch (quoting, retries, give-up, oversized
  output) without a network.
- Cost: one process and one round trip per file. An audit of 29 rules makes a few dozen ssh calls;
  connection multiplexing (`ControlMaster` in the user's ssh config) removes most of the cost, and
  batching reads into one remote script is an M2 option.
- Cost: the real SSH path is not exercised on the author's machine (no reachable Linux host);
  only the fake-runner tests run locally.
