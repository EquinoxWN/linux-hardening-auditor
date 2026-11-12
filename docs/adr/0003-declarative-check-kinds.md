# ADR 0003: Rules use a fixed set of declarative check kinds, never code

- **Status:** Accepted

## Context

Each control is a YAML rule (M1). The check inside a rule could be a free-form shell command or
Python expression, which covers anything, or one of a fixed set of kinds whose parameters are
data (`sshd_option`, `sysctl`, `file_mode`, `pam_module`, `sudoers`, `services_not_running`).

Audits often run as root, over SSH, on many hosts. A rule file that holds commands is code that
runs with those rights, and reviewing a rule then means reviewing a program.

## Decision

- Six check kinds, each with a strict schema: unknown keys, missing keys, wrong types, unsafe paths
  and malformed unit or sysctl names are rejected when the rules load, before any host is read.
- Rule files are loaded with `yaml.safe_load` (no Python object tags), capped at 256 KiB, and
  rule ids must be unique across files.
- Knowledge of how each daemon reads its configuration lives in the parsers, once, not in each rule.

## Consequences

- Good: a reviewer reads a rule as data; a new control in an existing area is a few lines of YAML.
- Good: the semantics that are easy to get wrong (sshd first value wins, sudo includedir skipping)
  are tested once in the parsers and shared by every rule.
- Cost: a control that needs a new kind of evidence (for example auditd rules or mount options)
  needs a new check kind in Python and its tests. That is deliberate: such a change gets code review.
