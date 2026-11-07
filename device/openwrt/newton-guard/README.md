# newton-guard

`newton-guard` provides a reboot-safe, device-side rollback window for OpenWrt
UCI files. It protects non-hidden entries in `/etc/config` only.

## Install

Copy `newton-guard` to `/usr/libexec/newton-guard` and `newton-guard.init` to
`/etc/init.d/newton-guard`, chmod both 0755, then run:

```sh
/etc/init.d/newton-guard enable
/usr/libexec/newton-guard status
```

The final command prints exactly `idle`.

## Commands and output

- `arm TXN TIMEOUT` prints `armed <txn> <deadline> <timeout>`. The snapshot
  must be consistent across files: arm copies and hashes the live config into
  a candidate LKG, then re-hashes the complete live set in one pass. Only
  names and md5 hashes are compared; modes and owners are not. If anything
  changed, the candidate is discarded and one fresh snapshot is taken; if the
  live set changes again, arm refuses with `refused config-changed <name>`
  (the file that differed, `-` if none can be named): exit 3, no `pending`
  written, no timer started, no LKG directory left. The same refusal covers a
  file that stops being a regular non-symlink file, or a copy whose hash
  diverges, while it is being copied.
- `confirm TXN` prints `confirmed <txn>`.
- `restore REASON` prints `restored <txn> <reason>` or `nothing-pending`.
- `recover` and `recover restore TXN` are operator-only commands for the
  console; the caller protocol never runs them. They clear a guard that no
  longer moves on its own: a corrupt `pending` (restore fails with
  `failed - pending-corrupt`, `confirm` refuses `pending-corrupt`, `arm`
  refuses `failed -`), or a valid `pending` together with a `failed` file (a
  permanent failure such as `lkg-corrupt`, `lkg-unsealed`, `lkg-missing`,
  `verify-failed` or `boot-loop`: `tick`, `boot` and the timer stand down and
  `arm` refuses `failed <txn>`). A valid `pending` is live only while no
  `failed` file exists; both commands refuse a live one (`refused pending
  <txn>`, exit 3) and change nothing. Otherwise both move the old state
  (`pending`, `failed`, `boot_attempts`, `restore_attempts`) into
  `quarantine/recover-<YYYYmmddTHHMMSS>`.
  - `recover` then returns the guard to `idle` and prints `recovered <dir>`.
    It abandons the rollback: the live config stays as it is. With no
    `pending` it prints `nothing-to-recover`, exit 0.
  - `recover restore <txn>` first preflights the LKG of `<txn>` exactly like a
    restore (`refused lkg-missing <txn>`, `refused lkg-unsealed <txn>`,
    `refused lkg-corrupt <txn>`, exit 3, nothing changed), so after a
    permanent failure it can restore any other sealed LKG. It then quarantines
    the state, writes a fresh expired `pending` for `<txn>`, runs a normal
    restore (so crash recovery, retries and reload behave the same; after an
    I/O failure the fresh `pending` stays and `tick`, `boot` or `restore
    <reason>` retry it) and prints `restored <txn> recover`. If it is
    interrupted after writing that expired `pending` (it reads `<txn> 0 ...`),
    running the same `recover restore <txn>` again resumes it: nothing is
    quarantined a second time, the retry budget starts fresh, and the earlier
    recover directory stays protected from pruning. Any other valid `pending`
    without a `failed` file (another transaction, or a deadline other than 0)
    is live and is refused.
  - A failed quarantine or pending write prints `error recover-failed`, exit
    1. `recover restore BAD` prints `error bad-txn`, exit 2.
- `retry <txn> <why> <n>` is printed by `restore`, `tick`, and `boot` when a
  restore step failed with an I/O error and will be retried; `n` is the
  failed attempt number. `restore` and `tick` exit 1, `boot` exits 0.
- `status` prints `idle`, `pending <txn> <seconds_left>`,
  `restored <txn> <reason>`, or `failed <txn> <why>`. If non-hidden entries
  whose names are not UCI package names exist, it then prints
  `skipped <escaped_name> ...`; bytes outside `[A-Za-z0-9._-]` use `\xHH`
  escapes with lowercase hex.
- `boot` prints the applicable status/restore/failure line and always exits
  0. `tick` prints a pending, restore, or failure line. `timer` is the
  internal polling process run under procd and prints nothing.

Exit 0 means success (including `nothing-pending`), 1 means an internal error
or failed restore, 2 means usage/validation error, and 3 means state refused
the request. Every invocation except `timer` emits exactly one stdout line,
unless `status` also needs to emit its `skipped` line.

Validation/error lines are `error bad-root`, `error bad-txn`,
`error bad-timeout`, `error bad-reason`, `error df-failed`,
`error scratch-failed`, `error pending-write-failed`, `error pending-mismatch`,
`error lkg-write-failed`, `error confirm-failed`, `error recover-failed`, and
`error usage`. `error scratch-failed` means `arm` could not make its scratch
directory; nothing was changed. `error confirm-failed` means `confirm` could
not remove `pending`; the transaction remains armed and its counters and
timer are left untouched.
Refusal lines are `refused failed <txn>`, `refused pending <txn>`,
`refused pending -`, `refused boot-hook-disabled`,
`refused bad-config-entry <name>` (a directory or symlink whose name matches
`[A-Za-z0-9_-]+`), `refused no-config`,
`refused low-space <available_kb> <needed_kb>`, `refused txn-used`,
`refused config-changed <name>`, `refused timer-not-running`,
`refused nothing-pending`, `refused pending-corrupt`,
`refused txn-mismatch <pending_txn>`, and `refused expired`. Restore
failure/status words are `failed - pending-corrupt`,
`retry <txn> verify-failed <n>`, and
`failed <txn> lkg-missing|lkg-unsealed|lkg-corrupt|verify-failed|boot-loop`.

## Caller protocol

The on-router program (`/usr/libexec/newton/newton-router`) is the only caller
in production. It arms the guard with `arm <SID> <T+30>` just before the
program calls `ubus call uci apply` (rpcd's apply). The window is T+30 so
rpcd's rollback finishes first in the normal case (design 6.1). The program
then verifies from NEW sessions, confirms rpcd first, then confirms the
guard. Never auto-confirm after a controller restart. A lost confirm reply
is settled by `status` (which `tick`s the guard first and reports one of
`applied-pending-confirm`, `confirmed`, `rolled-back`, `inconsistent`, `gone`)
or by `abort` (which calls `uci rollback` and `newton-guard restore abort` to
settle both layers; design 6.4, 6.5).

## State and recovery

Persistent state is below `/etc/newton`:

- `pending` — `<txn> <deadline> <boot_id>`, written by `arm`; removed by
  `confirm` and by a successful restore; moved to quarantine by `recover`.
- `failed` — `<txn> <why>`, written when automatic recovery gives up without
  clearing `pending`; cleared by `confirm`, cleared by the next `arm` or
  `boot` when no `pending` exists, moved by `recover`.
- `boot_attempts`, `restore_attempts` — `<txn> <n>` attempt counters.
  `boot_attempts` counts interrupted boots; `restore_attempts` counts failed
  restore I/O attempts. A line for another transaction (or an invalid line)
  counts as 0. A successful restore removes `boot_attempts` and `failed`
  before `pending`, then removes `restore_attempts` immediately after
  `pending`; `confirm` removes the counters right after `pending`; a manual
  `restore`, `arm` and `boot` clear leftovers (`arm` and `boot` only when no
  `pending` exists); `recover` moves both to quarantine.
- `last_revert` — `<txn> <reason>` of the last completed restore; removed by
  the next `arm`.
- `lkg/<txn>/` — the sealed snapshot: config copies plus `.seq` (a recency
  counter), `.manifest` (`<md5>  <name>` rows, sorted), and `.seal`, a
  one-line seal `<sha256-of-.manifest> <count> <name1> ... <nameN>` written
  atomically before `.manifest` is renamed into place, so an existing
  `.manifest` always implies a complete, sealed LKG. At arm the guard
  re-verifies the seal (manifest bytes, row count, name list, directory
  entries, per-file hashes) before publishing `pending`; any LKG write or
  verify failure removes the LKG directory and prints
  `error lkg-write-failed`. Before restore touches any live file the seal is
  re-checked: a missing, symlinked or unreadable `.seal` fails with
  `lkg-unsealed`, and any mismatch (wrong sha256, count or names, empty or
  truncated manifest, extra LKG entry) fails with `lkg-corrupt`; both are
  permanent failures (`failed` written at once, nothing moved, nothing
  quarantined, `pending` kept). An LKG made by an older guard (no seal) is
  refused with `lkg-unsealed`, so the guard must not be upgraded while
  armed. Old LKG directories are pruned: only the newest 5 kept, incomplete
  ones removed unless their transaction is pending or failed.
- `quarantine/<name>/` — entries displaced during restore (or
  `quarantine/recover-<timestamp>/` from `recover`), each with a `.seq`
  counter (one plus the highest existing counter at creation, so ordering
  never depends on the wall clock or mtimes; a directory without a valid
  `.seq` counts as the oldest). After every `confirm` and restore the
  quarantine is pruned, best effort: the newest 5 directories are kept (the
  active transaction's and the directory a `recover` just wrote are never
  removed but still count toward the 5), and then, oldest first and skipping
  those protected directories, entries are removed until the total is at
  most 256 KiB (`du -sk`, never file reads). Pruning can never make a
  `confirm` or restore fail, and logs each removal to `guard.log`.
- `guard.lock` — the state lock. Every state-changing command opens it with
  `exec 9>>` and takes `flock 9`; it is never written (so no flash wear). It
  lives here, not in `tmp`, because `/etc/newton` is mode 700 and root-owned:
  a local non-root user (a compromised `dnsmasq`, say) can pre-plant a file or
  a symlink at a fixed name under the world-writable `tmp`, but can neither
  create nor hold this one. Nothing that lists or seals the state directory
  counts its entries, so the file cannot change a manifest, a seal or a
  count.
- `guard.log` — the bounded event log, trimmed to the last 100 lines when it
  grows past 16 KiB.

Scratch files live in a private mode-700 directory made by `mktemp -d` below
`tmp` (so `/tmp/newton-guard.XXXXXX` on the device) and removed when the
command ends, also when SIGHUP (a dropped SSH session), SIGINT or SIGTERM
stops it (BusyBox ash skips its exit trap on a signal, so the guard traps
these three; the trap runs once the command the guard is currently waiting
for has returned, and the guard exits 1); a run killed with SIGKILL can
still leave one small directory in `tmp` until reboot (`tmp` is RAM). After
the lock moved into the state directory, nothing with a fixed name is left in
`tmp`.

`failed` means automatic recovery stopped without clearing `pending`. I/O
failures while restoring (a copy, move, quarantine or verification step that
fails after the LKG preflight checks pass) are transient: the guard removes
the partial `.newton-tmp.*` files, keeps `pending`, records the attempt in
`restore_attempts`, prints `retry <txn> verify-failed <n>`, and tries again
on the next `tick`, `boot`, or manual `restore`. The timer waits 15 seconds
before each retry of a failed restore attempt (including its first tick after
a `boot` that left a retry outstanding), so the three attempts span at least
30 seconds; the first attempt is made at once, and `tick`, `boot`, `restore`
and `recover restore` still make one attempt per call without waiting. After
3 failed attempts the failure becomes permanent (`failed` is written). A
manual `restore` starts a fresh budget of 3 attempts. Preflight failures
(`pending-corrupt`, `lkg-missing`, `lkg-unsealed`, `lkg-corrupt`) are
permanent immediately. When the state directory cannot be written
(read-only, full, or wrong permissions) the guard can neither count
attempts in `restore_attempts` nor record `failed`, so the timer waits 15
seconds after every failed attempt and keeps trying until a restore
succeeds or the directory can be written again (the 3-attempt limit
applies from then on); `pending` stays in place meanwhile.

There are two operator exits: `confirm <txn>` accepts the current config,
while `restore <reason>` retries the LKG and keeps rollback semantics. A
leftover `failed`, `boot_attempts` or `restore_attempts` without `pending` is
ignored by status and cleared by the next `arm` or `boot`.

The procd instance is named `timer`, uses `respawn 3600 1 5`, polls once per
second, and stops itself after pending state clears or failure is recorded.
The init script uses `START=09`: S09 runs after S00 but before S10boot, so the
LKG is restored before Wi-Fi detection, uci-defaults, boot's `reload_config`
snapshot, and every service that reads `/etc/config`.

## Tests

Tests set `NEWTON_GUARD_ROOT` to an absolute fake router root.
`NEWTON_GUARD_CRASH_AT=N` is honored only when that root is set and kills the
guard at durability point N. The fake root also wraps `cp`, `mv`, `sync`,
`rm`, `mktemp`, and `sleep` (`rm` is used only for the two guarded `pending` removals,
`mktemp` only for the per-process scratch directory, `sleep` calls of 10
seconds or more are logged but not slept);
control files select always/once failures with optional argument matching, a
`cp` mode that copies only the first 4 bytes and exits 1, `cp` modes
(`cp-hook`, `cp-hook-once`) that run a shell command after a successful
matching copy, an `mv` mode that moves then truncates its target, an `mv`
mode that appends a line after the move, and a `sync` mode that fails only
while a marker path exists. The `rm` wrapper uses the same always/once
failure controls. Every wrapper logs its calls to
`control/<tool>.calls`. Run:

```sh
.venv/bin/python -m pytest device/openwrt/newton-guard/tests -q
```

## Limits

- Only non-hidden `/etc/config` files named with `[A-Za-z0-9_-]+` are
  protected; other names are skipped, never snapshotted, never changed by
  restore, and listed escaped by `status`.
- `valid_timeout` accepts 60..900 s; the on-router program arms it with
  T+30 where T is 60..600, so windows of 90..630 s; the bound was 600
  before RD10.
- Edits made during the armed window are reverted; no copy of reverted
  versions of tracked files is kept, though untracked new validly named
  files are retained in quarantine.
- A uci or LuCI commit that lands while restore is running is overwritten,
  and no copy of it is kept.
- Names matching `.newton-tmp.*` in `/etc/config` are reserved for the guard
  and are deleted by restore and boot.
- A root process can still wedge the guard until reboot by swapping a config
  file for a FIFO at the wrong instant during arm (between the regular-file
  check and the read, in the snapshot or in the final consistency pass); that
  race is not defended. A swap that happens earlier is detected and arm
  refuses.
- The BusyBox on the device must provide `sha256sum` (arm and restore refuse
  without it), `sort`, and `mktemp` (used as `mktemp -d` to make the per-process
  scratch directory). `du` is used only for the quarantine size cap;
  without it the 256 KiB rule is skipped and the 5-directory rule still
  applies. None of this has been verified on a router: the tests ran against
  Ubuntu's BusyBox 1.36.1 with applets preferred.
- A successful `sync` does not prove the data reached flash: the kernel can
  report a write-back error only later, and the arm read-back reads the page
  cache, so a delayed ENOSPC or I/O error after `sync` goes unnoticed.
  BusyBox `sync -f FILE` (FEATURE_SYNC_FANCY) can report such errors; whether
  the device build has it is not verified.
- `scripts/newton-router-setup` installs the guard on the router, and
  `scripts/owrt-change.sh` refuses a change while the guard's state is
  `failed`. The guard has no rpcd plugin. Power-cut behavior during a guard
  write has not been tested on hardware.
