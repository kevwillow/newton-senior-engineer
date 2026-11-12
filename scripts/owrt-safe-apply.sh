#!/bin/sh
# owrt-safe-apply.sh — apply OpenWrt UCI changes with automatic rollback.
# Runs ON the router (BusyBox ash). Push it to /tmp each time; nothing is installed.
#
# Uses the same rpcd mechanism as LuCI's "apply with rollback": changes are staged in a
# private rpcd session, applied with a timer, and reverted automatically unless confirmed.
# The session outlives the SSH connection, so confirm from a NEW connection after the
# change: if the change broke your access, you simply cannot confirm and it rolls back.
#
#   SID=$(owrt-safe-apply.sh stage < changes.uci)    # uci batch on stdin (staging verbs only); prints session id
#   owrt-safe-apply.sh diff    <SID>                  # show staged changes
#   owrt-safe-apply.sh named   <SID>                  # show changes to named nft objects that require a restart
#   owrt-safe-apply.sh confighash                       # "<md5 of file bytes> <file name>" for each config file
#   owrt-safe-apply.sh health-snapshot <SID>            # record running services and fw4 warnings before apply
#   owrt-safe-apply.sh health-check <SID> [after-rollback] # compare current service/fw4 health with the snapshot
#   owrt-safe-apply.sh fwrestart <0|1>                 # restart/recover fw4, given whether it was loaded before apply
#   owrt-safe-apply.sh apply   <SID> [timeout_s]      # default 90s, allowed 60..600
#   owrt-safe-apply.sh status  <SID>                  # staged | applied-pending-confirm | rolled-back | gone
#   owrt-safe-apply.sh confirm <SID>                  # keep the change (run from a fresh connection)
#   owrt-safe-apply.sh abort   <SID>                  # discard staged changes, or roll back now if applied
#
# Rollback covers UCI config only (/etc/config). It does not undo package changes, file edits,
# passwords, reboots, or client-side state (leases, wifi associations) caused by the apply.
# One transaction per router at a time (lock in /tmp/owrt-safe-apply.lock).
# After an automatic rollback the session lingers until its timeout; harmless (tmpfs).
#
# Verified on OpenWrt 25.12.5 (2026-10-03): plain `ubus call uci apply '{"rollback":true}'`
# from a shell returns "Invalid argument"; it only works with a ubus_rpc_session.
set -u

# The helper is installed on the router as /usr/libexec/newton/newton-safe-apply.
# On that path the environment is the router's own: NEWTON_RPCD_ROOT (the
# test-root prefix) is dropped, the way newton-router drops it in production,
# so only the test harness can set it.
if [ "$0" = /usr/libexec/newton/newton-safe-apply ]; then
	unset NEWTON_RPCD_ROOT
fi

SESSION_TIMEOUT=2700
LOCK=${NEWTON_LOCK:-/tmp/owrt-safe-apply.lock}
UPTIME_FILE=${NEWTON_UPTIME_FILE:-/proc/uptime}
# The rpcd session folders. The rpcd change d99f703 stopped naming a session's
# folder after the session id: the folder is now uci-<32 hex>, a random
# value no ubus call returns. NEWTON_RPCD_ROOT is the test-root prefix
# (empty on the router); the folder Newton records is always the canonical
# /var/run/rpcd one.
RPCD_ROOT=${NEWTON_RPCD_ROOT:-}
die()   { echo "ERROR: $*" >&2; exit 1; }
uptime_s() {
	IFS=' ' read -r _up _ < "$UPTIME_FILE" || return 1
	_up=${_up%%.*}
	case "$_up" in ''|*[!0-9]*) return 1 ;; esac
	printf '%s\n' "$_up"
}
# rpcd_dir SID: the canonical folder rpcd keeps a session's changes in.
rpcd_dir() { echo "/var/run/rpcd/uci-$1"; }
# rpcd_path CANONICAL: the folder as this host sees it.
rpcd_path() { echo "$RPCD_ROOT$1"; }
# valid_dir PATH: the path is one of rpcd's own session folders.  The WHOLE
# path must be /var/run/rpcd/uci- and exactly 32 hex characters, and nothing
# else: no "..", no extra component, no trailing slash.
valid_dir() {
	_vd_hex=${1#/var/run/rpcd/uci-}
	[ "$_vd_hex" != "$1" ] || return 1
	[ "${#_vd_hex}" -eq 32 ] || return 1
	case "$_vd_hex" in *[!0-9a-f]*) return 1 ;; esac
	return 0
}
# recorded_dir SID: the folder this transaction recorded, or nothing when it
# has no record (a transaction staged by an older Newton). Returns 1 when the
# record holds a path that is not one of rpcd's own folders: the caller must
# then use no folder at all.
recorded_dir() {
	[ -f "$LOCK/$1.dir" ] || return 0
	_rd=
	IFS= read -r _rd 2>/dev/null < "$LOCK/$1.dir" || _rd=
	[ -n "$_rd" ] || return 1
	valid_dir "$_rd" || return 1
	printf '%s\n' "$_rd"
}
# find_dir SID: the folder rpcd keeps this session's staged changes in.
#
# The folder is found with a marker: one probe section is added to the
# session and taken back out again, and the one delta file that holds the
# probe names the folder. Exactly one file may hold it, and the folder must
# be one of rpcd's own. The probe never reaches /etc/config.
find_dir() {
	_fd_sid="$1"
	_fd_reply=$(ubus call uci add "{\"config\":\"system\",\"type\":\"newton_probe\",\"ubus_rpc_session\":\"$_fd_sid\"}" 2>/dev/null) || return 1
	_fd_section=$(printf '%s\n' "$_fd_reply" | jsonfilter -e '@.section' 2>/dev/null) || return 1
	case "$_fd_section" in
		'' | *[!A-Za-z0-9_]*) return 1 ;;
	esac
	[ "${#_fd_section}" -le 64 ] || return 1
	_fd_hits=$(grep -Fxl "+system.$_fd_section='newton_probe'" "$RPCD_ROOT"/var/run/rpcd/uci-*/system 2>/dev/null) || :
	_fd_count=$(printf '%s\n' "$_fd_hits" | grep -c .)
	[ "$_fd_count" -eq 1 ] || return 1
	_fd_dir=${_fd_hits%/*}
	_fd_name=${_fd_dir##*/}
	_fd_canon="/var/run/rpcd/$_fd_name"
	# the folder is one of rpcd's own: the whole path is the pattern, and
	# it is the one under the root this host sees
	valid_dir "$_fd_canon" || return 1
	[ "$_fd_dir" = "$RPCD_ROOT$_fd_canon" ] || return 1
	ubus call uci revert "{\"config\":\"system\",\"ubus_rpc_session\":\"$_fd_sid\"}" >/dev/null 2>&1 || return 1
	[ -s "$_fd_dir/system" ] && return 1
	printf '%s\n' "$_fd_canon"
}
live()  { ubus call session list "{\"ubus_rpc_session\":\"$1\"}" >/dev/null 2>&1; }
clean() {
	_cd=
	if ! _cd=$(recorded_dir "$1"); then
		_cd=	# the record is not one of rpcd's folders: use no folder at all
	elif [ -z "$_cd" ]; then
		_cd=$(rpcd_dir "$1")	# an old transaction: the folder it used
	fi
	if [ -n "$_cd" ]; then rm -rf "$(rpcd_path "$_cd")"; fi
	rm -rf "$LOCK/$1.applied" "$LOCK/$1.health"
	rm -f "$LOCK/$1.dir"
	[ "$(cat "$LOCK/sid" 2>/dev/null)" = "$1" ] && rm -rf "$LOCK"; :
}
drop()  { ubus call session destroy "{\"ubus_rpc_session\":\"$1\"}" >/dev/null 2>&1; clean "$1"; }
valid_sid() { echo "$1" | grep -qE '^[0-9a-f]{32}$' || die "malformed session id"; }
need_sid()  { [ -n "${1:-}" ] || die "missing session id"; valid_sid "$1"; live "$1" || die "session $1 not found (expired or destroyed)"; }
applied()   { [ -e "$LOCK/$1.applied" ]; }
# The deadline is judged with uptime, not the wall clock: routers without an
# RTC step the wall clock when NTP syncs, while rpcd's rollback timer counts real elapsed time.
expired()   {
	applied "$1" || return 1
	line=$(head -n 1 "$LOCK/$1.applied" 2>/dev/null)
	case "$line" in
		up\ *)
			n=${line#up }
			case "$n" in ''|*[!0-9]*) return 1 ;; esac
			now=$(uptime_s) || return 1
			[ "$now" -gt "$(( n + 5 ))" ]
			;;
		*)
			case "$line" in ''|*[!0-9]*) return 1 ;; esac
			[ "$(date +%s)" -gt "$(( line + 5 ))" ]
			;;
	esac
}

# fw4_first_line FILE: the first line of `fw4 check` output that names a real problem, not a notice that
# health-check itself ignores; if every line is such a notice (or blank), the first output line.
fw4_first_line() {
	[ -s "$1" ] || { echo "no output"; return 0; }
	first=""
	while IFS= read -r fw4_line || [ -n "$fw4_line" ]; do
		[ -n "$fw4_line" ] || continue
		case "$fw4_line" in
			*"is disabled, ignoring section") continue ;;
		esac
		first=$fw4_line
		break
	done < "$1"
	[ -n "$first" ] || first=$(head -n 1 "$1")
	printf '%s' "$first" | tr '\000-\037\177' ' ' | cut -c1-300
}

cmd=${1:-}; shift 2>/dev/null
case "$cmd" in
stage)
	[ -z "$(uci changes)" ] || die "uncommitted CLI changes exist (uci changes) — resolve them first"
	if [ -d "$LOCK" ]; then
		old=$(cat "$LOCK/sid" 2>/dev/null)
		if [ -n "$old" ] && live "$old" && ! expired "$old"; then die "another transaction is open (session $old) — confirm or abort it first"; fi
		[ -n "$old" ] && drop "$old"; rm -rf "$LOCK"   # stale: expired session, or rolled back automatically
	fi
	mkdir "$LOCK" 2>/dev/null || die "could not take transaction lock"
	BATCH=$(cat)
	# only staging verbs; commit/import/revert/export would bypass the rollback
	bad=$(printf '%s\n' "$BATCH" | grep -vE '^[[:space:]]*(#|$)' | grep -vE '^[[:space:]]*(set|add|add_list|del_list|delete|rename|reorder)[[:space:]]')
	[ -z "$bad" ] || { rm -rf "$LOCK"; die "only set/add/add_list/del_list/delete/rename/reorder are allowed, got: $(printf '%s' "$bad" | head -1)"; }
	config_dir=${NEWTON_CONFIG_DIR:-/etc/config}
	before=$(md5sum "$config_dir"/* | md5sum)
	SID=$(ubus call session create "{\"timeout\":$SESSION_TIMEOUT}" | jsonfilter -e '@.ubus_rpc_session') || { rm -rf "$LOCK"; die "session create failed"; }
	echo "$SID" > "$LOCK/sid"
	ubus call session grant "{\"ubus_rpc_session\":\"$SID\",\"scope\":\"uci\",\"objects\":[[\"*\",\"read\"],[\"*\",\"write\"]]}" >/dev/null || { drop "$SID"; die "grant failed"; }
	# the folder rpcd keeps this session's changes in is found with a marker
	# (rpcd d99f703): nothing is staged before it is known
	SDIR=$(find_dir "$SID") || { drop "$SID"; die "could not locate the rpcd session folder"; }
	# the record of the folder is what every later step reads: it must be
	# written and read back, or the stage fails and nothing is staged
	printf '%s\n' "$SDIR" > "$LOCK/$SID.dir" || { drop "$SID"; die "could not record the rpcd session folder"; }
	_rd=
	IFS= read -r _rd < "$LOCK/$SID.dir" 2>/dev/null || _rd=
	[ "$_rd" = "$SDIR" ] || { drop "$SID"; die "could not record the rpcd session folder"; }
	# uci batch exits 0 even when a line fails — the error appears only on stderr, so any stderr rejects the whole batch
	# stdout (add prints the new section name) is discarded: the session id must be the only thing stage prints
	printf '%s\n' "$BATCH" | uci -P "$(rpcd_path "$SDIR")" batch >/dev/null 2>"$LOCK/batch.err"; rc=$?
	if [ "$rc" -ne 0 ] || [ -s "$LOCK/batch.err" ]; then
		msg=$(head -n 3 "$LOCK/batch.err")
		drop "$SID"; die "uci batch rejected the changes (exit $rc), nothing staged: $msg"
	fi
	rm -f "$LOCK/batch.err"
	[ "$(md5sum "$config_dir"/* | md5sum)" = "$before" ] || { drop "$SID"; die "/etc/config changed during staging — investigate before retrying"; }
	[ -n "$(uci -P "$(rpcd_path "$SDIR")" changes)" ] || { drop "$SID"; die "no changes staged"; }
	echo "$SID"
	;;
diff)
	need_sid "${1:-}"
	d=$(recorded_dir "$1") || die "could not locate the rpcd session folder"
	[ -n "$d" ] || die "could not locate the rpcd session folder"
	uci -P "$(rpcd_path "$d")" changes
	;;
named)
	need_sid "${1:-}"
	d=$(recorded_dir "$1") || die "could not locate the rpcd session folder"
	[ -n "$d" ] || die "could not locate the rpcd session folder"
	d=$(rpcd_path "$d")
	ch=$(uci -P "$d" changes firewall) || die "uci changes failed"
	printf '%s\n' "$ch" | sed -n 's/^[-+@^]\{0,1\}firewall\.\([A-Za-z0-9_]*\).*/\1/p' | sort -u | while read -r s; do
		t=$(uci -P "$d" -q get "firewall.$s") || t=$(uci -q get "firewall.$s")
		n=$(uci -P "$d" -q get "firewall.$s.name") || n=$(uci -q get "firewall.$s.name")
		case "$t" in
		zone)
			if printf '%s\n' "$ch" | grep -qE "^[-+@^]?firewall\.$s\.log_limit(=|$)"; then
				echo "firewall.$s.log_limit (zone $n: limit $n.log_limit)"
			fi
			;;
		ipset) echo "firewall.$s (ipset $n: set $n)" ;;
		esac
	done
	;;
check-staged)
	# P16: check the STAGED firewall config without applying it. Prints exactly ONE line (the host reads
	# only the first): fw4 pass | fail DETAIL | running-fails DETAIL | skipped-untouched | not-checked REASON.
	# fw4 builds its ruleset from uci.cursor() with no arguments, so a ucode wrapper swaps the cursor for one
	# that reads /etc/config plus the rpcd session's delta dir (the dir `uci -P` uses), includes fw4's own
	# template, and the rendered text goes to `nft -c`, which loads nothing. fw4 gets interface state from
	# ubus (live), so a staged network change is not seen: it is never reported as a pass. Anything the
	# wrapper cannot prove (it fails, or a canary rule in a scratch delta dir does not show up in its output)
	# is not-checked, never pass. Measured on OpenWrt 25.12.5 only.
	[ "$#" -eq 1 ] || die "check-staged takes one session id"
	valid_sid "${1:-}"
	say() { printf 'fw4 %s\n' "$*"; exit 0; }
	d=$(recorded_dir "$1") || say not-checked no-folder
	[ -n "$d" ] || say not-checked no-folder
	d=$(rpcd_path "$d")
	config_dir=${NEWTON_CONFIG_DIR:-/etc/config}
	live "$1" || say not-checked session-gone
	ch=$(uci -P "$d" changes 2>/dev/null) || say not-checked changes-unreadable
	[ -n "$ch" ] || say not-checked session-gone
	command -v fw4 >/dev/null 2>&1 && command -v utpl >/dev/null 2>&1 && command -v nft >/dev/null 2>&1 || say not-checked no-fw4
	w=$(mktemp -d "${LOCK%/*}/newton-chk.XXXXXX" 2>/dev/null) || say not-checked no-tmp
	trap 'rm -rf "$w"' EXIT
	trap 'rm -rf "$w"; exit 1' HUP INT TERM
	line_of() { head -n 3 "$1" | tr '\000-\037\177' ' ' | sed 's#[^ ]*/newton-chk\.[A-Za-z0-9]*/##g; s/  */ /g; s/^ //' | cut -c1-300; }
	fw4 check > "$w/run.out" 2>&1 || say running-fails "$(fw4_first_line "$w/run.out")"
	printf '%s\n' "$ch" | grep -qE '^[-+@^]?firewall\.' || {
		printf '%s\n' "$ch" | grep -qE '^[-+@^]?(network|wireless)\.' && say not-checked network-live-state
		say skipped-untouched
	}
	render() {	# render SAVEDIR OUT: the ruleset fw4 would load, over /etc/config plus the delta in SAVEDIR
		printf '{%%\nlet uci = require("uci");\nlet orig = uci.cursor;\nuci.cursor = function() { return orig("%s", "%s"); };\ninclude("/usr/share/firewall4/main.uc");\n%%}\n' "$config_dir" "$1" > "$w/w.uc" || return 1
		ACTION=print utpl -S "$w/w.uc" > "$2" 2>/dev/null
	}
	mkdir "$w/canary" && cn="newton-canary-$$" &&
		printf '%s\n' 'add firewall rule' "set firewall.@rule[-1].name='$cn'" "set firewall.@rule[-1].proto='tcp'" \
			"set firewall.@rule[-1].dest_port='9'" "set firewall.@rule[-1].target='DROP'" | uci -P "$w/canary" batch >/dev/null 2>&1 || say not-checked wrapper-unverified
	render "$w/canary" "$w/canary.nft" || say not-checked wrapper-failed
	grep -Fq "$cn" "$w/canary.nft" || say not-checked wrapper-unverified
	render "$d" "$w/staged.nft" || say not-checked wrapper-failed
	grep -q 'table inet fw4' "$w/staged.nft" || say not-checked wrapper-failed
	if nft -c -f "$w/staged.nft" > "$w/nft.out" 2>&1; then
		printf '%s\n' "$ch" | grep -qE '^[-+@^]?(network|wireless)\.' && say not-checked network-live-state
		say pass
	fi
	[ -s "$w/nft.out" ] || echo "no output" > "$w/nft.out"
	say fail "$(line_of "$w/nft.out")"
	;;
confighash)
	[ "$#" -eq 0 ] || die "confighash takes no arguments"
	config_dir=${NEWTON_CONFIG_DIR:-/etc/config}
	LC_ALL=C; export LC_ALL
	for f in "$config_dir"/*; do
		[ -f "$f" ] || continue
		name=${f##*/}
		clean=$(printf '%s' "$name" | LC_ALL=C tr -d '\000-\037\177')
		if [ "$clean" != "$name" ]; then
			safe=$(printf '%s' "$name" | LC_ALL=C tr '\000-\037\177' ' ' | cut -c1-120)
			printf 'ERROR: confighash unsafe config file name: %s\n' "$safe" >&2
			exit 1
		fi
		if [ ! -r "$f" ] || ! sum=$(md5sum "$f" 2>/dev/null); then
			printf 'ERROR: confighash cannot read config file: %s\n' "$name" >&2
			exit 1
		fi
		hash=${sum%% *}
		printf '%s %s\n' "$hash" "$name"
	done
	;;
health-snapshot)
	need_sid "${1:-}"
	health="$LOCK/$1.health"
	tmp="$LOCK/$1.health.new"
	rm -rf "$tmp"
	mkdir "$tmp" || die "cannot create health snapshot"
	if ! ubus call service list > "$tmp/services.json"; then
		rm -rf "$tmp"
		die "ubus call service list failed"
	fi
	if ! ucode -e '
		const fs = require("fs");
		let services = json(fs.readfile("/dev/stdin"));
		if (type(services) != "object") exit(1);
		for (let service, body in services) {
			if (type(body?.instances) != "object") continue;
			for (let instance, state in body.instances)
				if (state?.running == true) printf("%s/%s\n", service, instance);
		}
	' < "$tmp/services.json" > "$tmp/running.unsorted"; then
		rm -rf "$tmp"
		die "cannot parse service health"
	fi
	if [ ! -s "$tmp/running.unsorted" ]; then
		rm -rf "$tmp"
		die "no running services found"
	fi
	if ! awk -F '\t' '
		function valid_instance(value, slash) {
			slash = index(value, "/")
			return slash > 1 && slash < length(value) && index(substr(value, slash + 1), "/") == 0
		}
		NF != 1 || !valid_instance($1) { exit 1 }
	' "$tmp/running.unsorted"; then
		rm -rf "$tmp"
		die "invalid service health output"
	fi
	LC_ALL=C sort -u "$tmp/running.unsorted" > "$tmp/running"
	rm -f "$tmp/running.unsorted"
	rm -f "$tmp/services.json"
	if command -v fw4 >/dev/null 2>&1; then
		: > "$tmp/fw4.present"
		fw4 check > "$tmp/fw4.out" 2>&1; rc=$?
		if [ "$rc" -ne 0 ]; then
			first=$(fw4_first_line "$tmp/fw4.out")
			rm -rf "$tmp"
			die "the firewall config already fails fw4 check before the change: $first; fix it first"
		fi
		echo "$rc" > "$tmp/fw4.rc"
		grep -F '[!]' "$tmp/fw4.out" | LC_ALL=C sort -u > "$tmp/fw4.warnings" || :
		rm -f "$tmp/fw4.out"
	fi
	rm -rf "$health"
	mv "$tmp" "$health" || { rm -rf "$tmp"; die "cannot save health snapshot"; }
	;;
health-check)
	[ -n "${1:-}" ] || die "missing session id"
	valid_sid "$1"
	[ "$#" -le 2 ] || die "health-check takes <SID> [after-rollback]"
	case "${2:-}" in
		"") check_restarts=1 ;;
		after-rollback) check_restarts=0 ;;
		*) die "health-check takes <SID> [after-rollback]" ;;
	esac
	health="$LOCK/$1.health"
	[ -d "$health" ] || die "health snapshot for session $1 not found"
	if ! ubus call service list > "$health/services.now.json"; then
		rm -f "$health/services.now.json"
		die "ubus call service list failed"
	fi
	if ! ucode -e '
		const fs = require("fs");
		let services = json(fs.readfile("/dev/stdin"));
		if (type(services) != "object") exit(1);
		for (let service, body in services) {
			if (type(body?.instances) != "object") continue;
			for (let instance, state in body.instances) {
				let pid = state?.pid;
				printf("%s/%s\t%s\t%s\n", service, instance,
					state?.running == true ? "true" : "false", pid == null ? "" : pid);
			}
		}
	' < "$health/services.now.json" > "$health/services.now.unsorted"; then
		rm -f "$health/services.now.json" "$health/services.now"
		die "cannot parse service health"
	fi
	if ! awk -F '\t' '
		function valid_instance(value, slash) {
			slash = index(value, "/")
			return slash > 1 && slash < length(value) && index(substr(value, slash + 1), "/") == 0
		}
		NF != 3 || !valid_instance($1) || ($2 != "true" && $2 != "false") || $3 !~ /^([0-9]+)?$/ { exit 1 }
	' "$health/services.now.unsorted"; then
		rm -f "$health/services.now.json" "$health/services.now.unsorted" "$health/services.now"
		die "invalid service health output"
	fi
	LC_ALL=C sort -u "$health/services.now.unsorted" > "$health/services.now"
	rm -f "$health/services.now.unsorted"
	rm -f "$health/services.now.json"
	while IFS= read -r instance; do
		[ -n "$instance" ] || continue
		if awk -F '\t' -v wanted="$instance" '$1 == wanted { found=1; if ($2 == "true") running=1 } END { exit !(found && !running) }' "$health/services.now"; then
			rm -f "$health/services.now"
			echo "health: service $instance is not running after the change" >&2
			exit 1
		fi
	done < "$health/running"
	if [ "$check_restarts" -eq 1 ]; then
		awk -F '\t' '
			NR == FNR { baseline[$0] = 1; next }
			$1 in baseline && $2 == "true" { print $1 "\t" $3 }
		' "$health/running" "$health/services.now" > "$health/pids.now"
		: > "$health/restart.reason"
		had_previous=0
		[ ! -f "$health/pids.previous" ] || had_previous=1
		tab=$(printf '\t')
		while IFS="$tab" read -r instance pid; do
			[ -n "$instance" ] || continue
			if [ -z "$pid" ]; then
				[ -s "$health/restart.reason" ] || printf 'health: service %s restarted between verify rounds\n' "$instance" > "$health/restart.reason"
			elif [ "$had_previous" -eq 1 ]; then
				if previous=$(awk -F '\t' -v wanted="$instance" '$1 == wanted { print $2; found=1; exit } END { exit !found }' "$health/pids.previous") && [ "$previous" != "$pid" ]; then
					[ -s "$health/restart.reason" ] || printf 'health: service %s restarted between verify rounds\n' "$instance" > "$health/restart.reason"
				fi
			fi
		done < "$health/pids.now"
		mv "$health/pids.now" "$health/pids.previous" || die "cannot save service health"
		if [ -s "$health/restart.reason" ]; then
			cat "$health/restart.reason" >&2
			rm -f "$health/restart.reason" "$health/services.now"
			exit 1
		fi
		rm -f "$health/restart.reason" "$health/services.now"
	else
		rm -f "$health/services.now"
	fi
	if command -v fw4 >/dev/null 2>&1; then
		fw4 check > "$health/fw4.now" 2>&1; rc=$?
		if [ "$rc" -ne 0 ]; then
			first=$(head -n 1 "$health/fw4.now")
			rm -f "$health/fw4.now"
			echo "health: fw4 check failed: $first" >&2
			exit 1
		fi
		grep -F '[!]' "$health/fw4.now" | LC_ALL=C sort -u > "$health/fw4.warnings.now" || :
		rm -f "$health/fw4.now"
		while IFS= read -r warning; do
			[ -n "$warning" ] || continue
			case "$warning" in
				*"is disabled, ignoring section") continue ;;
			esac
			if ! grep -Fqx "$warning" "$health/fw4.warnings" 2>/dev/null; then
				rm -f "$health/fw4.warnings.now"
				echo "health: new firewall warning: $warning" >&2
				exit 1
			fi
		done < "$health/fw4.warnings.now"
		rm -f "$health/fw4.warnings.now"
	fi
	;;
fwrestart)
	trap '' HUP PIPE   # a dropped ssh session must not kill a restart half-way (no table: no filtering, no NAT)
	# Restart the firewall so named nft objects are re-created from the config (fw4 reload keeps them).
	# $1: 1 = table inet fw4 was loaded before the apply, 0 = it was not.
	# exit 0 restarted | 1 the restart failed, table present | 2 usage | 3 not loaded before and not now (left alone)
	#      98 the table was missing and fw4 stop + fw4 start loaded it again | 99 it is missing and could not be loaded
	case "${1:-}" in 0|1) ;; *) echo "ERROR: fwrestart needs 0 or 1 (was table inet fw4 loaded before the apply)" >&2; exit 2 ;; esac
	fw_init=${NEWTON_FIREWALL_INIT:-/etc/init.d/firewall}   # the tests point this at a fake init script
	fw_loaded() { nft list table inet fw4 >/dev/null 2>&1; }
	fw_load_again() {
		fw4 stop >/dev/null 2>&1; fw4 start 2>&1
		fw_loaded && exit 98
		echo "the fw4 table is STILL missing"; exit 99
	}
	if ! fw_loaded; then
		[ "$1" = 1 ] || { echo "the firewall is not loaded (no table inet fw4): left as it is"; exit 3; }
		echo "the fw4 table is missing although it was loaded before the apply: loading it again (fw4 stop; fw4 start)"
		fw_load_again
	fi
	"$fw_init" restart 2>&1; rc=$?
	if ! fw_loaded; then
		echo "the fw4 table is missing after the restart: loading it again (fw4 stop; fw4 start)"
		fw_load_again
	fi
	[ "$rc" -eq 0 ] && exit 0
	echo "firewall restart exited $rc"; exit 1
	;;
status)
	[ -n "${1:-}" ] || die "missing session id"; valid_sid "$1"
	if ! live "$1"; then echo gone; elif expired "$1"; then echo rolled-back; elif applied "$1"; then echo applied-pending-confirm; else echo staged; fi
	;;
apply)
	need_sid "${1:-}"; T=${2:-90}
	echo "$T" | grep -qE '^[0-9]+$' && [ "$T" -ge 60 ] && [ "$T" -le 600 ] || die "timeout must be an integer 60..600"
	applied "$1" && die "already applied; confirm or abort"
	up1=$(uptime_s) || die "cannot read uptime"
	ubus call uci apply "{\"rollback\":true,\"timeout\":$T,\"ubus_rpc_session\":\"$1\"}" || die "apply failed"
	up2=$(uptime_s) || up2=$up1
	printf 'up %s\n' "$(( up2 + T ))" > "$LOCK/$1.applied"
	echo "APPLIED with rollback. Auto-revert in ${T}s unless: $0 confirm $1"
	;;
confirm)
	need_sid "${1:-}"
	applied "$1" || die "not applied yet"
	expired "$1" && { drop "$1"; die "rollback deadline passed — the change was already reverted"; }
	ubus call uci confirm "{\"ubus_rpc_session\":\"$1\"}" || die "confirm failed (rollback window may have expired)"
	drop "$1"
	echo "CONFIRMED. Change kept; session destroyed."
	;;
abort)
	[ -n "${1:-}" ] || die "missing session id"
	valid_sid "$1"
	if ! live "$1"; then
		clean "$1"
		echo "session already gone; cleaned transaction state."
		echo "ABORTED."
		exit 0
	fi
	if expired "$1"; then
		echo "rollback deadline passed — automatic rollback already happened."
	elif applied "$1"; then
		ubus call uci rollback "{\"ubus_rpc_session\":\"$1\"}" || die "ROLLBACK FAILED — session kept; it will still auto-revert at its deadline. Check uci show and logread."
		echo "ROLLED BACK applied change."
	else
		echo "nothing applied; discarding staged changes."
	fi
	drop "$1"
	echo "ABORTED."
	;;
*)
	sed -n '2,26p' "$0"; exit 2
	;;
esac
