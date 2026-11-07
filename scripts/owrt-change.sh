#!/usr/bin/env bash
# owrt-change.sh — run the OpenWrt change protocol from the agent host.
#
#   owrt-change.sh plan  <router> <changes.uci> [timeout] [probes-file]
#                                                        validate, backup, stage, seal, print diff + plan facts
#   owrt-change.sh apply <router> <SID> [timeout]         apply with rollback, verify over NEW connections,
#                                                          confirm only after 3 consecutive passing rounds
#   owrt-change.sh status <router> <SID>                  staged | applied-pending-confirm | rolled-back | gone
#   owrt-change.sh backup <router>                        config backup to the agent host only
#   owrt-change.sh abort <router> <SID>                   discard staged changes (or roll back now)
#
# <router> is an ssh destination (e.g. root@192.0.2.1). [probes-file] is an optional file of probe lines
# (design 3.6: at most 4096 bytes, no CR) the router runs itself each verify round, instead of a shell check.
# $OWRT_LOCAL_CHECK, if set, runs on the agent host each round too (use it to test the user path the change
# affects, e.g. a client-side ping). Timeout 60..600s, default 90; use >=120 for wifi or anything on the agent's
# own path. Rollback is config-only (see owrt-safe-apply.sh). After the window, the committed config is compared
# with its state right before the apply; a difference is an ALERT.
# If logd restarts during apply or rollback, running dnsmasq is restarted and DNS/DHCP are verified before success.
# Changes to named nft objects restart the firewall after apply and rollback so the live objects match the config.
# Backups:   $OWRT_BACKUP_DIR   (default ~/.local/state/network-agent/backups)
# Audit log: $OWRT_AUDIT_LOG    (default ~/.local/state/network-agent/audit.log)
# SSH port: $OWRT_SSH_PORT (default 22). Jump host: $OWRT_SSH_PROXY, a ProxyCommand such as
#   'ssh -i ~/.ssh/key -o BatchMode=yes -W %h:%p root@jumphost'.
# Key auth: $OWRT_SSH_KEY (added with IdentitiesOnly=yes so an old plain key cannot log you in) and
#   $OWRT_KNOWN_HOSTS (StrictHostKeyChecking=yes with that known-hosts file).
# Password auth: set $OWRT_SSH_PASSWORD_FILE to a mode-600 file holding the password (lab default is password
#   SSH); the password is fed through SSH_ASKPASS and never appears on a command line or in output.
# Environment: OWRT_APPROVAL_TOKEN (approval token for apply), OWRT_APPROVAL_NBF / OWRT_APPROVAL_EXP
#   (the approval window the token binds, decimal UNIX seconds; default 0 0. Token 'none' takes 0 and 0, a 64-hex
#   token takes two 10-digit numbers, and any other pairing is refused before any ssh call),
#   OWRT_EXPECT_DEVICE / OWRT_EXPECT_PROFILE
#   (compared with the router's hello line; when unset the compare is skipped and the audit log gets
#   `unchecked device` / `unchecked profile`), OWRT_SRC_ROOT (repo root with the host copies of the router
#   code; default: the parent directory of this script).
set -uo pipefail
# Control characters (C0 / DEL, including newline and ESC) in any argument
# make the script print an error and exit 2 BEFORE the audit log, the state
# directories, the temp dir (mktemp below), and any ssh call are touched.
# A hostile `router\n` would otherwise trip a parser downstream into acting
# on a forged "second" argument.
for a in "$@"; do
	if ( LC_ALL=C; [[ $a == *[[:cntrl:]]* ]] ); then
		printf '%s\n' "ERROR: control character in an argument" >&2
		exit 2
	fi
done
# backups hold /etc/shadow and dropbear keys, so new files are 600 and new dirs 700
umask 077
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

# Resolve ssh the same way as mcp/newton_mcp/ssh_path.py: the first of
# /usr/bin/ssh, /bin/ssh that is a regular executable file, else die before
# any ssh call.  Looking ssh up through PATH would run whatever the operator's
# (or a hostile ~/.bashrc's) PATH happens to name first, so PATH is not consulted.
# There is deliberately no env seam for this: OWRT_LOCAL_CHECK (below) already
# runs operator-supplied bash, but an ssh-path seam would change which binary
# talks to the router, so it does not exist.
# The refusal returns non-zero rather than exiting: a command substitution runs
# in a subshell, so an `exit` there would only end the substitution and the
# script would carry on with an empty SSH_BIN.
SSH_BIN=""
resolve_ssh() {
	local c
	for c in /usr/bin/ssh /bin/ssh; do
		if [[ -f $c && -x $c ]]; then
			SSH_BIN=$c
			return 0
		fi
	done
	printf '%s\n' "ERROR: no ssh at /usr/bin/ssh or /bin/ssh; refusing to resolve ssh through PATH" >&2
	return 1
}
resolve_ssh || exit 1

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${OWRT_SRC_ROOT:-$HERE/..}
STATE=${XDG_STATE_HOME:-$HOME/.local/state}/network-agent
BACKUPS=${OWRT_BACKUP_DIR:-$STATE/backups}
AUDIT=${OWRT_AUDIT_LOG:-$STATE/audit.log}
PLANS=$STATE/plans
PROG=/usr/libexec/newton/newton-router
# ControlMaster/ControlPath off: every call must be a genuinely new connection, never a reused multiplexed one
SSH=("$SSH_BIN" -o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o ControlMaster=no -o ControlPath=none)
PASSES=3
# State dirs whose PARENT (the directory one level up) is group- or world-writable
# without the sticky bit let any local user plant a symlink the script then follows.
# Refuse before any mkdir, so the check sits before anything is created.
check_state_dir_parent_sticky() {
	local dir=$1 label=$2 parent mode
	parent=$(dirname -- "$dir") || { printf '%s\n' "ERROR: cannot resolve the parent of $label ($dir)" >&2; exit 1; }
	# $STATE is the exception, and only that: when it is a real directory (not
	# a symlink) we own, the chmod 700 "$STATE" below tightens it itself, so a
	# $STATE left 0775 by an older version is healed here rather than refused
	# on the default layout, where BACKUPS and PLANS sit directly under it.
	# $STATE's own parent is still checked above this, a $STATE that is a
	# symlink or belongs to another user is refused, and an OWRT_BACKUP_DIR
	# or OWRT_AUDIT_LOG elsewhere keeps its parent checked.
	if [[ $parent == "$STATE" ]] && [[ -d $STATE && ! -L $STATE && -O $STATE ]]; then
		return 0
	fi
	# A parent that does not exist cannot be inspected for its mode; the mkdir
	# below lays it down under our umask 077, and a parent we just created is
	# ours alone, so there is nothing to refuse.
	[[ -d $parent ]] || return 0
	# GNU coreutils on the agent host: stat -c %a prints the mode as 3 or 4 octal
	# digits (a leading 1/2/4 is sticky/setgid/setuid), so read it as base 8.
	mode=$(stat -c %a -- "$parent") || { printf '%s\n' "ERROR: cannot stat the parent of $label ($parent)" >&2; exit 1; }
	if (( (8#$mode & 022) && !(8#$mode & 01000) )); then
		printf '%s\n' "ERROR: state directory parent $parent of $label ($dir) is group- or world-writable without the sticky bit" >&2
		exit 1
	fi
}
check_state_dir_parent_sticky "$STATE" 'STATE'
check_state_dir_parent_sticky "$BACKUPS" 'OWRT_BACKUP_DIR'
check_state_dir_parent_sticky "$AUDIT" 'OWRT_AUDIT_LOG'
check_state_dir_parent_sticky "$PLANS" 'PLANS'
mkdir -p "$BACKUPS" "$PLANS" "$(dirname "$AUDIT")"
# also tightens dirs created 775 by older versions (does not touch dirname of $AUDIT — may be shared)
chmod 700 "$STATE" "$BACKUPS" "$PLANS"
PORT=${OWRT_SSH_PORT:-22}; [[ $PORT =~ ^[0-9]+$ ]] || { echo "ERROR: OWRT_SSH_PORT must be numeric" >&2; exit 1; }
if [[ -n ${OWRT_SSH_PASSWORD_FILE:-} ]]; then
	[[ -r $OWRT_SSH_PASSWORD_FILE ]] || { echo "ERROR: password file not readable" >&2; exit 1; }
	[[ $(stat -c %a "$OWRT_SSH_PASSWORD_FILE") == 600 ]] || { echo "ERROR: password file must be mode 600" >&2; exit 1; }
	ASKPASS=$TMPD/askpass
	printf '#!/bin/sh\nexec cat %q\n' "$OWRT_SSH_PASSWORD_FILE" > "$ASKPASS"; chmod 700 "$ASKPASS"
	export SSH_ASKPASS=$ASKPASS SSH_ASKPASS_REQUIRE=force DISPLAY=${DISPLAY:-x}
	SSH=("$SSH_BIN" -o BatchMode=no -o "PreferredAuthentications=password,keyboard-interactive" -o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o ControlMaster=no -o ControlPath=none)
else
	# key mode: the key is pinned with IdentitiesOnly so ssh cannot fall back to an old plain key that is
	# still authorised; the known-hosts file pins the router identity
	if [[ -n ${OWRT_SSH_KEY:-} ]]; then
		SSH+=(-i "$OWRT_SSH_KEY" -o IdentitiesOnly=yes)
	fi
	if [[ -n ${OWRT_KNOWN_HOSTS:-} ]]; then
		SSH+=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$OWRT_KNOWN_HOSTS")
	fi
fi
# LC_ALL=C below: in a UTF-8 locale bash ranges like A-Z also match accented letters.
PROXY_COMMAND_RE='^[A-Za-z0-9 _./:@%~=,+-]{1,512}$'
# Reach routers behind a jump host (e.g. a lab management network): full ProxyCommand, so the hop's key is explicit.
if [[ -n ${OWRT_SSH_PROXY:-} ]]; then
	( LC_ALL=C; [[ $OWRT_SSH_PROXY =~ $PROXY_COMMAND_RE ]] ) || { echo "ERROR: OWRT_SSH_PROXY contains characters outside [A-Za-z0-9 _./:@%~=,+-] or is longer than 512" >&2; exit 1; }
	SSH+=(-o "ProxyCommand=$OWRT_SSH_PROXY")
fi

log()  { printf '%s %s %s\n' "$(date -Is)" "$ROUTER" "$*" >> "$AUDIT"; echo "$*"; }
mask() { sed 's/CONFIRMED/confirmed/g; s/ROLLBACK WINDOW PASSED/rollback window passed/g; s/OUTCOME UNKNOWN/outcome unknown/g; s/ALERT/alert/g; s/APPLIED/applied/g'; }
oneline() {
	if (( $# > 0 )); then printf '%s' "$1"; else cat; fi |
		LC_ALL=C tr '\000-\037\177' ' ' |
		LC_ALL=C sed 's/\xe2\x80\xa8/ /g; s/\xe2\x80\xa9/ /g; s/\xc2\x85/ /g' |
		mask | cut -c1-120
}
# One secret-name catalog shared with mcp/newton_mcp/redact.py (triage #4).
# scripts/ and mcp/ are siblings both in the repo and in /opt/newton.
SECRET_CATALOG=$HERE/../mcp/newton_mcp/secret_names.txt
# Loads the catalog ONCE into four ERE fragments (no forks per diff line).
# Fail closed: a missing, empty or malformed catalog kills plan/apply at startup.
load_secret_catalog() {
	local raw kind word lineno=0
	SECRET_EXACT_WORDS=; SECRET_SUFFIX_WORDS=; SECRET_CONTAINS_WORDS=; SECRET_ALLOW_WORDS=
	[[ -r $SECRET_CATALOG ]] || die "secret-name catalog missing or unreadable: $SECRET_CATALOG"
	while IFS= read -r raw || [[ -n $raw ]]; do
		lineno=$((lineno + 1))
		raw=${raw#"${raw%%[![:space:]]*}"}
		[[ -z ${raw//[[:space:]]/} || $raw == \#* ]] && continue
		kind=${raw%% *}; word=${raw##* }
		if [[ $kind != "$raw" && $word != "$raw" && $word =~ ^[a-z0-9_]+$ ]]; then
			case $kind in
				exact)    SECRET_EXACT_WORDS+="$word|" ;;
				suffix)   SECRET_SUFFIX_WORDS+="$word|" ;;
				contains) SECRET_CONTAINS_WORDS+="$word|" ;;
				allow)    SECRET_ALLOW_WORDS+="$word|" ;;
				*)        word= ;;
			esac
		else
			word=
		fi
		[[ -n $word ]] || die "secret-name catalog $SECRET_CATALOG line $lineno: not 'exact|suffix|contains <lowercase word>'"
	done < "$SECRET_CATALOG"
	[[ -n $SECRET_EXACT_WORDS && -n $SECRET_SUFFIX_WORDS && -n $SECRET_CONTAINS_WORDS ]] || {
		die "secret-name catalog $SECRET_CATALOG: empty (needs exact, suffix and contains rules)"
	}
	SECRET_EXACT_RE="^(${SECRET_EXACT_WORDS%|})$"
	SECRET_SUFFIX_RE="_(${SECRET_SUFFIX_WORDS%|})$"
	SECRET_CONTAINS_RE="(${SECRET_CONTAINS_WORDS%|})"
	SECRET_ALLOW_RE=; [[ -z $SECRET_ALLOW_WORDS ]] || SECRET_ALLOW_RE="^(${SECRET_ALLOW_WORDS%|})$"
}
mask_secrets() {
	local line=$1
	local i=0 len=${#line} ch n_eq=0 j name_end name_start NAME option lower pre_eq
	while (( i < len )); do
		ch=${line:i:1}
		if [[ $ch == = ]]; then
			n_eq=$(( n_eq + 1 ))
			if (( n_eq > 64 )); then
				oneline "${line:0:i}<masked: too many assignments>"
				return
			fi
			j=$(( i - 1 ))
			while (( j >= 0 )); do
				case "${line:j:1}" in
					[' ']|$'\t') j=$(( j - 1 )) ;;
					*) break ;;
				esac
			done
			if (( j >= 0 )); then
				case "${line:j:1}" in
					'+'|'-'|'^') j=$(( j - 1 )) ;;
				esac
				while (( j >= 0 )); do
					case "${line:j:1}" in
						[' ']|$'\t') j=$(( j - 1 )) ;;
						*) break ;;
					esac
				done
			fi
			name_end=$(( j + 1 ))
			while (( j >= 0 )); do
				case "${line:j:1}" in
					[A-Za-z0-9_.@\[\]-]) j=$(( j - 1 )) ;;
					*) break ;;
				esac
			done
			name_start=$(( j + 1 ))
			if (( name_start < name_end )); then
				NAME=${line:name_start:name_end-name_start}
				option=${NAME##*.}
				option=${option%+}; option=${option%-}; option=${option%^}
				lower=${option,,}
				lower=${lower//-/_}
				if [[ -n $SECRET_ALLOW_RE && $lower =~ $SECRET_ALLOW_RE ]]; then
					:
				elif [[ $lower =~ $SECRET_EXACT_RE || $lower =~ $SECRET_SUFFIX_RE || $lower =~ $SECRET_CONTAINS_RE ]]; then
					pre_eq=${line:name_start:i-name_start}
					oneline "${line:0:name_start}${pre_eq}='<masked>'"
					return
				fi
			fi
		fi
		i=$(( i + 1 ))
	done
	oneline "$line"
}
die()  { log "ERROR: $*"; exit 1; }
r()    { "${SSH[@]}" -p "$PORT" -- "$ROUTER" "$@"; }
need_sid() { [[ ${1:-} =~ ^[0-9a-f]{32}$ ]] || die "malformed or missing session id"; }
logd_pid() { r "$PROG logd-pid" </dev/null; }
# handshake [plan]: the hello call of design 2.6, first call of every host command (it replaces the push).
# Parses the reply strictly (exactly one line, key=value fields, no repeats) and checks it against this
# controller: api, mode, the four code hashes, device, profile, guard state and — for plan — busy.
handshake() {
	local mode=${1:-} nonce reply k tok key val comp rel hsha rsha setup
	local -a hl=() toks=()
	local -A H=()
	nonce=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
	reply=$(r "$PROG hello $nonce" </dev/null 2>"$TMPD/hello.err"); hrc=$?
	(( hrc == 255 )) && die "router unreachable during hello"
	readarray -t hl <<< "$reply"
	(( ${#hl[@]} == 1 )) || die "malformed hello reply"
	read -r -a toks <<< "${hl[0]}"
	(( ${#toks[@]} >= 3 )) || die "malformed hello reply"
	[[ ${toks[0]} == hello && ${toks[1]} == "$nonce" ]] || die "malformed hello reply"
	for (( k=2; k<${#toks[@]}; k++ )); do
		tok=${toks[k]}
		[[ $tok == *=* ]] || die "malformed hello reply"
		key=${tok%%=*}; val=${tok#*=}
		[[ -n $key ]] || die "malformed hello reply"
		[[ -z ${H[$key]+x} ]] || die "malformed hello reply"
		H[$key]=$val
	done
	setup="sudo -u newton newton-router-setup ${OWRT_EXPECT_DEVICE:-$ROUTER} upgrade"
	[[ ${H[api]-} == 1 ]] || die "router program speaks api=$(oneline "${H[api]:-?}"), this controller speaks api=1; run: $setup"
	[[ ${H[mode]-} == prod ]] || die "router program runs in mode=$(oneline "${H[mode]:-?}"); this controller only talks to mode=prod routers; fix the router's newton install"
	for comp in prog helper guard init; do
		case $comp in
			prog)   rel=device/openwrt/newton-router/newton-router ;;
			helper) rel=scripts/owrt-safe-apply.sh ;;
			guard)  rel=device/openwrt/newton-guard/newton-guard ;;
			init)   rel=device/openwrt/newton-guard/newton-guard.init ;;
		esac
		[[ -r $ROOT/$rel ]] || die "cannot read this controller's copy of the router's $comp: $ROOT/$rel"
		hsha=$(sha256sum "$ROOT/$rel" | cut -d' ' -f1)
		rsha=${H[$comp]-}
		[[ $rsha == "$hsha" ]] || die "router ${comp/prog/program} $(oneline "${H[version]:-?}") ($comp $(oneline "${rsha:0:8}")...) differs from this controller's (${hsha:0:8}...); run: $setup"
	done
	if [[ -n ${OWRT_EXPECT_DEVICE:-} ]]; then
		[[ ${H[device]-} == "$OWRT_EXPECT_DEVICE" ]] || die "router device=$(oneline "${H[device]:-?}") is not the expected $OWRT_EXPECT_DEVICE; check OWRT_EXPECT_DEVICE and the router address $ROUTER"
	else
		log "unchecked device"
	fi
	if [[ -n ${OWRT_EXPECT_PROFILE:-} ]]; then
		[[ ${H[profile]-} == "$OWRT_EXPECT_PROFILE" ]] || die "router profile=$(oneline "${H[profile]:-?}") is not the expected $OWRT_EXPECT_PROFILE; check OWRT_EXPECT_PROFILE and the router address $ROUTER"
	else
		log "unchecked profile"
	fi
	[[ ${H[guard-state]-} != failed ]] || die "the router's newton-guard is in state failed; fix the guard on the router before running changes"
	if [[ $mode == plan ]]; then
		[[ ${H[busy]-} == - || ${H[busy]-} == "${H[caller]-}" ]] || die "router busy with another change (owner $(oneline "${H[busy]:-?}")); wait for it or abort it first"
	fi
	ROUTER_VERSION=${H[version]-}
	log "ROUTER version=$(oneline "${H[version]:-?}") caller=$(oneline "${H[caller]:-?}") profile=$(oneline "${H[profile]:-?}")"
}
valid_config_hashes() {
	local data=$1 line
	[[ -n $data ]] || return 1
	while IFS= read -r line; do
		[[ $line =~ ^[0-9a-f]{32}\ .+$ ]] || return 1
	done <<<"$data"
}
# print_config_hashes: print the hashes of the committed config on stdout, one
# "CONFIGHASH <md5> <name>" line per package.
#
# The router is asked once ("$PROG confighash"); its stderr goes to a file
# under $TMPD, never to the terminal.  A confighash that fails, or that
# answers something which is not a list of hashes, prints NOTHING and changes
# NOTHING: the outcome of the apply and the exit code never depend on it.
# Only the lines that match ^[0-9a-f]{32} [A-Za-z0-9_-]+$ are printed (a name
# with a space or a control character in it is dropped), and at most 200 of
# them.  These lines go to stdout only: the audit log never sees them.
print_config_hashes() {
	local out line name n=0
	out=$(r "$PROG confighash" </dev/null 2>"$TMPD/confighash.print.err") || return 0
	valid_config_hashes "$out" || return 0
	while IFS= read -r line; do
		( LC_ALL=C; [[ $line =~ ^[0-9a-f]{32}\ [A-Za-z0-9_-]+$ ]] ) || continue
		n=$((n + 1))
		(( n > 200 )) && break
		name=${line#* }
		printf 'CONFIGHASH %s %s\n' "${line%% *}" "$name"
	done <<< "$out"
	return 0
}
validate_timeout() {
	[[ $T =~ ^[1-9][0-9]{1,2}$ ]] && (( T >= 60 && T <= 600 )) || die "timeout must be an integer 60..600"
}

# staged_check SID: ask the router program to check the STAGED config without applying it.
# Sets SC_STATUS (pass | skipped-untouched | not-checked) and SC_REASON. A staged config that fails fw4
# check, or a running one that already fails, discards the session and dies. Anything that cannot run
# or is not understood is not-checked: never a pass. The verb exists from router program 1.3.0 on.
STAGED_CHECK_MIN_VERSION=1.3.0
staged_check() {
	local sid=$1 out first detail crc
	SC_STATUS=not-checked; SC_REASON=router-program-has-no-check
	[[ ${ROUTER_VERSION:-} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
	[[ $(printf '%s\n%s\n' "$STAGED_CHECK_MIN_VERSION" "$ROUTER_VERSION" | LC_ALL=C sort -V | head -n 1) == "$STAGED_CHECK_MIN_VERSION" ]] || return 0
	SC_REASON=check-error
	out=$(r "$PROG check-staged $sid" </dev/null 2>/dev/null); crc=$?
	first=${out%%$'\n'*}
	if [[ $first =~ ^fw4\ (fail|running-fails)(\ (.*))?$ ]]; then
		detail=$(mask_secrets "${BASH_REMATCH[3]:-}" | oneline)
		r "$PROG abort $sid" </dev/null >/dev/null 2>&1 || true
		if [[ ${BASH_REMATCH[1]} == fail ]]; then
			die "staged firewall config fails fw4 check: $detail; the staged change was discarded"
		fi
		die "the firewall config already fails fw4 check before the change: $detail; fix it first; the staged change was discarded"
	elif (( crc != 0 )); then
		SC_STATUS=not-checked; SC_REASON=check-error
	elif [[ $first =~ ^fw4\ (pass|skipped-untouched)$ ]]; then
		SC_STATUS=${BASH_REMATCH[1]}; SC_REASON=
	elif [[ $first =~ ^fw4\ not-checked\ ([a-z0-9-]{1,40})$ ]]; then
		SC_STATUS=not-checked; SC_REASON=${BASH_REMATCH[1]}
	else
		SC_STATUS=not-checked; SC_REASON=check-error
	fi
}

cmd=${1:-}; ROUTER=${2:-}; [[ -n $ROUTER ]] || { sed -n '2,31p' "$0"; exit 2; }
# INJ-1: the destination is one argv word of every ssh call.  A shape check
# keeps a value that ssh could read as an option (a leading dash), a second
# word (a space), a shell metacharacter or a newline out of the command
# line; `--` before the destination tells ssh the next word is the host
# whatever it looks like.  The user@ prefix is optional: a bare host or an
# ssh_config alias still takes its user from ssh.
( LC_ALL=C; [[ $ROUTER =~ ^([A-Za-z0-9_][A-Za-z0-9_.-]{0,31}@)?[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] ) || die "router destination must look like [user@]host"

backup_now() {
	local host ts bk lead
	handshake
	host=$(r "$PROG hostname" </dev/null) || die "router unreachable"
	host=$(printf '%s' "$host" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' | cut -c1-63)
	lead=${host%%[!.]*}; host=${lead//./_}${host#"$lead"} # leading dots would hide the file
	[[ -n $host ]] || host=router
	ts=$(date +%Y%m%d-%H%M%S); bk="$BACKUPS/${host}-${ts}.tar.gz"
	r "$PROG backup" </dev/null > "$bk"
	tar -tzf "$bk" >/dev/null 2>&1 || die "backup failed or corrupt: $(oneline "$bk")"
	log "BACKUP $(printf '%s' "$bk" | LC_ALL=C tr '\000-\037\177' ' ') ($(tar -tzf "$bk" | grep -c '^etc/config/[^/][^/]*$') config files)"
}

case $cmd in
backup)
	backup_now
	;;
plan)
	load_secret_catalog
	F=${3:-}; [[ -r $F ]] || die "changes file not readable: $F"
	# `${4-90}` not `${4:-90}`: the default is only for an ABSENT argument; an empty one
	# must reach validate_timeout and die (design 7.1, rows 90-92)
	T=${4-90}
	# probes are validated before any ssh call: a bad file must cost nothing on the router
	PROBES=
	if (( $# >= 5 )); then
		PROBES=$5
		[[ -r $PROBES ]] || die "probes file not readable: $PROBES"
		[[ $(stat -c %s "$PROBES") -le 4096 ]] || die "probes file larger than 4096 bytes: $PROBES"
		if LC_ALL=C grep -q $'\r' "$PROBES"; then die "probes file contains CR: $PROBES"; fi
	fi
	validate_timeout
	backup_now
	handshake plan
	SID=$(r "$PROG stage" < "$F" 2>"$TMPD/stage.err"); rc=$?
	if (( rc != 0 )); then
		msg=; n=0
		while IFS= read -r line || [[ -n $line ]]; do
			[[ -z $msg ]] || msg+=' / '
			msg+=$(mask_secrets "$line")
			n=$((n + 1)); (( n >= 3 )) && break
		done < "$TMPD/stage.err"
		if [[ -n $msg ]]; then
			die "staging rejected: $msg"
		fi
		die "staging rejected"
	fi
	need_sid "$SID"
	if [[ -n $PROBES ]]; then
		SEAL=$(r "$PROG seal $SID $T" < "$PROBES" 2>"$TMPD/seal.err"); rc=$?
	else
		SEAL=$(r "$PROG seal $SID $T" </dev/null 2>"$TMPD/seal.err"); rc=$?
	fi
	if (( rc != 0 )); then
		r "$PROG abort $SID" </dev/null >/dev/null 2>&1 || true
		first=
		IFS= read -r first < "$TMPD/seal.err" || true
		die "probes refused: $(oneline "$first"); the staged change was discarded"
	fi
	# parse the seal reply exactly as the program prints it (design 3.5b step 9); anything else is fatal
	readarray -t seal_lines <<< "$SEAL"
	(( ${#seal_lines[@]} >= 7 )) || die "malformed seal reply"
	[[ ${seal_lines[0]} =~ ^base\ ([0-9a-f]{64})$ ]] || die "malformed seal reply"; SEAL_BASE=${BASH_REMATCH[1]}
	[[ ${seal_lines[1]} =~ ^diff\ ([0-9a-f]{64})$ ]] || die "malformed seal reply"; SEAL_DIFF=${BASH_REMATCH[1]}
	[[ ${seal_lines[2]} =~ ^probes\ ([0-9]+)\ ([0-9a-f]{64})$ ]] || die "malformed seal reply"; SEAL_PROBES_N=${BASH_REMATCH[1]}; SEAL_PROBES_SHA=${BASH_REMATCH[2]}
	[[ ${seal_lines[3]} =~ ^t\ ([0-9]{2,3})$ ]] || die "malformed seal reply"; [[ ${BASH_REMATCH[1]} == "$T" ]] || die "malformed seal reply"
	[[ ${seal_lines[4]} =~ ^profile\ (lab|prod)$ ]] || die "malformed seal reply"; SEAL_PROFILE=${BASH_REMATCH[1]}
	[[ ${seal_lines[${#seal_lines[@]}-2]} =~ ^approval\ (required|not-required)$ ]] || die "malformed seal reply"; SEAL_APPROVAL=${BASH_REMATCH[1]}
	[[ ${seal_lines[${#seal_lines[@]}-1]} =~ ^digest\ ([0-9a-f]{64})$ ]] || die "malformed seal reply"; SEAL_DIGEST=${BASH_REMATCH[1]}
	for (( k=5; k<${#seal_lines[@]}-2; k++ )); do
		[[ ${seal_lines[k]} == section\ * || ${seal_lines[k]} == leash\ * ]] || die "malformed seal reply"
	done
	staged_check "$SID"
	printf '%s\n' "$SEAL_DIFF" > "$PLANS/$SID.sha256"
	printf '%s\n' "$SEAL_BASE" > "$PLANS/$SID.base"
	# the probe count of the seal line, read back at apply time for the CONFIRMED line (design 7.1 rows 344-345)
	printf '%s\n' "$SEAL_PROBES_N" > "$PLANS/$SID.probes"
	log "STAGED session=$SID from $F"
	echo "BASEHASH $SEAL_BASE"
	echo "PROBES $(oneline "$SEAL_PROBES_N $SEAL_PROBES_SHA")"
	echo "PROFILE $(oneline "$SEAL_PROFILE")"
	for (( k=5; k<${#seal_lines[@]}-2; k++ )); do
		case ${seal_lines[k]} in
			section*) echo "SECTION $(oneline "${seal_lines[k]#section }")" ;;
			leash*)   echo "LEASH $(oneline "${seal_lines[k]#leash }")" ;;
		esac
	done
	echo "APPROVAL $(oneline "$SEAL_APPROVAL")"
	echo "PLANDIGEST $SEAL_DIGEST"
	echo "STAGEDCHECK fw4 $SC_STATUS${SC_REASON:+ $SC_REASON}"
	log "STAGED CHECK session=$SID fw4=$SC_STATUS${SC_REASON:+ reason=$SC_REASON}" >/dev/null
	operator=${OWRT_OPERATOR:-${SUDO_USER:-${USER:-unknown}}}
	log "OPERATOR session=$SID: $(oneline "$operator")"
	DIFF_RAW=$(r "$PROG diff $SID" </dev/null) || die "cannot read staged diff"
	echo "----- diff -----"
	while IFS= read -r line || [[ -n $line ]]; do mask_secrets "$line"; done <<< "$DIFF_RAW"
	echo "----------------"
	echo "next: $0 apply $ROUTER $SID [timeout]"
	;;
apply)
	# the approval token is validated before any ssh call; its value never reaches a log, a die text or an echoed command
	TOKEN=${OWRT_APPROVAL_TOKEN:-none}
	[[ $TOKEN =~ ^(none|[0-9a-f]{64})$ ]] || die "OWRT_APPROVAL_TOKEN must be 'none' or 64 lowercase hex characters; nothing applied"
	# SW2 Item 2: the approval window (UNIX seconds) is bound into the token, so the
	# router recomputes the HMAC over exactly these two numbers.  A token none needs
	# 0 0; a 64-hex token needs two 10-digit positive numbers.  Any other pairing is
	# refused here, before the first ssh call; neither the values nor the token are
	# echoed, logged or printed.
	APPROVAL_NBF=${OWRT_APPROVAL_NBF:-0}; APPROVAL_EXP=${OWRT_APPROVAL_EXP:-0}
	if [[ $TOKEN == none ]]; then
		[[ $APPROVAL_NBF == 0 && $APPROVAL_EXP == 0 ]] || die "OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP do not match OWRT_APPROVAL_TOKEN; nothing applied"
	else
		( LC_ALL=C; [[ $APPROVAL_NBF =~ ^[1-9][0-9]{9}$ && $APPROVAL_EXP =~ ^[1-9][0-9]{9}$ ]] ) || die "OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP do not match OWRT_APPROVAL_TOKEN; nothing applied"
	fi
	load_secret_catalog
	# `${4-90}` not `${4:-90}`: an empty timeout argument is invalid, not the default (design 7.1)
	SID=${3:-}; T=${4-90}
	NEED_DHCP=0; DNSMASQ_RESTARTED=0; DNSMASQ_TOUCHED=0
	logd_repair() {
		local when=$1 now old out repair_rc dhcp listener first
		[[ -n $LOGD_SEEN ]] || return 1
		now=$(logd_pid </dev/null) || return 2
		if [[ -z $now ]]; then
			log "LOGD MISSING session=$SID ($when): logd is not running (was pid $(oneline "$LOGD_SEEN")); dnsmasq left alone"
			return 3
		fi
		[[ $now != "$LOGD_SEEN" ]] || return 1
		old=$LOGD_SEEN
		out=$(r "$PROG dnsmasq-repair" </dev/null) || return 2
		LOGD_SEEN=$now
		if [[ $out =~ ^restarted\ rc=([0-9]+)\ dhcp=([01])$ ]]; then
			repair_rc=${BASH_REMATCH[1]}; dhcp=${BASH_REMATCH[2]}
			if (( dhcp == 1 )); then NEED_DHCP=1; else NEED_DHCP=2; fi
			DNSMASQ_RESTARTED=1; DNSMASQ_TOUCHED=1
			if (( dhcp == 1 )); then listener=yes; else listener=no; fi
			log "LOGD RESTARTED session=$SID ($when): logd pid $(oneline "$old") -> $(oneline "$now"); restarted dnsmasq (rc=$repair_rc; its jail keeps the old /dev/log), DHCP listener before the restart: $listener"
		elif [[ $out == not-running ]]; then
			(( DNSMASQ_TOUCHED == 1 )) || NEED_DHCP=0
			log "LOGD RESTARTED session=$SID ($when): logd pid $(oneline "$old") -> $(oneline "$now"); dnsmasq is not running, nothing to restart"
		else
			first=${out%%$'\n'*}
			first=$(oneline "$first")
			log "LOGD RESTARTED session=$SID ($when): logd pid $(oneline "$old") -> $(oneline "$now"); dnsmasq repair gave unexpected output: $first"
		fi
		return 0
	}
	fw_restart() {
		local when=$1 rc first attempt
		for (( attempt=1; attempt <= 3; attempt++ )); do
			r "$PROG fwrestart $FW_LOADED" </dev/null >"$TMPD/fw.out" 2>&1
			rc=$?
			(( rc == 255 && attempt < 3 )) || break
			sleep 2
		done
		FW_RESTART_RC=$rc
		case $rc in
		0)
			log "FIREWALL RESTARTED session=$SID ($when): named nft objects re-created from the config"
			return 0
			;;
		3)
			log "FIREWALL NOT RESTARTED session=$SID ($when): the firewall is not loaded (no table inet fw4); left as it is"
			return 0
			;;
		98)
			IFS= read -r first < "$TMPD/fw.out" || true
			first=$(oneline "$first")
			log "FIREWALL RESTART FAILED session=$SID ($when): exit 98 (the fw4 table was loaded again): $first"
			return 1
			;;
		esac
		IFS= read -r first < "$TMPD/fw.out" || true
		first=$(oneline "$first")
		log "FIREWALL RESTART FAILED session=$SID ($when): exit $rc: $first"
		return 1
	}
	add_rollback_reason() {
		local reason=$1
		[[ -z $rollback_reason ]] || rollback_reason+='; '
		rollback_reason+=$reason
	}
	need_sid "$SID"
	validate_timeout
	[[ -r $PLANS/$SID.sha256 ]] || die "no plan record for $SID — run plan first"
	# the probe count the plan printed (seal's `probes <n> <sha>` line); the router reports no count at apply time
	PROBE_N=
	[[ -r $PLANS/$SID.probes ]] && IFS= read -r PROBE_N < "$PLANS/$SID.probes"
	[[ $PROBE_N =~ ^[0-9]+$ ]] || PROBE_N=0
	if [[ -n ${OWRT_LOCAL_CHECK:-} ]]; then
		out=$(bash -n -c "$OWRT_LOCAL_CHECK" 2>&1); rc=$?
		if (( rc != 0 )); then
			msg=${out%%$'\n'*}
			die "OWRT_LOCAL_CHECK is not valid bash: $(oneline "$msg"); nothing applied, session $SID is still staged"
		fi
	fi
	handshake
	# ONE diff fetch: the sha256 must equal the plan record's, then the masked DIFF audit lines (rows 261-263)
	DIFF_RAW=$(r "$PROG diff $SID" </dev/null) || die "cannot read staged diff; nothing applied, session $SID is still staged"
	if [[ -n $DIFF_RAW ]]; then
		DIFF_SHA=$(printf '%s\n' "$DIFF_RAW" | sha256sum | cut -d' ' -f1)
	else
		DIFF_SHA=$(sha256sum </dev/null | cut -d' ' -f1)
	fi
	[[ $DIFF_SHA == "$(cat "$PLANS/$SID.sha256")" ]] || die "staged diff changed since plan — re-plan and re-approve"
	while IFS= read -r line || [[ -n $line ]]; do log "DIFF session=$SID: $(mask_secrets "$line")"; done <<< "$DIFF_RAW"
	operator=${OWRT_OPERATOR:-${SUDO_USER:-${USER:-unknown}}}
	log "OPERATOR session=$SID: $(oneline "$operator")"
	NAMED=$(r "$PROG named $SID" </dev/null) || die "cannot inspect the staged change for named nft objects; nothing applied, session $SID is still staged"
	FW_LOADED=0
	if [[ -n $NAMED ]]; then
		FW_LOADED=$(r "$PROG fw-loaded" </dev/null) || die "router unreachable before apply; nothing applied, session $SID is still staged"
		[[ $FW_LOADED == [01] ]] || die "unexpected answer while reading the firewall state: $(oneline "$FW_LOADED"); nothing applied, session $SID is still staged"
		named_log=$(oneline "$NAMED")
		log "NAMED NFT OBJECTS session=$SID: $named_log — a firewall reload keeps them, so the firewall will be restarted after the apply"
	fi
	LOGD_SEEN=$(logd_pid </dev/null) || die "router unreachable before apply; nothing applied, session $SID is still staged"
	CONFIG_BEFORE=$(r "$PROG confighash" </dev/null 2>"$TMPD/confighash.err"); config_before_rc=$?
	if (( config_before_rc != 0 )); then
		config_hash_err=$(oneline < "$TMPD/confighash.err")
		die "cannot record the committed config before the apply; nothing applied, session $SID is still staged${config_hash_err:+; helper said: $config_hash_err}"
	fi
	if ! valid_config_hashes "$CONFIG_BEFORE"; then
		die "cannot record the committed config before the apply; nothing applied, session $SID is still staged"
	fi
	CURRENT_BASE=$(printf '%s\n' "$CONFIG_BEFORE" | sha256sum | cut -d' ' -f1)
	if [[ -n ${OWRT_EXPECT_BASE:-} ]]; then
		[[ $OWRT_EXPECT_BASE =~ ^[0-9a-f]{64}$ ]] || die "OWRT_EXPECT_BASE must be 64 lowercase hexadecimal characters; nothing applied, session $SID is still staged"
		[[ $CURRENT_BASE == "$OWRT_EXPECT_BASE" ]] || die "router config changed since the plan; plan again"
	fi
	log "APPLYBASE $CURRENT_BASE"
	CONFIG_COUNT=$(printf '%s\n' "$CONFIG_BEFORE" | wc -l); CONFIG_COUNT=${CONFIG_COUNT//[[:space:]]/}
	health_err=$(r "$PROG health-snapshot $SID" </dev/null 2>&1); health_rc=$?
	if (( health_rc != 0 )); then
		health_detail=${health_err:+; helper said: $(oneline "$health_err")}
		die "cannot record service and firewall health before the apply; nothing applied, session $SID is still staged$health_detail"
	fi
	log "APPLYING session=$SID"
	out=$(r "$PROG apply $SID $T $TOKEN $APPROVAL_NBF $APPROVAL_EXP" </dev/null 2>"$TMPD/apply.err"); arc=$?
	appl_re="^applied $SID t=$T guard=[0-9]+$"
	if (( arc == 0 )) && [[ $out =~ $appl_re ]]; then
		:
	elif (( arc == 3 )); then
		first=; IFS= read -r first < "$TMPD/apply.err" || true
		die "apply refused, nothing applied: $(oneline "$first"); session $SID is still staged"
	else
		die "apply did not report success — OUTCOME UNKNOWN; run: $0 status $ROUTER $SID"
	fi
	log "APPLIED session=$SID rollback=${T}s"
	deadline=$((SECONDS + T - 15)); good=0; round=0; last_round=; verify=1; FW_RESTART_RC=0
	sleep 5
	if [[ -n $NAMED ]] && ! fw_restart "after apply"; then
		verify=0
	fi
	if (( verify == 1 )); then
		logd_repair "after apply"
	fi
	while (( verify && SECONDS < deadline )); do        # require PASSES consecutive successes: services may still be reloading
		round=$((round + 1))
		r "$PROG verify $SID $NEED_DHCP" </dev/null >"$TMPD/round.out" 2>"$TMPD/round.err"; rc=$?
		lrc=0
		if (( rc == 0 )) && [[ -n ${OWRT_LOCAL_CHECK:-} ]]; then
			bash -c "$OWRT_LOCAL_CHECK" >/dev/null 2>"$TMPD/local.err"; lrc=$?
		fi
		if (( rc == 0 && lrc == 0 )); then
			good=$((good + 1))
			if (( good >= PASSES )); then
				logd_repair "before confirm"; repair_rc=$?
				if (( repair_rc == 1 )); then
					break
				elif (( repair_rc == 3 )); then
					good=0
					last_round=$round
					last_rc=3; last_stage=logd
					printf 'logd is not running (was pid %s): not confirming while the system log is down\n' "$LOGD_SEEN" > "$TMPD/lastfail"
					: > "$TMPD/lastfail.out"
				fi
				good=0
			fi
		else
			good=0
			last_round=$round
			if (( rc != 0 )); then
				last_rc=$rc; last_stage=router-verify
				cp "$TMPD/round.err" "$TMPD/lastfail"
				cp "$TMPD/round.out" "$TMPD/lastfail.out"
			else
				last_rc=$lrc; last_stage=local-check
				{ printf 'local check exited %s\n' "$lrc"; cat "$TMPD/local.err"; } > "$TMPD/lastfail"
				: > "$TMPD/lastfail.out"
			fi
		fi
		sleep 5
	done
	confirm_refused=0
	if (( good >= PASSES )); then
		out=$(r "$PROG confirm $SID" </dev/null 2>"$TMPD/confirm.err"); crc=$?
		if (( crc == 0 )) && [[ $out == "confirmed $SID" || $out == "confirmed $SID rpcd-timer-lost" ]]; then
			lost_note=
			[[ $out == "confirmed $SID rpcd-timer-lost" ]] && lost_note='; rpcd had lost its rollback timer, the guard held the window'
			# the hashes of the committed config, read once more after the
			# confirmation and printed on stdout for the caller.
			# A confighash problem prints nothing and changes nothing: the
			# CONFIRMED line below stays the last line of stdout.
			print_config_hashes
			log "CONFIRMED session=$SID ($PASSES consecutive passes: fresh ssh + router-side ping, dns, health and $PROBE_N probes${OWRT_LOCAL_CHECK:+ + local check})$lost_note"
			rm -f "$PLANS/$SID.sha256"
		elif (( crc == 3 )); then
			confirm_refused=1
			first=; IFS= read -r first < "$TMPD/confirm.err" || true
			reason=$(oneline "$first"); reason=${reason:-exit 3 (too-late)}
			log "CONFIRM REFUSED session=$SID: $reason; the router reverts on its own, waiting out the window"
		elif (( crc == 1 )); then
			first=; IFS= read -r first < "$TMPD/confirm.err" || true
			if [[ $first == 'error rpcd-confirm-failed'* || $first == 'error confirm-incomplete'* ]]; then
				confirm_refused=1
				log "CONFIRM REFUSED session=$SID: $(oneline "$first"); the router reverts on its own, waiting out the window"
			else
				log "CONFIRM DID NOT REPORT SUCCESS session=$SID — OUTCOME UNKNOWN; run: $0 status $ROUTER $SID"; exit 1
			fi
		else
			log "CONFIRM DID NOT REPORT SUCCESS session=$SID — OUTCOME UNKNOWN; run: $0 status $ROUTER $SID"; exit 1
		fi
	else
		log "VERIFY FAILED session=$SID — not confirming; waiting for automatic rollback"
		if (( verify == 0 )); then
			log "VERIFY DETAIL session=$SID firewall restart exit=$FW_RESTART_RC (the change cannot be made live; its output follows, last 20 lines, at most 2 KB)"
			tail -n 20 "$TMPD/fw.out" | tail -c 2048 | LC_ALL=C tr -d '\000-\010\013-\037\177' | \
				mask > "$TMPD/excerpt"
			if [[ -s $TMPD/excerpt ]]; then
				while IFS= read -r line || [[ -n $line ]]; do
					log "VERIFY STDERR session=$SID: $line"
				done < "$TMPD/excerpt"
			else
				log "VERIFY STDERR session=$SID: (empty)"
			fi
		elif [[ -n $last_round ]]; then
			log "VERIFY DETAIL session=$SID round=$last_round exit=$last_rc stage=$last_stage (last failed round; stderr and stdout follow, each last 20 lines, at most 2 KB)"
			tail -n 20 "$TMPD/lastfail" | tail -c 2048 | LC_ALL=C tr -d '\000-\010\013-\037\177' | \
				mask > "$TMPD/excerpt"
			if [[ -s $TMPD/excerpt ]]; then
				while IFS= read -r line || [[ -n $line ]]; do
					log "VERIFY STDERR session=$SID: $line"
				done < "$TMPD/excerpt"
			else
				log "VERIFY STDERR session=$SID: (empty)"
			fi
			tail -n 20 "$TMPD/lastfail.out" | tail -c 2048 | LC_ALL=C tr -d '\000-\010\013-\037\177' | \
				mask > "$TMPD/excerpt"
			if [[ -s $TMPD/excerpt ]]; then
				while IFS= read -r line || [[ -n $line ]]; do
					log "VERIFY STDOUT session=$SID: $line"
				done < "$TMPD/excerpt"
			fi
		else
			log "VERIFY DETAIL session=$SID: no round failed; $good consecutive passes before the deadline, $PASSES needed"
		fi
	fi
	if (( confirm_refused == 1 || good < PASSES )); then
		# failure branch (design 7.1): the router reverts on its own; wait, settle, check
		sleep $(( deadline + 30 - SECONDS ))
		st_full=; st_waited=0
		while :; do
			out=$(r "$PROG status $SID" </dev/null 2>/dev/null); src=$?
			if (( src == 0 )); then
				# a hostile `status` reply that includes a newline would otherwise
				# leave `st_full` a multi-line blob whose later fields (rpcd=, etc.)
				# could be attacker-controlled text the script logs or branches on
				st_full=${out%%$'\n'*}
				break
			fi
			(( src == 255 && st_waited < 90 )) || break
			sleep 5
			st_waited=$((st_waited + 5))
		done
		st=${st_full%% *}
		[[ -n $st ]] || st=unreachable
		case $st in
		rolled-back|gone|applied-pending-confirm)
			abort_how=failed
			abort_out=$(r "$PROG abort $SID" </dev/null 2>"$TMPD/abort.err")
			if [[ $abort_out == "aborted $SID "* ]]; then
				abort_how=${abort_out#aborted $SID }
				log "ABORTED session=$SID ($(oneline "$abort_how"))"
			else
				first=; IFS= read -r first < "$TMPD/abort.err" || true
				log "ALERT session=$SID abort did not report success: $(oneline "$first") — check the router now; latest backup in $BACKUPS"
			fi
			sleep 5
			rollback_reason=
			CONFIG_DIFF=
			health_rc=1
			for (( attempt=1; attempt <= 3; attempt++ )); do
				health_err=$(r "$PROG health-check $SID after-rollback" </dev/null 2>&1); health_rc=$?
				(( health_rc == 0 )) && break
				(( attempt < 3 )) && sleep 5
			done
			if (( health_rc != 0 )); then
				if [[ ${health_err%%$'\n'*} == "health: not compared"* ]]; then
					add_rollback_reason "service or firewall health was not compared after the rollback: $(oneline "$health_err")"
				else
					add_rollback_reason "service or firewall health differs from before the apply after the rollback: $(oneline "$health_err")"
				fi
			fi
			CONFIG_AFTER=$(r "$PROG confighash" </dev/null 2>"$TMPD/confighash.err"); config_after_rc=$?
			if (( config_after_rc != 0 )) || ! valid_config_hashes "$CONFIG_AFTER"; then
				config_hash_err=$(oneline < "$TMPD/confighash.err")
				add_rollback_reason "could not read the config to compare it with its state before the apply${config_hash_err:+: $config_hash_err}"
			else
				printf '%s\n' "$CONFIG_BEFORE" > "$TMPD/config.before"
				printf '%s\n' "$CONFIG_AFTER" > "$TMPD/config.after"
				CONFIG_DIFF=$(awk 'NR==FNR { before[substr($0, 34)]=substr($0, 1, 32); next } { after[substr($0, 34)]=substr($0, 1, 32) } END { for (p in before) if (!(p in after) || before[p] != after[p]) print p; for (p in after) if (!(p in before)) print p }' "$TMPD/config.before" "$TMPD/config.after" | LC_ALL=C sort -u | paste -sd' ' -)
			fi
			DNSMASQ_RESTARTED=0
			if [[ -n $NAMED ]] && ! fw_restart "after rollback"; then
				if (( FW_RESTART_RC != 98 )); then
					IFS= read -r first < "$TMPD/fw.out" || true
					first=$(oneline "$first")
					add_rollback_reason "firewall restart after the rollback failed: $first"
				fi
			fi
			logd_repair "after rollback"; repair_rc=$?
			if (( repair_rc == 2 )); then
				add_rollback_reason "router unreachable while checking logd after the rollback"
			elif (( repair_rc == 3 )); then
				add_rollback_reason "logd is not running after the rollback (was pid $(oneline "$LOGD_SEEN"))"
			fi
			if (( DNSMASQ_TOUCHED == 1 )); then
				if (( DNSMASQ_RESTARTED == 0 )); then
					dnsmasq_state=$(r "$PROG dnsmasq-ensure" </dev/null); dnsmasq_state_rc=$?
					if (( dnsmasq_state_rc != 0 )); then
						add_rollback_reason "router unreachable while checking dnsmasq after the rollback"
					elif [[ $dnsmasq_state =~ ^started\ rc=([0-9]+)$ ]]; then
						log "DNSMASQ STARTED session=$SID (after rollback): dnsmasq was not running after the rollback and Newton had restarted it during the window (rc=${BASH_REMATCH[1]})"
					fi
				fi
				post_ok=0
				for (( attempt=1; attempt <= 5; attempt++ )); do
					if r "$PROG dns-dhcp-check $NEED_DHCP" </dev/null 2>"$TMPD/post.err"; then
						post_ok=1
						break
					fi
					(( attempt < 5 )) && sleep 3
				done
				if (( post_ok == 1 )); then
					if (( NEED_DHCP == 1 )); then listener=yes; else listener=no; fi
					log "DNS AND DHCP OK session=$SID after the dnsmasq restart (DHCP listener checked: $listener)"
				else
					IFS= read -r post_err < "$TMPD/post.err" || true
					post_err=$(oneline "$post_err")
					add_rollback_reason "DNS/DHCP check failed after the dnsmasq restart: $post_err"
				fi
			fi
			# who rolled back: the status line's rpcd= field (design 6.5) — `rolled-back` means rpcd
			# reverted by itself, anything else (rpcd=-) is the guard restoring a lost rpcd timer
			rollback_cause='the guard: rpcd lost its rollback'
			[[ $st_full == *' rpcd=rolled-back '* || $st_full == *' rpcd=rolled-back' ]] && rollback_cause=rpcd
			# a USER abort during the window leaves rpcd=- but guard=restored:<who>, which names the
			# restorer (design 6.5); rpcd=rolled-back already named rpcd itself and wins. Whole
			# fields of the first line only, the same way the rpcd= match above does.
			if [[ $rollback_cause != rpcd ]]; then
				[[ $st_full == *' guard=restored:rpcd '* || $st_full == *' guard=restored:rpcd' ]] && \
					rollback_cause='an abort during the window (rpcd rolled it back)'
				[[ $st_full == *' guard=restored:guard '* || $st_full == *' guard=restored:guard' ]] && \
					rollback_cause='an abort during the window (the guard restored it)'
				[[ $st_full == *' guard=restored:already-base '* || $st_full == *' guard=restored:already-base' ]] && \
					rollback_cause='an abort during the window (the config was already back)'
			fi
			safe_st=$(oneline "$st")
			safe_config_diff=$(oneline "$CONFIG_DIFF")
			if [[ -n $CONFIG_DIFF ]]; then
				log "ALERT session=$SID status=$safe_st after the rollback window, but the committed config differs from its state before the apply in: $safe_config_diff — the change may still be live (rpcd restarted during the window, or the change was confirmed outside Newton)${rollback_reason:+; also: $rollback_reason} — check the router now; latest backup in $BACKUPS (abort: $(oneline "$abort_how"))"
			elif [[ -z $rollback_reason ]]; then
				log "ROLLBACK WINDOW PASSED session=$SID — router reachable; the committed config matches its state before the apply ($CONFIG_COUNT packages compared); rolled back by $rollback_cause"
			else
				log "ALERT session=$SID rolled back, but $rollback_reason — check the router now; latest backup in $BACKUPS (abort: $(oneline "$abort_how"))"
			fi
			;;
		confirmed)
			log "ALERT session=$SID status=confirmed after the rollback window — the change was confirmed outside this run; check the router now; latest backup in $BACKUPS"
			;;
		staged|inconsistent|unreachable)
			log "ALERT session=$SID status=$st after rollback window — check the router now; latest backup in $BACKUPS"
			;;
		*) log "ALERT session=$SID status=unexpected ($(oneline "$st")) after rollback window — check the router now; latest backup in $BACKUPS" ;;
		esac
		rm -f "$PLANS/$SID.sha256"
		exit 1
	fi
	;;
status)
	SID=${3:-}; need_sid "$SID"; handshake
	out=$(r "$PROG status $SID" </dev/null) || die "status did not answer — run: $0 status $ROUTER $SID"
	oneline "$out"
	;;
abort)
	SID=${3:-}; need_sid "$SID"; handshake
	out=$(r "$PROG abort $SID" </dev/null 2>"$TMPD/abort.err"); arc=$?
	if (( arc == 0 )) && [[ $out == "aborted $SID "* ]]; then
		log "ABORTED session=$SID ($(oneline "${out#aborted $SID }"))"
		rm -f "$PLANS/$SID.sha256"
	else
		first=; IFS= read -r first < "$TMPD/abort.err" || true
		die "abort did not report success: $(oneline "$first"); run: $0 status $ROUTER $SID"
	fi
	;;
*) sed -n '2,31p' "$0"; exit 2 ;;
esac
