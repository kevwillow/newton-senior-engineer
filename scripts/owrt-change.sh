#!/usr/bin/env bash
# owrt-change.sh — run the OpenWrt change protocol from the agent host.
#
#   owrt-change.sh plan  <router> <changes.uci> [timeout] [probes-file]
#                                                        validate, backup, stage, seal, print diff + plan facts
#   owrt-change.sh apply <router> <SID> [timeout] [--hold]  apply with rollback, verify over NEW connections,
#                                                          confirm only after 3 consecutive passing rounds;
#                                                          --hold: the same rounds, then NO confirm (the rollback stays armed)
#   owrt-change.sh confirm <router> <SID>                 confirm a held apply inside its window, after one more round
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
# BK_PARTIAL names a backup file still being written: a run that stops
# before the archive checks out removes it, so no truncated file is left
# under a normal backup name for an ALERT's "latest backup" to point at
BK_PARTIAL=
trap 'rm -rf "$TMPD"; [[ -z $BK_PARTIAL ]] || rm -f -- "$BK_PARTIAL"' EXIT

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
mask() { sed 's/CONFIRMED/confirmed/g; s/ROLLBACK WINDOW PASSED/rollback window passed/g; s/OUTCOME UNKNOWN/outcome unknown/g; s/ALERT/alert/g; s/APPLIED/applied/g; s/HELD APPLY/held apply/g; s/RUNNING/running/g'; }
# check_digest TEXT: the sha256 (64 hex) of the exact bytes of TEXT, the
# tool the script already uses for the config hashes.  No newline of its
# own is added, so the digest is of the string as it stands.  Fails when
# the tool is gone or says something else, so a caller never writes a
# digest it cannot trust.
check_digest() {
	local d
	d=$(printf '%s' "$1" | sha256sum | cut -d' ' -f1) || return 1
	[[ $d =~ ^[0-9a-f]{64}$ ]] || return 1
	printf '%s' "$d"
}
oneline() {
	if (( $# > 0 )); then printf '%s' "$1"; else cat; fi |
		LC_ALL=C tr '\000-\037\177' ' ' |
		LC_ALL=C sed 's/\xe2\x80\xa8/ /g; s/\xe2\x80\xa9/ /g; s/\xc2\x85/ /g' |
		mask | cut -c1-120
}
# setup_launcher: the command an owner types for newton-router-setup. An
# installed Newton (its launchers set NEWTON_HOME) refuses the bare name,
# so the hint is the installed launcher (the rule of _launcher in
# mcp/newton_mcp/approve.py).
setup_launcher() {
	if [[ -n ${NEWTON_HOME:-} ]]; then
		printf '%s' "sudo -u newton /usr/local/bin/newton-router-setup"
	else
		printf '%s' "sudo -u newton newton-router-setup"
	fi
}
# quarantine_note LINE: QNOTE = the owner's note when the router's status
# LINE ends with the whole field quarantined=<n> (the guard's restore moved
# config entries that were not in the saved copy, such as a file a package
# added during the window, to /etc/newton/quarantine/<SID>/ and keeps them
# there); empty otherwise. The router prints one more field after it, the
# running one (running=match|differs|unproven|boot), so that field may
# follow the count; a running value the router does not print is not its
# line, and no note is drawn from it.
quarantine_note() {
	QNOTE=
	[[ $1 =~ \ quarantined=([1-9][0-9]{0,3})(\ running=(match|differs|unproven|boot))?$ ]] || return 0
	QNOTE="the guard moved ${BASH_REMATCH[1]} config file(s) that were not in the saved copy to /etc/newton/quarantine/$SID/ on the router; they stay there until you remove them: copy back into /etc/config any you want to keep"
}
# running_note LINE: RNOTE = the owner's note when the router's status LINE
# ends with the whole field running=differs or running=unproven (the guard
# put the old settings back on its own, but Newton cannot show that the
# running network matches them); empty otherwise. RVAL = the value of the
# whole field running=match|differs|unproven|boot (empty when the line has
# no such field): the host prints it as a machine line of its own, because
# the router's line is cut at 120 characters and the field stands at its
# end, so the cut drops it.
running_note() {
	RNOTE=
	RVAL=
	[[ $1 =~ \ running=(match|differs|unproven|boot)$ ]] || return 0
	RVAL=${BASH_REMATCH[1]}
	case "$RVAL" in
		differs|unproven)
			RNOTE="the router put the old settings back on its own, but Newton cannot show the running network matches them; on the router run: reload_config; /etc/init.d/firewall restart; wifi reload"
			;;
	esac
}
# refusal_next_step FIRST: the true next step for a router's exit-3 apply
# refusal (its first stderr line, "error <code> [detail]"). Only the codes
# that leave an applicable staged session say "still staged"; an unknown
# code claims nothing and points at status.
refusal_next_step() {
	local words code again
	read -r -a words <<< "$1"
	code=${words[1]-}
	again="if this plan needs approval, approve it again (an approval is spent once it reaches the router), then apply again: $0 apply $ROUTER $SID"
	# the router checks the timeout before anything else of the plan, so a
	# timeout that differs from the sealed one leaves the session applicable
	[[ $code == plan-changed && ${words[2]-} == t && ${#words[@]} == 3 ]] && code=plan-changed-t
	case $code in
		plan-changed-t)
			printf '%s' "the timeout differs from the one this session was planned with; session $SID is still staged; apply it again with the timeout it was planned with (the plan's next: line names it): $0 apply $ROUTER $SID <planned timeout>" ;;
		not-sealed|plan-changed|stale-stage|stale-base)
			printf '%s' "this session cannot be applied; plan the change again (if the router then says it is busy with this session, abort it first: $0 abort $ROUTER $SID)" ;;
		session-gone|no-such-txn)
			printf '%s' "the router no longer has session $SID (rpcd restarted or the router rebooted), so nothing is staged; plan the change again" ;;
		role)
			printf '%s' "the router says this login's key does not hold the role apply needs: it needs the change role, and nothing was applied; apply with a change-role key, or check the session with: $0 status $ROUTER $SID" ;;
		not-owner)
			printf '%s' "this login does not own session $SID on the router (another login planned it, or its owner record is missing), so nothing was applied; apply it from the login that planned it, or plan the change again from this one" ;;
		guard)
			printf '%s' "the router's rollback guard is not idle (another change is armed or a restore is pending); session $SID is still staged; check it with: $0 status $ROUTER $SID; when the guard is idle, $again" ;;
		no-health-snapshot)
			printf '%s' "the health record from before the apply is missing; session $SID is still staged; $again" ;;
		needs-approval)
			printf '%s' "session $SID is still staged; approve the plan, then apply again: $0 apply $ROUTER $SID" ;;
		approval-window)
			printf '%s' "the approval expired or is not valid yet; approve the plan again; session $SID is still staged; then apply again: $0 apply $ROUTER $SID" ;;
		bad-approval)
			printf '%s' "the approval does not match this plan; approve the plan again; session $SID is still staged; then apply again: $0 apply $ROUTER $SID" ;;
		approval-key-missing)
			printf '%s' "the router has no approval key (run: $(setup_launcher) ${OWRT_EXPECT_DEVICE:-<device>} approval-key); session $SID is still staged; then $again" ;;
		*)
			printf '%s' "this refusal code is not one Newton knows, so whether session $SID can still be applied is not known from here; run: $0 status $ROUTER $SID" ;;
	esac
}
# One secret-name catalog shared with mcp/newton_mcp/redact.py.
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
# true when this host's audit log records a CONFIRMED line for session $1
confirmed_here() { [[ -r $AUDIT ]] && grep -qF -- " CONFIRMED session=$1 " "$AUDIT"; }
# true when this host's audit log records an abort that rolled back or
# discarded session $1 (an `ABORTED ... (gone)` line rolled nothing back)
aborted_here() {
	[[ -r $AUDIT ]] && grep -qE -- " ABORTED session=$1 \((discarded|rolled-back|rolled-back-by-guard|already-rolled-back)\)$" "$AUDIT"
}
# reconcile_confirmed WHY: the router says session $SID is confirmed, but
# this host never logged it (the link dropped after the router confirmed,
# before its answer arrived). For a session this host applied (its plan
# or hold record is still here), log the CONFIRMED line the server writes
# the receipt from. Returns 1, recording nothing, for a session confirmed
# here already or not applied from here.
# No config hashes are printed: the config now is not the config right
# after the confirm (a later change, or an edit outside Newton, may sit in
# it), and an undo built on it would revert that too. The undo planner
# refuses a reconciled change and says why.
reconcile_confirmed() {
	confirmed_here "$SID" && return 1
	[[ -e $PLANS/$SID.sha256 || -e $PLANS/$SID.held ]] || return 1
	log "CONFIRMED session=$SID (reconciled: $1)"
	rm -f "$PLANS/$SID.sha256" "$PLANS/$SID.held" "$PLANS/$SID.named"
}
# held_closed_rolled_back STATUS: a held apply whose window ended
# unconfirmed is recorded as rolled back only when the router's own status
# line says rolled-back for this session; returns 1 (and records nothing)
# otherwise. The server writes the rolled-back receipt from the line.
held_closed_rolled_back() {
	[[ $1 =~ ^rolled-back\ sid=$SID\  ]] || return 1
	log "HELD APPLY ROLLED BACK session=$SID (its window ended unconfirmed; the router's status says rolled-back)"
	rm -f "$PLANS/$SID.held"
}
HELD_UNKNOWN_NEXT="the router's status does not say rolled-back, so the outcome is not known from here"
# plan_backup: the backup the plan of session $SID took, as words for an
# ALERT or die line. $BACKUPS is shared by every router and by vendor
# backups, so "the latest backup" there can be another router's config.
plan_backup() {
	local p=
	[[ -r $PLANS/$SID.backup ]] && { IFS= read -r p < "$PLANS/$SID.backup" || true; }
	if [[ -n $p && -f $p ]]; then
		printf 'the backup this plan took, %s' "$(printf '%s' "$p" | LC_ALL=C tr '\000-\037\177' ' ')"
	else
		printf "the backup this plan took (this host has no record of it; %s holds the backups of every router, so pick this router's by its name and the time of the plan)" "$BACKUPS"
	fi
}
# router_says_confirmed STATUS: the router's own status line says this
# session is confirmed (a confirm reached it after this host stopped
# waiting, so no CONFIRMED line was logged here)
router_says_confirmed() { [[ $1 =~ ^confirmed\ sid=$SID\  ]]; }
confirmed_live() { printf '%s' "the router's status says session $SID is confirmed, so the change stays live; to undo it, plan the reverse change (newton_plan_undo)"; }
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
	setup="$(setup_launcher) ${OWRT_EXPECT_DEVICE:-$ROUTER} upgrade"
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
		[[ ${H[profile]-} == "$OWRT_EXPECT_PROFILE" ]] || die "router profile=$(oneline "${H[profile]:-?}") is not the expected $OWRT_EXPECT_PROFILE, the inventory profile; change profile in ${NEWTON_INVENTORY:-/var/lib/newton/devices.toml} (owned by the newton account; edit it with sudo -u newton) or run: $(setup_launcher) ${OWRT_EXPECT_DEVICE:-$ROUTER} profile $OWRT_EXPECT_PROFILE"
	else
		log "unchecked profile"
	fi
	[[ ${H[guard-state]-} != failed ]] || die "the router's newton-guard is in state failed; fix the guard on the router before running changes"
	if [[ $mode == plan ]]; then
		[[ ${H[busy]-} == - || ${H[busy]-} == "${H[caller]-}" ]] || die "router busy with another change (owner $(oneline "${H[busy]:-?}")); wait for it or abort it first"
	fi
	ROUTER_VERSION=${H[version]-}
	HELLO_CALLER=${H[caller]-}
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
# answers something which is not a list of hashes, prints NOTHING and returns
# 1; the outcome of the apply and the exit code never depend on it.
# Only the lines that match ^[0-9a-f]{32} [A-Za-z0-9_-]+$ are printed (a name
# with a space or a control character in it is dropped), and at most 200 of
# them.  These lines go to stdout only: the audit log never sees them.
# Returns 1 when it printed no line, so the caller can say that no undo
# record was kept (confighash_after_confirm).
print_config_hashes() {
	local out line name n=0
	out=$(r "$PROG confighash" </dev/null 2>"$TMPD/confighash.print.err") || return 1
	valid_config_hashes "$out" || return 1
	while IFS= read -r line; do
		( LC_ALL=C; [[ $line =~ ^[0-9a-f]{32}\ [A-Za-z0-9_-]+$ ]] ) || continue
		n=$((n + 1))
		(( n > 200 )) && break
		name=${line#* }
		printf 'CONFIGHASH %s %s\n' "${line%% *}" "$name"
	done <<< "$out"
	(( n > 0 ))
}
# confighash_after_confirm: print the config hashes right after a confirm;
# when none could be read, say (on stdout and in the audit log) that no undo
# record was kept. The CONFIRMED line the caller logs next stays last.
confighash_after_confirm() {
	print_config_hashes && return 0
	log "NO UNDO RECORD session=$SID: the router's config could not be read right after the confirm, so newton_plan_undo cannot undo this change; to undo it, plan the reverse change with newton_plan_change"
}
validate_timeout() {
	[[ $T =~ ^[1-9][0-9]{1,2}$ ]] && (( T >= 60 && T <= 600 )) || die "timeout must be an integer 60..600"
}

# discard_staged REASON: a plan that staged session $SID failed after the
# stage; abort the session and die with REASON and whether it really was
# discarded. A failed abort (a dropped link) leaves the session staged on
# the router, where it blocks the next plan, so the die names the abort.
discard_staged() {
	local out
	out=$(r "$PROG abort $SID" </dev/null 2>/dev/null)
	if [[ $out == "aborted $SID "* ]]; then
		die "$1; the staged change was discarded"
	fi
	die "$1; the staged change could NOT be discarded (session $SID is still staged on the router); run: $0 abort $ROUTER $SID"
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
		if [[ ${BASH_REMATCH[1]} == fail ]]; then
			discard_staged "staged firewall config fails fw4 check: $detail"
		fi
		discard_staged "the firewall config already fails fw4 check before the change: $detail; fix it first"
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

cmd=${1:-}; ROUTER=${2:-}; [[ -n $ROUTER ]] || { sed -n '2,33p' "$0"; exit 2; }
# the destination is one argv word of every ssh call.  A shape check
# keeps a value that ssh could read as an option (a leading dash), a second
# word (a space), a shell metacharacter or a newline out of the command
# line; `--` before the destination tells ssh the next word is the host
# whatever it looks like.  The user@ prefix is optional: a bare host or an
# ssh_config alias still takes its user from ssh.
( LC_ALL=C; [[ $ROUTER =~ ^([A-Za-z0-9_][A-Za-z0-9_.-]{0,31}@)?[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$ ]] ) || die "router destination must look like [user@]host"

# Ctrl-C or a TERM: say what the router does on its own and how to look.
# An apply that was sent and not yet confirmed is rolled back by the router
# when its window ends.  Once the confirm was sent, this run cannot tell
# whether it took, so it says only that and how to look.
SID=; APPLY_SENT=0; CONFIRM_SENT=0
on_interrupt() {
	trap - INT TERM
	if [[ $SID =~ ^[0-9a-f]{32}$ ]]; then
		if (( CONFIRM_SENT == 1 )); then
			log "INTERRUPTED session=$SID: this run stopped; the confirm was sent; whether it took is not known from here; run: $0 status $ROUTER $SID"
		elif (( APPLY_SENT == 1 )); then
			if fw_restart_owed; then
				log "INTERRUPTED session=$SID: this run stopped after it sent the apply and confirmed nothing; if the change was applied, the router rolls it back by itself when its window ends, but $(owed_fw_next)"
			else
				log "INTERRUPTED session=$SID: this run stopped after it sent the apply and confirmed nothing; if the change was applied, the router rolls it back by itself when its window ends; run: $0 status $ROUTER $SID"
			fi
		else
			log "INTERRUPTED session=$SID: this run stopped; run: $0 status $ROUTER $SID"
		fi
	else
		log "INTERRUPTED: this run stopped"
	fi
	exit 130
}
trap on_interrupt INT TERM

backup_now() {
	local host ts bk lead n
	handshake
	host=$(r "$PROG hostname" </dev/null) || die "router unreachable"
	host=$(printf '%s' "$host" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' | cut -c1-63)
	lead=${host%%[!.]*}; host=${lead//./_}${host#"$lead"} # leading dots would hide the file
	[[ -n $host ]] || host=router
	ts=$(date +%Y%m%d-%H%M%S)
	# the name is claimed with noclobber (an O_EXCL create), so a second
	# backup in the same second, from another router with the same hostname
	# or another run, gets a -2, -3, ... suffix instead of overwriting it
	bk="$BACKUPS/${host}-${ts}.tar.gz"; n=1
	until ( set -C; : > "$bk" ) 2>/dev/null; do
		n=$((n + 1))
		(( n <= 99 )) || die "cannot create a new backup file in $BACKUPS"
		bk="$BACKUPS/${host}-${ts}-$n.tar.gz"
	done
	BK_PARTIAL=$bk
	r "$PROG backup" </dev/null > "$bk"
	tar -tzf "$bk" >/dev/null 2>&1 || die "backup failed or corrupt (the partial file was removed): $(oneline "$bk")"
	BK_PARTIAL=
	PLAN_BACKUP=$bk
	log "BACKUP $(printf '%s' "$bk" | LC_ALL=C tr '\000-\037\177' ' ') ($(tar -tzf "$bk" | grep -c '^etc/config/[^/][^/]*$') config files)"
}

# fw_restart WHEN: restart the firewall so the live named nft objects match
# the config ($FW_LOADED: whether table inet fw4 was loaded before the apply).
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
# A change to named nft objects needs a firewall restart after its rollback
# (a reload keeps the live objects). $PLANS/<sid>.named, written before the
# apply with the FW_LOADED answer, says that restart is still owed; it goes
# when the change is confirmed or the restart after the rollback is made.
owed_fw_next() { printf '%s' "this change touched named nft objects, so the firewall must be restarted after the rollback (a reload keeps the live objects); run: $0 abort $ROUTER $SID (it restarts the firewall once the change is rolled back)"; }
fw_restart_owed() { [[ $SID =~ ^[0-9a-f]{32}$ && -e $PLANS/$SID.named ]]; }
# restart_owed_firewall WHEN: make the owed restart; 0 when none is owed or
# it worked (the record goes), 1 when it failed (the record stays)
restart_owed_firewall() {
	local loaded=
	fw_restart_owed || return 0
	IFS= read -r loaded < "$PLANS/$SID.named" || true
	[[ $loaded == [01] ]] || loaded=1
	FW_LOADED=$loaded
	fw_restart "$1" || return 1
	rm -f "$PLANS/$SID.named"
}
# die_fw_restart_failed: the abort rolled the change back, the restart failed
die_fw_restart_failed() {
	local first=
	IFS= read -r first < "$TMPD/fw.out" || true
	die "session $SID was rolled back, but the firewall restart after it failed: $(oneline "${first:-exit $FW_RESTART_RC}"); the live named nft objects may still hold the change; run: $0 abort $ROUTER $SID to restart the firewall again"
}

case $cmd in
backup)
	backup_now
	;;
plan)
	load_secret_catalog
	F=${3:-}; [[ -r $F ]] || die "changes file not readable: $F"
	# the router refuses any CR byte (stdin-bad-byte) without saying which
	if LC_ALL=C grep -q $'\r' "$F"; then die "changes file contains CR (convert CRLF line endings to LF): $F"; fi
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
	if (( rc == 255 )); then
		# the router program finishes a stage whose link dropped, so a
		# session may be open there; its id never reached this host
		first=; IFS= read -r first < "$TMPD/stage.err" || true
		die "the connection to the router failed while staging: $(oneline "$first"); whether the change was staged is not known; plan again (if the router then says it is busy with a session of this login, that refusal names it: abort that session, then plan again)"
	fi
	if (( rc != 0 )); then
		busy_next=
		first=; IFS= read -r first < "$TMPD/stage.err" || true
		if [[ $first =~ ^error\ busy\ ([^\ ]+)\ ([0-9a-f]{32})$ && ${BASH_REMATCH[1]} == "${HELLO_CALLER-}" ]]; then
			bsid=${BASH_REMATCH[2]}
			# an applied session is not staged: apply again is refused as
			# already applied, and the router rolls it back at its window end
			if [[ -e $PLANS/$bsid.held ]]; then
				busy_next="session $bsid of this login is applied and held on the router, not confirmed; confirm it ($0 confirm $ROUTER $bsid) or abort it ($0 abort $ROUTER $bsid), then plan again; left alone, the router rolls it back when its window ends"
			elif [[ -r $AUDIT ]] && [[ $(grep -E -- "^[^ ]+ [^ ]+ (APPLYING|APPLY REFUSED) session=$bsid\$" "$AUDIT" | tail -n 1) == *" APPLYING session=$bsid" ]]; then
			# the last apply of that session was sent and not refused by the
			# router (a refusal logs APPLY REFUSED: nothing was applied)
				busy_next="session $bsid of this login was applied and its window is still open; wait for that apply to end or abort it ($0 abort $ROUTER $bsid), then plan again; unless it is confirmed, the router rolls it back when its window ends"
			elif [[ ! -r $PLANS/$bsid.sha256 ]]; then
			# a stage whose link dropped: the session id never reached this
			# host, so there is no plan record here and an apply cannot run
				busy_next="session $bsid of this login is still open on the router and has no plan record on this host (a plan whose connection dropped while staging left it there), so it cannot be applied from here; abort it ($0 abort $ROUTER $bsid), then plan again; an open session left alone expires on the router after about 45 minutes"
			else
				busy_next="session $bsid of this login is still open on the router; apply it ($0 apply $ROUTER $bsid <its planned timeout>) or abort it ($0 abort $ROUTER $bsid), then plan again; an open session left alone expires on the router after about 45 minutes"
			fi
		elif [[ $first =~ ^error\ busy\ ([^\ ]+)\  ]]; then
			busy_next="another login ($(oneline "${BASH_REMATCH[1]}")) has a change open on the router; wait until it is applied or aborted (an open session left alone expires after about 45 minutes), then plan again"
		fi
		msg=; n=0
		while IFS= read -r line || [[ -n $line ]]; do
			[[ -z $msg ]] || msg+=' / '
			msg+=$(mask_secrets "$line")
			n=$((n + 1)); (( n >= 3 )) && break
		done < "$TMPD/stage.err"
		if [[ -n $msg ]]; then
			die "staging rejected: $msg${busy_next:+; $busy_next}"
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
		first=
		IFS= read -r first < "$TMPD/seal.err" || true
		if (( rc == 255 )); then
			discard_staged "the connection to the router failed while sealing the plan: $(oneline "$first")"
		fi
		discard_staged "probes refused: $(oneline "$first")"
	fi
	# parse the seal reply exactly as the program prints it (design 3.5b step 9); anything else is fatal
	bad_seal="malformed seal reply"
	readarray -t seal_lines <<< "$SEAL"
	(( ${#seal_lines[@]} >= 7 )) || discard_staged "$bad_seal"
	[[ ${seal_lines[0]} =~ ^base\ ([0-9a-f]{64})$ ]] || discard_staged "$bad_seal"; SEAL_BASE=${BASH_REMATCH[1]}
	[[ ${seal_lines[1]} =~ ^diff\ ([0-9a-f]{64})$ ]] || discard_staged "$bad_seal"; SEAL_DIFF=${BASH_REMATCH[1]}
	[[ ${seal_lines[2]} =~ ^probes\ ([0-9]+)\ ([0-9a-f]{64})$ ]] || discard_staged "$bad_seal"; SEAL_PROBES_N=${BASH_REMATCH[1]}; SEAL_PROBES_SHA=${BASH_REMATCH[2]}
	[[ ${seal_lines[3]} =~ ^t\ ([0-9]{2,3})$ ]] || discard_staged "$bad_seal"; [[ ${BASH_REMATCH[1]} == "$T" ]] || discard_staged "$bad_seal"
	[[ ${seal_lines[4]} =~ ^profile\ (lab|prod)$ ]] || discard_staged "$bad_seal"; SEAL_PROFILE=${BASH_REMATCH[1]}
	[[ ${seal_lines[${#seal_lines[@]}-2]} =~ ^approval\ (required|not-required)$ ]] || discard_staged "$bad_seal"; SEAL_APPROVAL=${BASH_REMATCH[1]}
	[[ ${seal_lines[${#seal_lines[@]}-1]} =~ ^digest\ ([0-9a-f]{64})$ ]] || discard_staged "$bad_seal"; SEAL_DIGEST=${BASH_REMATCH[1]}
	for (( k=5; k<${#seal_lines[@]}-2; k++ )); do
		[[ ${seal_lines[k]} == section\ * || ${seal_lines[k]} == leash\ * ]] || discard_staged "$bad_seal"
	done
	staged_check "$SID"
	# the staged diff is read before any plan record is written: a read that
	# fails discards the session, so no record is left to point at it
	DIFF_RAW=$(r "$PROG diff $SID" </dev/null 2>"$TMPD/diff.err"); rc=$?
	if (( rc != 0 )); then
		first=; IFS= read -r first < "$TMPD/diff.err" || true
		discard_staged "cannot read the staged diff of session $SID: $(oneline "${first:-exit $rc}")"
	fi
	printf '%s\n' "$SEAL_DIFF" > "$PLANS/$SID.sha256"
	printf '%s\n' "$SEAL_BASE" > "$PLANS/$SID.base"
	# the backup this plan took: ALERT and die lines name it, never "the
	# latest backup" (the backup directory is shared by every router)
	printf '%s\n' "$PLAN_BACKUP" > "$PLANS/$SID.backup"
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
	echo "----- diff -----"
	while IFS= read -r line || [[ -n $line ]]; do mask_secrets "$line"; done <<< "$DIFF_RAW"
	echo "----------------"
	echo "next: $0 apply $ROUTER $SID $T"
	echo "(to test the change before keeping it: $0 apply $ROUTER $SID $T --hold, then confirm or abort)"
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
	# --hold, last: run the verify rounds but do not confirm (see confirm).
	# Anything else after the timeout is refused, so a typo can never turn
	# into an apply that confirms on its own.
	HOLD=0
	if [[ ${4-} == --hold ]]; then
		(( $# == 4 )) || die "usage: $0 apply <router> <SID> [timeout] [--hold]; nothing applied"
		HOLD=1; T=90
	elif (( $# >= 5 )); then
		[[ $5 == --hold ]] && (( $# == 5 )) || die "usage: $0 apply <router> <SID> [timeout] [--hold]; nothing applied"
		HOLD=1
	fi
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
	add_rollback_reason() {
		local reason=$1
		[[ -z $rollback_reason ]] || rollback_reason+='; '
		rollback_reason+=$reason
	}
	# read_refused RC WHAT: a read before the apply exited RC. An exit 3
	# is the router's refusal; its first stderr line (in $TMPD/read.err)
	# and its next step are named, since a session gone after a reboot or
	# an rpcd restart is not still staged.
	read_refused() {
		local first=
		if (( $1 == 3 )); then
			IFS= read -r first < "$TMPD/read.err" || true
			die "$2: $(oneline "$first"); nothing applied; $(refusal_next_step "$first")"
		fi
		die "$2; nothing applied, session $SID is still staged"
	}
	need_sid "$SID"
	validate_timeout
	confirmed_here "$SID" && die "session $SID was already confirmed; nothing applied (run: $0 status $ROUTER $SID)"
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
		# the local check runs in every round of this run, and the confirm
		# of a held apply runs it once more, right before it asks the
		# router to confirm: a held change is checked in every round and
		# once more at the confirm
	fi
	handshake
	# the diff fetch: its sha256 must equal the plan record's, then the masked DIFF audit lines (rows 261-263).
	# A read the link cut short can still exit 0, so a mismatch is read once more; the second read must
	# match exactly too, and the DIFF lines come from the read that matched.
	PLAN_DIFF_SHA=$(cat "$PLANS/$SID.sha256")
	for diff_read in 1 2; do
		DIFF_RAW=$(r "$PROG diff $SID" </dev/null 2>"$TMPD/read.err") || read_refused $? "cannot read staged diff"
		if [[ -n $DIFF_RAW ]]; then
			DIFF_SHA=$(printf '%s\n' "$DIFF_RAW" | sha256sum | cut -d' ' -f1)
		else
			DIFF_SHA=$(sha256sum </dev/null | cut -d' ' -f1)
		fi
		[[ $DIFF_SHA == "$PLAN_DIFF_SHA" ]] && break
		(( diff_read == 2 )) && die "the staged diff does not match the plan, or the read of it was cut short; nothing applied; abort session $SID ($0 abort $ROUTER $SID), then plan the change again and approve it again"
	done
	while IFS= read -r line || [[ -n $line ]]; do log "DIFF session=$SID: $(mask_secrets "$line")"; done <<< "$DIFF_RAW"
	operator=${OWRT_OPERATOR:-${SUDO_USER:-${USER:-unknown}}}
	log "OPERATOR session=$SID: $(oneline "$operator")"
	NAMED=$(r "$PROG named $SID" </dev/null 2>"$TMPD/read.err") || read_refused $? "cannot inspect the staged change for named nft objects"
	FW_LOADED=0
	if [[ -n $NAMED ]]; then
		FW_LOADED=$(r "$PROG fw-loaded" </dev/null) || die "router unreachable before apply; nothing applied, session $SID is still staged"
		[[ $FW_LOADED == [01] ]] || die "unexpected answer while reading the firewall state: $(oneline "$FW_LOADED"); nothing applied, session $SID is still staged"
		named_log=$(oneline "$NAMED")
		log "NAMED NFT OBJECTS session=$SID: $named_log — a firewall reload keeps them, so the firewall will be restarted after the apply"
		# a held change can be rolled back with no run left to restart the
		# firewall after it, so the live nft objects would not match
		(( HOLD == 0 )) || die "--hold cannot be used for a change to named nft objects: their rollback needs the firewall restart this run makes after the window; nothing applied, session $SID is still staged"
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
	if (( health_rc == 3 )); then
		printf '%s\n' "$health_err" > "$TMPD/read.err"
		read_refused 3 "cannot record service and firewall health before the apply"
	fi
	if (( health_rc != 0 )); then
		health_detail=${health_err:+; helper said: $(oneline "$health_err")}
		die "cannot record service and firewall health before the apply; nothing applied, session $SID is still staged$health_detail"
	fi
	if [[ -n $NAMED ]]; then
		printf '%s\n' "$FW_LOADED" > "$PLANS/$SID.named" || die "cannot record that this change needs a firewall restart after a rollback; nothing applied, session $SID is still staged"
	fi
	log "APPLYING session=$SID"
	APPLY_SENT=1
	out=$(r "$PROG apply $SID $T $TOKEN $APPROVAL_NBF $APPROVAL_EXP" </dev/null 2>"$TMPD/apply.err"); arc=$?
	appl_re="^applied $SID t=$T guard=[0-9]+$"
	if (( arc == 0 )) && [[ $out =~ $appl_re ]]; then
		:
	elif (( arc == 3 )); then
		first=; IFS= read -r first < "$TMPD/apply.err" || true
		log "APPLY REFUSED session=$SID"
		rm -f "$PLANS/$SID.named"
		die "apply refused, nothing applied: $(oneline "$first"); $(refusal_next_step "$first")"
	elif (( arc == 1 )) && IFS= read -r first < "$TMPD/apply.err" && [[ $first == "error already-applied" ]]; then
		# the router refuses before it touches anything: an earlier run
		# applied this session (e.g. one that was interrupted)
		die "apply refused: the router says session $SID was already applied (by an earlier run); nothing applied by this run; unless that run confirms it, the router rolls it back by itself when its window ends; run: $0 status $ROUTER $SID"
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
	if (( good >= PASSES && HOLD == 1 )); then
		# held: the rounds passed and nothing is confirmed. The router's
		# rollback stays armed; `confirm` can confirm until held_until.
		held_until=$(( $(date +%s) + deadline - SECONDS ))
		# The fourth field of the hold record is the digest of the client
		# check this apply ran (0 when it ran none): the confirm of a
		# held apply runs that check again, right before it asks the
		# router to confirm, so a confirm that runs another check (or
		# none) must not confirm the change.  A record with three fields
		# is one of an older host: it ran no check.
		local_check=0
		if [[ -n ${OWRT_LOCAL_CHECK:-} ]]; then
			local_check=$(check_digest "$OWRT_LOCAL_CHECK") \
				|| die "cannot digest the client check of this apply; nothing is confirmed and the router rolls the change back when its ${T}s window ends"
		fi
		printf '%s %s %s %s\n' "$NEED_DHCP" "$PROBE_N" "$held_until" "$local_check" > "$PLANS/$SID.held" || \
			die "cannot record the hold of session $SID; nothing is confirmed and the router rolls the change back when its ${T}s window ends"
		(( DNSMASQ_TOUCHED == 0 )) || log "NOTE session=$SID: dnsmasq was restarted during the window; after an abort or the window end, check DNS and DHCP"
		log "HELD session=$SID until=$held_until ($PASSES consecutive passes; NOT confirmed: the router rolls the change back when its window ends, at $(date -d "@$held_until" -Is), unless it is confirmed first) confirm: $0 confirm $ROUTER $SID abort: $0 abort $ROUTER $SID"
		exit 0
	fi
	if (( good >= PASSES )); then
		CONFIRM_SENT=1
		out=$(r "$PROG confirm $SID" </dev/null 2>"$TMPD/confirm.err"); crc=$?
		if (( crc == 0 )) && [[ $out == "confirmed $SID" || $out == "confirmed $SID rpcd-timer-lost" ]]; then
			lost_note=
			[[ $out == "confirmed $SID rpcd-timer-lost" ]] && lost_note='; rpcd had lost its rollback timer, the guard held the window'
			# the hashes of the committed config, read once more after the
			# confirmation and printed on stdout for the caller.
			# A confighash problem prints a NO UNDO RECORD line and changes
			# nothing else: the CONFIRMED line below stays the last line of stdout.
			confighash_after_confirm
			log "CONFIRMED session=$SID ($PASSES consecutive passes: fresh ssh + router-side ping, dns, health and $PROBE_N probes${OWRT_LOCAL_CHECK:+ + local check})$lost_note"
			rm -f "$PLANS/$SID.sha256" "$PLANS/$SID.named"
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
				log "ALERT session=$SID abort did not report success: $(oneline "$first") — check the router now; compare it with $(plan_backup)"
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
				if (( health_rc == 255 )); then
					add_rollback_reason "the router was unreachable, so service or firewall health was not compared after the rollback: $(oneline "$health_err")"
				elif [[ ${health_err%%$'\n'*} == "health: not compared"* ]]; then
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
			if [[ -n $NAMED ]] && ! restart_owed_firewall "after rollback"; then
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
				post_ok=0; post_rc=0
				for (( attempt=1; attempt <= 5; attempt++ )); do
					r "$PROG dns-dhcp-check $NEED_DHCP" </dev/null 2>"$TMPD/post.err"; post_rc=$?
					if (( post_rc == 0 )); then
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
					if (( post_rc == 255 )); then
						add_rollback_reason "the router was unreachable, so DNS and DHCP were not checked after the dnsmasq restart: $post_err"
					else
						add_rollback_reason "DNS/DHCP check failed after the dnsmasq restart: $post_err"
					fi
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
			# the guard may have restored only now, in the abort: ask again
			q_line=$st_full
			if [[ $abort_how == rolled-back-by-guard ]]; then
				q_line=$(r "$PROG status $SID" </dev/null 2>/dev/null) || q_line=
				q_line=${q_line%%$'\n'*}
			fi
			quarantine_note "$q_line"
			if [[ -n $CONFIG_DIFF ]]; then
				log "ALERT session=$SID status=$safe_st after the rollback window, but the committed config differs from its state before the apply in: $safe_config_diff — the change may still be live (rpcd restarted during the window, or the change was confirmed outside Newton)${rollback_reason:+; also: $rollback_reason} — check the router now; compare it with $(plan_backup) (abort: $(oneline "$abort_how"))${QNOTE:+; $QNOTE}"
			elif [[ -z $rollback_reason ]]; then
				log "ROLLBACK WINDOW PASSED session=$SID — router reachable; the committed config matches its state before the apply ($CONFIG_COUNT packages compared); rolled back by $rollback_cause${QNOTE:+; $QNOTE}"
			else
				log "ALERT session=$SID rolled back, but $rollback_reason — check the router now; compare it with $(plan_backup) (abort: $(oneline "$abort_how"))${QNOTE:+; $QNOTE}"
			fi
			;;
		confirmed)
			rm -f "$PLANS/$SID.named"
			log "ALERT session=$SID status=confirmed after the rollback window — the change was confirmed outside this run; check the router now; compare it with $(plan_backup)"
			;;
		staged|inconsistent|unreachable)
			log "ALERT session=$SID status=$st after rollback window — check the router now; compare it with $(plan_backup)$(fw_restart_owed && printf '; %s' "$(owed_fw_next)")"
			;;
		*) log "ALERT session=$SID status=unexpected ($(oneline "$st")) after rollback window — check the router now; compare it with $(plan_backup)$(fw_restart_owed && printf '; %s' "$(owed_fw_next)")" ;;
		esac
		rm -f "$PLANS/$SID.sha256"
		exit 1
	fi
	;;
status)
	SID=${3:-}; need_sid "$SID"; handshake
	out=$(r "$PROG status $SID" </dev/null) || die "status did not answer — run: $0 status $ROUTER $SID"
	oneline "$out"
	quarantine_note "${out%%$'\n'*}"
	[[ -z $QNOTE ]] || echo "NOTE session=$SID: $QNOTE"
	running_note "${out%%$'\n'*}"
	[[ -z $RNOTE ]] || echo "NOTE session=$SID: $RNOTE"
	# the value of the running field, on a line of the host's own: the
	# router's line is cut at 120 characters and the field stands at its
	# end, so the cut drops it
	[[ -z $RVAL ]] || echo "RUNNING session=$SID $RVAL"
	held_line=; [[ -r $PLANS/$SID.held ]] && { IFS= read -r held_line < "$PLANS/$SID.held" || true; }
	if [[ $held_line =~ ^[0-2]\ [0-9]+\ ([0-9]+)(\ 0|\ [0-9a-f]{64})?$ ]] && (( $(date +%s) >= BASH_REMATCH[1] )); then
		if router_says_confirmed "$out"; then
			echo "NOTE session=$SID: the window of its held apply has passed and $(confirmed_live)"
		else
			held_closed_rolled_back "$out" \
				|| echo "NOTE session=$SID: the window of its held apply ended unconfirmed and $HELD_UNKNOWN_NEXT; compare the router's config with $(plan_backup), or run this status again"
		fi
	fi
	if router_says_confirmed "$out"; then
		reconcile_confirmed "the router's status says confirmed" || true
	elif fw_restart_owed && [[ $out =~ ^(rolled-back|gone)\ sid=$SID\  ]] && ! confirmed_here "$SID"; then
		echo "NOTE session=$SID: $(owed_fw_next)"
	elif [[ $out =~ ^gone\ sid=$SID\  ]] && confirmed_here "$SID"; then
		# the router keeps its confirm record in memory: a reboot or a
		# later confirm forgets it, this host's audit log does not
		echo "NOTE session=$SID: this host's audit log records it confirmed, so the change stays live (the router no longer remembers the confirm after a reboot or a later change); to undo it, plan the reverse change (newton_plan_undo)"
	fi
	;;
confirm)
	# confirm a change an `apply --hold` left armed. Only a held apply of
	# this host, only inside its window (the router refuses a late one
	# too), and only after one more verify round over a new connection.
	SID=${3:-}; need_sid "$SID"
	(( $# == 3 )) || die "usage: $0 confirm <router> <SID>; nothing confirmed"
	HELD_FILE=$PLANS/$SID.held
	confirmed_here "$SID" && die "session $SID was already confirmed; nothing confirmed (run: $0 status $ROUTER $SID)"
	held_next="to see where session $SID stands, run: $0 status $ROUTER $SID; to roll it back now: $0 abort $ROUTER $SID"
	[[ -r $HELD_FILE ]] || die "no held apply of session $SID on this host; nothing confirmed (only an apply run with --hold is confirmed here); $held_next"
	held_line=; IFS= read -r held_line < "$HELD_FILE" || true
	[[ $held_line =~ ^([0-2])\ ([0-9]+)\ ([0-9]+)(\ 0|\ [0-9a-f]{64})?$ ]] || die "the hold record of session $SID is malformed; nothing confirmed; an armed change rolls back on its own when its window ends; $held_next"
	NEED_DHCP=${BASH_REMATCH[1]}; PROBE_N=${BASH_REMATCH[2]}; held_until=${BASH_REMATCH[3]}
	# The fourth field is the digest of the client check the held apply
	# ran (0 when it ran none).  The confirm runs that check again, right
	# before it asks the router to confirm, so a confirm without it, or
	# with another one, would confirm a change nobody checked the way
	# the apply checked it: it is refused before the router is asked.  A
	# record with three fields is one of an older host: it ran no client
	# check.  A fourth field of 1 is malformed: no such record ever
	# shipped, so it is not read as a check of any kind.
	local_check=${BASH_REMATCH[4]:-}
	local_check=${local_check# }
	if [[ -n $local_check && $local_check != 0 ]]; then
		now_check=
		[[ -n ${OWRT_LOCAL_CHECK:-} ]] && now_check=$(check_digest "$OWRT_LOCAL_CHECK")
		if [[ -z $now_check || $now_check != "$local_check" ]]; then
			die "the held apply of session $SID ran a client check; run the confirm with the same OWRT_LOCAL_CHECK as the apply; nothing confirmed; $held_next"
		fi
	fi
	if (( $(date +%s) >= held_until )); then
		# the window ended unconfirmed: ask the router what it did
		handshake
		st=$(r "$PROG status $SID" </dev/null 2>/dev/null) || st=
		router_says_confirmed "$st" \
			&& die "the window of session $SID has closed; nothing confirmed by this run; $(confirmed_live)"
		held_closed_rolled_back "$st" \
			&& die "the window of session $SID has closed; nothing confirmed: the router rolled the change back (its status says rolled-back)"
		die "the window of session $SID has closed; nothing confirmed; $HELD_UNKNOWN_NEXT; run: $0 status $ROUTER $SID, and compare the router's config with $(plan_backup)"
	fi
	# check_failed WHAT MSG: a check before the confirm failed (WHAT says
	# which, MSG is the refusal when the session is still armed). An earlier
	# confirm may have reached the router after this host stopped waiting
	# (then its verify answers no-such-txn); the router's status decides,
	# so a confirmed session is never reported as rolling back.
	check_failed() {
		local st
		st=$(r "$PROG status $SID" </dev/null 2>/dev/null) || st=
		if router_says_confirmed "$st"; then
			reconcile_confirmed "the router's status says confirmed" || true
			rm -f "$HELD_FILE"
			die "session $SID is already confirmed on the router; nothing confirmed by this run; $(confirmed_live) (before this confirm, $1)"
		fi
		die "$2"
	}
	handshake
	r "$PROG verify $SID $NEED_DHCP" </dev/null >"$TMPD/round.out" 2>"$TMPD/round.err"; rc=$?
	if (( rc != 0 )); then
		first=; IFS= read -r first < "$TMPD/round.err" || true
		check_failed "the verify round failed: $(oneline "$first")" "verify failed before the confirm: $(oneline "$first"); not confirmed: the router rolls the change back when its window ends, or abort now: $0 abort $ROUTER $SID"
	fi
	if [[ -n ${OWRT_LOCAL_CHECK:-} ]]; then
		bash -c "$OWRT_LOCAL_CHECK" >/dev/null 2>"$TMPD/local.err"; lrc=$?
		(( lrc == 0 )) || check_failed "the local check failed (exit $lrc)" "the local check failed before the confirm (exit $lrc); not confirmed: the router rolls the change back when its window ends, or abort now: $0 abort $ROUTER $SID"
	fi
	logd_now=$(logd_pid </dev/null) || check_failed "the router was unreachable" "router unreachable before the confirm; not confirmed; run: $0 status $ROUTER $SID"
	[[ -n $logd_now ]] || check_failed "logd was not running" "logd is not running: not confirming while the system log is down; the router rolls the change back when its window ends"
	CONFIRM_SENT=1
	out=$(r "$PROG confirm $SID" </dev/null 2>"$TMPD/confirm.err"); crc=$?
	first=; IFS= read -r first < "$TMPD/confirm.err" || true
	if (( crc == 0 )) && [[ $out == "confirmed $SID" || $out == "confirmed $SID rpcd-timer-lost" ]]; then
		lost_note=
		[[ $out == "confirmed $SID rpcd-timer-lost" ]] && lost_note='; rpcd had lost its rollback timer, the guard held the window'
		confighash_after_confirm
		log "CONFIRMED session=$SID (held apply: $PASSES consecutive passes, then one more fresh ssh + router-side round before the confirm${OWRT_LOCAL_CHECK:+ + local check})$lost_note"
		rm -f "$PLANS/$SID.sha256" "$HELD_FILE"
	elif (( crc == 3 )) || [[ $crc == 1 && ( $first == 'error rpcd-confirm-failed'* || $first == 'error confirm-incomplete'* ) ]]; then
		reason=$(oneline "$first"); reason=${reason:-exit $crc}
		# a confirm that overlapped this one may have taken first (then the
		# router answers no-such-txn): its status decides
		check_failed "the router refused this confirm: $reason" "confirm refused: $reason; not confirmed: the router rolls the change back on its own; run: $0 status $ROUTER $SID"
	else
		log "CONFIRM DID NOT REPORT SUCCESS session=$SID — OUTCOME UNKNOWN; run: $0 status $ROUTER $SID"; exit 1
	fi
	;;
abort)
	SID=${3:-}; need_sid "$SID"
	# read before anything is logged: a log line would create a missing log
	audit_readable=0; [[ -f $AUDIT && -r $AUDIT ]] && audit_readable=1
	handshake
	out=$(r "$PROG abort $SID" </dev/null 2>"$TMPD/abort.err"); arc=$?
	# the router refuses a confirmed session only while its last line
	# names it; after a later session it answers "gone". This host's audit
	# log keeps the CONFIRMED line, so "gone" for a session confirmed here
	# is the same refusal. A live session is always aborted first.
	if (( arc == 0 )) && [[ $out == "aborted $SID gone" ]] && confirmed_here "$SID"; then
		die "abort refused: session $SID was already confirmed; the change stays live. To undo it, plan the reverse change (newton_plan_undo)"
	elif (( arc == 0 )) && [[ $out == "aborted $SID gone" ]] && aborted_here "$SID"; then
		# an earlier abort from this host discarded or rolled it back
		rm -f "$PLANS/$SID.sha256" "$PLANS/$SID.held"
		restart_owed_firewall "after abort" || die_fw_restart_failed
		echo "session $SID was already aborted on this host; nothing to do"
		exit 0
	elif (( arc == 0 )) && [[ $out == "aborted $SID gone" ]] && (( ! audit_readable )); then
		# without this host's audit log the confirmed check cannot run:
		# nothing was rolled back by this abort, so it never says ABORTED
		die "the router no longer has session $SID and this host's audit log ($AUDIT) cannot be read, so whether the change was confirmed, rolled back or is still live is not known from this host; this abort rolled nothing back. Check: $0 status $ROUTER $SID, and compare the router's config with $(plan_backup)"
	elif (( arc == 0 )) && [[ $out == "aborted $SID gone" ]]; then
		# "gone" rolled nothing back: the router no longer had the session
		# (a later session or a reboot), and a confirm killed before this
		# host logged CONFIRMED leaves the change live. Only the router's
		# status line decides; this abort never says ABORTED for it.
		st=$(r "$PROG status $SID" </dev/null 2>/dev/null) || st=
		oneline "$st"
		if router_says_confirmed "$st"; then
			reconcile_confirmed "the router's status says confirmed" || true
			die "abort refused: session $SID was already confirmed; the change stays live. To undo it, plan the reverse change (newton_plan_undo)"
		fi
		if [[ $st =~ ^rolled-back\ sid=$SID\  ]]; then
			# a line of its own: the server writes the rolled-back receipt of
			# a held apply from it
			[[ -e $PLANS/$SID.held ]] && log "HELD APPLY ROLLED BACK session=$SID (the abort found the session gone; the router's status says rolled-back)"
			rm -f "$PLANS/$SID.sha256" "$PLANS/$SID.held"
			restart_owed_firewall "after abort" || die_fw_restart_failed
			log "the router no longer has session $SID and its status says rolled-back; this abort rolled nothing back"
			exit 0
		fi
		if [[ $st =~ ^gone\ sid=$SID\  && ! -e $PLANS/$SID.held && ! -e $PLANS/$SID.sha256 ]] \
			&& ! grep -qE -- "^[^ ]+ [^ ]+ (STAGED|APPLYING) session=$SID( |\$)" "$AUDIT"; then
			# no plan record and no STAGED or APPLYING line: this host never
			# planned this id (a mistyped or copied-wrong id)
			die "the router has no session $SID, and this host has no plan of it (no plan record, no STAGED or APPLYING line in its audit log), so this abort rolled nothing back and the change you meant is untouched; check the session id (the plan's STAGED line names it), then abort that one"
		fi
		if [[ $st =~ ^gone\ sid=$SID\  && ! -e $PLANS/$SID.held ]] \
			&& ! grep -qE -- "^[^ ]+ [^ ]+ APPLYING session=$SID\$" "$AUDIT"; then
			# the router's status says gone, and no apply of it was ever sent
			# from this host (the first abort's answer was lost, so no ABORTED
			# line was logged): it was only staged
			rm -f "$PLANS/$SID.sha256"
			echo "the router no longer has session $SID, and this host never applied it (its audit log has no APPLYING line for it): it was only staged, so nothing of it is live from this host and this abort had nothing to roll back"
			exit 0
		fi
		die "the router no longer has session $SID; this abort rolled nothing back, and $HELD_UNKNOWN_NEXT: the change may still be live. Check: $0 status $ROUTER $SID, and compare the router's config with $(plan_backup)"
	elif (( arc == 0 )) && [[ $out == "aborted $SID "* ]]; then
		log "ABORTED session=$SID ($(oneline "${out#aborted $SID }"))"
		# a line of its own (router text never starts a line): the server
		# writes the rolled-back receipt of a held apply from it
		[[ -e $PLANS/$SID.held ]] && log "HELD APPLY ABORTED session=$SID"
		if [[ $out == "aborted $SID rolled-back-by-guard" ]]; then
			st=$(r "$PROG status $SID" </dev/null 2>/dev/null) || st=
			quarantine_note "${st%%$'\n'*}"
			[[ -z $QNOTE ]] || log "NOTE session=$SID: $QNOTE"
		fi
		rm -f "$PLANS/$SID.sha256" "$PLANS/$SID.held"
		restart_owed_firewall "after abort" || die_fw_restart_failed
	elif [[ $out == "refused $SID confirmed" ]]; then
		# a confirmed change has no rollback left; nothing was aborted
		reconcile_confirmed "the router refused the abort: it says confirmed" || true
		die "abort refused: session $SID was already confirmed; the change stays live. To undo it, plan the reverse change (newton_plan_undo)"
	else
		first=; IFS= read -r first < "$TMPD/abort.err" || true
		die "abort did not report success: $(oneline "$first"); run: $0 status $ROUTER $SID"
	fi
	;;
*) sed -n '2,33p' "$0"; exit 2 ;;
esac
