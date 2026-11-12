#!/bin/sh
# Newton owner script. Template owner-v1. Kind restore.
# Plan 9e8d7c6b5a4938271605f4e3d2c1b0a9 for device lab-r1.
# Runs as root on your router, sent by newton-router-setup over your own admin login.
# It restores what plan 3f9a1c0be2d44b17a1c3d5e7f9012345 changed, with the router's own undo timer of 180 s.
# If the router reboots or its web service restarts in those 180 s, the change stays.
# Touches: firewall.cfg0a1b2c.dest_port
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LC_ALL=C; export LC_ALL
umask 077
PLAN='9e8d7c6b5a4938271605f4e3d2c1b0a9'
WINDOW=180
die() { echo "NEWTON-STOP: $*"; exit 1; }
[ "$(id -u </dev/null)" = 0 ] || die "this must run as root"
echo "NEWTON-APPLYING plan=$PLAN"
W=$(mktemp -d /tmp/newton-owner.XXXXXX </dev/null) || die "no private directory"
trap 'rm -rf "$W"' EXIT
trap 'rm -rf "$W"; exit 1' HUP INT TERM
[ -z "$(uci changes </dev/null)" ] || die "the router has uncommitted changes"
undo_now=$(date +%s 2>/dev/null </dev/null) || undo_now=''
undo_newest=0
for undo_f in /var/run/rpcd/snapshot-files/*; do
  [ -f "$undo_f" ] || continue
  undo_m=$(stat -c %Y "$undo_f" 2>/dev/null </dev/null) || undo_m=''
  case "$undo_m" in
    '' | *[!0-9]*) continue ;;
  esac
  if [ "$undo_m" -gt "$undo_newest" ]; then undo_newest=$undo_m; fi
done
# shellcheck disable=SC2217
if [ -n "$(ls -A /var/run/rpcd/snapshot-files 2>/dev/null </dev/null)" ]; then
  if [ -n "$undo_now" ] && [ "$undo_newest" -gt 0 ]; then
    undo_age=$((undo_now - undo_newest))
    if [ "$undo_age" -ge 900 ]; then
      undo_mins=$((undo_age / 60))
      if [ "$undo_mins" -ge 1440 ]; then
        undo_days=$((undo_mins / 1440))
        if [ "$undo_days" -eq 1 ]; then undo_text="1 day"; else undo_text="$undo_days days"; fi
      elif [ "$undo_mins" -ge 60 ]; then
        undo_hours=$((undo_mins / 60))
        if [ "$undo_hours" -eq 1 ]; then undo_text="1 hour"; else undo_text="$undo_hours hours"; fi
      else
        if [ "$undo_mins" -eq 1 ]; then undo_text="1 minute"; else undo_text="$undo_mins minutes"; fi
      fi
      die "the router has a leftover undo file from $undo_text ago (its web service restarted during a change). If nobody is changing the router right now, reboot it, or as root run: rm -rf /var/run/rpcd/snapshot-files"
    fi
  fi
  die "another change is waiting for confirmation (LuCI or Newton)"
fi
if [ -d /var/run/rpcd/snapshot-files ]; then echo "NEWTON-NOTE: the router has an empty leftover from a refused change (/var/run/rpcd/snapshot-files); it does not block Newton"; fi
want() { got=$(uci -q get "$1" </dev/null) && [ "$got" = "$2" ] || die "the router changed since the plan: $1"; }
absent() { if uci -q get "$1" >/dev/null </dev/null; then die "the router changed since the plan: $1"; fi; }
want 'firewall.cfg0a1b2c.dest_port' '2222'
echo "NEWTON-CHECKED plan=$PLAN"
SID=$(ubus call session create "{\"timeout\":$((WINDOW + 120))}" </dev/null | jsonfilter -e '@.ubus_rpc_session')
drop_session() { printf '%s' "$SID" | grep -Eq '^[0-9a-f]{32}$' || return 0; ubus call session destroy "{\"ubus_rpc_session\":\"$SID\"}" </dev/null >/dev/null 2>&1; }
lookup_fail() { drop_session; die "could not locate the rpcd session folder"; }
printf '%s' "$SID" | grep -Eq '^[0-9a-f]{32}$' || { drop_session; die "could not open a session"; }
ubus call session grant "{\"ubus_rpc_session\":\"$SID\",\"scope\":\"uci\",\"objects\":[[\"*\",\"read\"],[\"*\",\"write\"]]}" </dev/null >/dev/null || { drop_session; die "could not open a session"; }
ubus call session grant "{\"ubus_rpc_session\":\"$SID\",\"scope\":\"ubus\",\"objects\":[[\"uci\",\"confirm\"]]}" </dev/null >/dev/null || { drop_session; die "could not open a session"; }
SECTION=$(ubus call uci add "{\"config\":\"system\",\"type\":\"newton_probe\",\"ubus_rpc_session\":\"$SID\"}" </dev/null | jsonfilter -e '@.section')
case "$SECTION" in
  '' | *[!A-Za-z0-9_]*) lookup_fail ;;
esac
[ "${#SECTION}" -le 64 ] || lookup_fail
NP=$(grep -Fxl "+system.$SECTION='newton_probe'" /var/run/rpcd/uci-*/system </dev/null 2>/dev/null)
NP_N=$(printf '%s\n' "$NP" | grep -c .)
[ "$NP_N" -eq 1 ] || lookup_fail
NP_DIR=${NP%/*}
NP_NAME=${NP_DIR##*/}
NP_HEX=${NP_NAME#uci-}
[ "$NP_HEX" != "$NP_NAME" ] || lookup_fail
[ "${#NP_HEX}" -eq 32 ] || lookup_fail
case "$NP_HEX" in *[!0-9a-f]*) lookup_fail ;; esac
case "$NP_DIR" in /var/run/rpcd/*) ;; *) lookup_fail ;; esac
ubus call uci revert "{\"config\":\"system\",\"ubus_rpc_session\":\"$SID\"}" </dev/null >/dev/null || lookup_fail
if [ -s "$NP_DIR/system" ]; then lookup_fail; fi
D="$NP_DIR"
stage() { "$@" </dev/null >/dev/null 2>"$W/err" && [ ! -s "$W/err" ] || die "the router refused a change; nothing was applied"; }
stage uci -P "$D" set 'firewall.cfg0a1b2c.dest_port=22'
[ -n "$(uci -P "$D" changes </dev/null)" ] || die "nothing to apply"
echo "NEWTON-STAGED plan=$PLAN"
trap '' HUP INT TERM
ubus call uci apply "{\"ubus_rpc_session\":\"$SID\",\"rollback\":true,\"timeout\":$WINDOW}" </dev/null >/dev/null || die "the router refused the apply; nothing changed"
echo "NEWTON-APPLIED plan=$PLAN window=$WINDOW session=$SID"
