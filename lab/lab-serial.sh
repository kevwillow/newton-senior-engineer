#!/usr/bin/env bash
# lab-serial.sh — expose a Newton lab VM's serial console on this host as socket://127.0.0.1:<port>.
#
#   lab-serial.sh up <vmid>      bridge apollo:/var/run/qemu-server/<vmid>.serial0 -> 127.0.0.1:(7000+vmid) here
#   lab-serial.sh down <vmid>    remove the bridge and tunnel
#   lab-serial.sh url <vmid>     print the pyserial URL
#
# On the Proxmox host a transient systemd unit runs socat bound to 127.0.0.1 only; this host reaches it
# through an ssh -L tunnel, so the console is never exposed on the network. One client at a time
# (the QEMU serial socket accepts a single connection; socat forks per TCP connection).
set -euo pipefail
# The Proxmox host: the live one lives in the lab file next to this script
# ([pve] host).  NEWTON_LAB_PVE overrides it.
PVE_HOST=$(sed -n '/^\[pve\]/,/^\[/ s/^host = "\(.*\)"$/\1/p' "$(dirname -- "$0")/lab.toml" 2>/dev/null | head -1)
PVE=${NEWTON_LAB_PVE:-root@${PVE_HOST:-192.0.2.11}}
KEY=${NEWTON_LAB_KEY:-$HOME/.ssh/claude-apollo}
SSH=(ssh -i "$KEY" -o BatchMode=yes -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=8)

cmd=${1:-}; id=${2:-}
[[ $id =~ ^[0-9]+$ ]] || { sed -n '2,8p' "$0"; exit 2; }
port=$((7000 + id))
tunnel_pid() { ps -eo pid=,args= | awk -v p="$port:127.0.0.1:$port" '$2=="ssh" && index($0, p) {print $1}'; }

case $cmd in
up)
	"${SSH[@]}" "$PVE" "test -S /var/run/qemu-server/$id.serial0 || { echo 'VM $id has no running serial0 socket' >&2; exit 1; }
		systemctl is-active -q newton-serial-$id || systemd-run -q --unit=newton-serial-$id --collect \
			socat TCP-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/var/run/qemu-server/$id.serial0"
	[[ -n $(tunnel_pid) ]] || "${SSH[@]}" -o ExitOnForwardFailure=yes -f -N -L "$port:127.0.0.1:$port" "$PVE"
	echo "socket://127.0.0.1:$port"
	;;
down)
	p=$(tunnel_pid); [[ -n $p ]] && kill $p
	"${SSH[@]}" "$PVE" "systemctl stop newton-serial-$id 2>/dev/null || true"
	echo "down $id"
	;;
url) echo "socket://127.0.0.1:$port" ;;
*) sed -n '2,8p' "$0"; exit 2 ;;
esac
