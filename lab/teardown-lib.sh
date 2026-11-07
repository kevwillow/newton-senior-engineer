#!/usr/bin/env bash

# Passive helpers for live scenario teardown. Sourcing this file performs no
# work and contacts nothing; callers provide their own rsh and setup functions.

newton_key_records() {
	awk '
	index($0, "command=\"/usr/libexec/newton/newton-router ") ||
	index($0, "command=\"/usr/libexec/newton/newton-router\"") {
		label = "-"
		role = "-"
		if (match($0, /--caller=[^ "]+/))
			label = substr($0, RSTART + 9, RLENGTH - 9)
		if (match($0, /--role=[^ "]+/))
			role = substr($0, RSTART + 7, RLENGTH - 7)
		if (label !~ /^[a-z][a-z0-9-]{1,31}$/) {
			print "warning: skipped a Newton key with an invalid label" > "/dev/stderr"
			next
		}
		if (role != "change" && role != "read") {
			print "warning: skipped a Newton key with an invalid role" > "/dev/stderr"
			next
		}
		printf "%s\t%s\t%s\n", label, role, $0
	}'
}

newton_key_labels() {
	newton_key_records | awk -F '\t' '{ print $1 " " $2 }' | sort -u
}

capture_newton_keys() {
	local outfile="${1-}" text rc

	rc=0
	text=$(rsh 'cat /etc/dropbear/authorized_keys') || rc=$?
	[[ $rc -eq 0 ]] || return "$rc"
	printf '%s\n' "$text" | newton_key_labels >"$outfile"
}

readd_newton_keys() {
	local baseline="${1-}" keys_dir="${2-}" device="${3-}"
	local label role line keyfile rc base_fp after_fp after_file
	local predicted predicted_fp
	local cur old_umask rsh_rc current_rc
	local label_pattern baseline_rc baseline_count router_rc router_count
	local -a missing_labels=() missing_roles=() missing_lines=()
	local i

	old_umask=$(umask)
	umask 077
	cur=$(mktemp) || {
		umask "$old_umask"
		return 1
	}
	rsh_rc=0
	rsh 'cat /etc/dropbear/authorized_keys' >"$cur" || rsh_rc=$?
	if [[ $rsh_rc -ne 0 ]]; then
		rm -f -- "$cur"
		umask "$old_umask"
		printf '%s\n' 'STOP cannot read authorized_keys'
		return "$rsh_rc"
	fi
	umask "$old_umask"

	# Pass 1 decides every label before the first router write, so a
	# conflict for a later key cannot follow a re-add for an earlier one.
	while IFS=$'\t' read -r label role line; do
		[[ -n "$label" ]] || continue

		label_pattern="--caller=${label}([ \"]|\$)"
		baseline_rc=0
		baseline_count=$(grep -cE -- "$label_pattern" "$baseline") ||
			baseline_rc=$?
		if [[ $baseline_rc -ne 0 && $baseline_rc -ne 1 ]]; then
			rm -f -- "$cur"
			return "$baseline_rc"
		fi
		if [[ $baseline_count -gt 1 ]]; then
			rm -f -- "$cur"
			printf 'STOP the baseline has two Newton key lines for %s\n' "$label"
			return 1
		fi

		router_rc=0
		router_count=$(grep -cE -- "$label_pattern" "$cur") || router_rc=$?
		if [[ $router_rc -ne 0 && $router_rc -ne 1 ]]; then
			rm -f -- "$cur"
			return "$router_rc"
		fi

		if [[ $router_count -gt 1 ]]; then
			rm -f -- "$cur"
			printf 'STOP %s has %d key lines on the router; not replaced\n' \
				"$label" "$router_count"
			return 1
		fi
		if [[ $router_count -eq 1 ]]; then
			current_rc=0
			grep -qxF -- "$line" "$cur" || current_rc=$?
			if [[ $current_rc -eq 0 ]]; then
				printf '== keep %s already on the router\n' "$label" || {
					rm -f -- "$cur"
					return 1
				}
				continue
			fi
			if [[ $current_rc -eq 1 ]]; then
				rm -f -- "$cur"
				printf 'STOP a different Newton key line for %s is on the router; not replaced\n' "$label"
				return 1
			fi
			rm -f -- "$cur"
			return "$current_rc"
		fi

		if [[ $router_count -ne 0 ]]; then
			rm -f -- "$cur"
			return 1
		fi

		missing_labels+=("$label")
		missing_roles+=("$role")
		missing_lines+=("$line")
	done < <(newton_key_records <"$baseline")

	# Predict the only layout pass 2 is allowed to produce before the
	# first router write: the current bytes plus each missing line.
	old_umask=$(umask)
	umask 077
	predicted=$(mktemp) || {
		umask "$old_umask"
		rm -f -- "$cur"
		return 1
	}
	umask "$old_umask"
	rc=0
	cp -- "$cur" "$predicted" || rc=$?
	if [[ $rc -ne 0 ]]; then
		rm -f -- "$cur" "$predicted"
		return "$rc"
	fi
	for ((i = 0; i < ${#missing_lines[@]}; i++)); do
		rc=0
		printf '%s\n' "${missing_lines[i]}" >>"$predicted" || rc=$?
		if [[ $rc -ne 0 ]]; then
			rm -f -- "$cur" "$predicted"
			return "$rc"
		fi
	done
	rc=0
	base_fp=$(sha256sum -- "$baseline") || rc=$?
	if [[ $rc -ne 0 ]]; then
		rm -f -- "$cur" "$predicted"
		return "$rc"
	fi
	base_fp=${base_fp%% *}
	rc=0
	predicted_fp=$(sha256sum -- "$predicted") || rc=$?
	if [[ $rc -ne 0 ]]; then
		rm -f -- "$cur" "$predicted"
		return "$rc"
	fi
	predicted_fp=${predicted_fp%% *}
	if [[ "$base_fp" != "$predicted_fp" ]]; then
		rm -f -- "$cur" "$predicted"
		printf '%s\n' \
			'STOP the baseline cannot be restored by appending the missing key lines; nothing changed'
		return 1
	fi
	rc=0
	rm -f -- "$cur" "$predicted" || rc=$?
	[[ $rc -eq 0 ]] || return "$rc"

	# Pass 2 re-adds only the labels that survived pass 1.
	for ((i = 0; i < ${#missing_labels[@]}; i++)); do
		label=${missing_labels[i]}
		role=${missing_roles[i]}
		line=${missing_lines[i]}
		keyfile="${keys_dir}/${device}-${label}"
		if [[ -f "$keyfile" ]]; then
			if setup add-key "$label" "$role"; then
				rc=0
			else
				rc=$?
			fi
			printf '== re-add %s via add-key rc=%d\n' "$label" "$rc" || {
				rm -f -- "$cur"
				return 1
			}
			if [[ $rc -ne 0 ]]; then
				rm -f -- "$cur"
				return "$rc"
			fi
		else
			# LABEL is never put in the remote text.  The fixed remote script
			# reads it from stdin, followed by the exact baseline line.
			if printf '%s\n%s\n' "$label" "$line" | rsh '
				f=/etc/dropbear/authorized_keys
				IFS= read -r label || exit 1
				IFS= read -r line || exit 1
				[ -n "$label" ] || exit 1
				[ -n "$line" ] || exit 1
				[ -e "$f" ] || exit 1
				grep_rc=0
				grep -qE -- "--caller=$label([ \"]|$)" "$f" ||
					grep_rc=$?
				[ "$grep_rc" -eq 1 ] || exit 1
				last=$(tail -c 1 "$f") || exit 1
				[ -z "$last" ] || exit 1
				printf "%s\n" "$line" >> "$f"
			'; then
				rc=0
			else
				rc=$?
			fi
			printf '== re-add %s byte-exact rc=%d\n' "$label" "$rc" || {
				rm -f -- "$cur"
				return 1
			}
			if [[ $rc -ne 0 ]]; then
				rm -f -- "$cur"
				return "$rc"
			fi
		fi
	done

	rm -f -- "$cur"

	rc=0
	base_fp=$(sha256sum -- "$baseline") || rc=$?
	[[ $rc -eq 0 ]] || return "$rc"
	base_fp=${base_fp%% *}
	old_umask=$(umask)
	umask 077
	after_file=$(mktemp) || {
		umask "$old_umask"
		return 1
	}
	rsh_rc=0
	rsh 'cat /etc/dropbear/authorized_keys' >"$after_file" || rsh_rc=$?
	if [[ $rsh_rc -ne 0 ]]; then
		rm -f -- "$after_file"
		umask "$old_umask"
		printf '%s\n' 'STOP cannot read authorized_keys'
		return "$rsh_rc"
	fi
	rc=0
	after_fp=$(sha256sum -- "$after_file") || rc=$?
	rm -f -- "$after_file"
	umask "$old_umask"
	[[ $rc -eq 0 ]] || return "$rc"
	after_fp=${after_fp%% *}
	if [[ "$base_fp" != "$after_fp" ]]; then
		printf '%s\n' 'STOP authorized_keys differs from the baseline'
		return 1
	fi
	# Appending restores the baseline only when the missing Newton lines are
	# the trailing block of the baseline in the same order.  Any other layout
	# STOPs in the pre-write prediction above; this final check still guards
	# what add-key and each remote append really wrote.
	return 0
}

baseline_diff_or_stop() {
	local base_fp="${1-}" after_fp="${2-}" rc
	if awk '
	function path_of(line, path) {
		path = line
		sub(/^[^ ]+[ ][ ]?/, "", path)
		sub(/^\//, "", path)
		return path
	}
	function plain(path) {
		sub(/^\//, "", path)
		return path
	}
	function ignored(path) {
		path = plain(path)
		return path == "etc/newton/guard.log" || index(path, "etc/newton/lkg/") == 1
	}
	FNR == NR {
		path = path_of($0)
		if (!ignored(path)) {
			before[path] = $1
		}
		next
	}
	{
		path = path_of($0)
		if (!ignored(path)) {
			after[path] = $1
		}
	}
	END {
		different = 0
		keys_different = 0
		for (path in before) {
			if (!(path in after)) {
				print "  files: " path
				different = 1
			} else if (before[path] != after[path]) {
				print "  changed: " path
				different = 1
			}
			if (path == "etc/dropbear/authorized_keys" &&
			    (!(path in after) || before[path] != after[path]))
				keys_different = 1
		}
		for (path in after) {
			if (!(path in before)) {
				print "  files: " path
				different = 1
				if (path == "etc/dropbear/authorized_keys")
					keys_different = 1
			}
		}
		if (keys_different)
			exit 10
		if (different)
			exit 11
	}' "$base_fp" "$after_fp"; then
		rc=0
	else
		rc=$?
	fi
	case "$rc" in
		0) return 0 ;;
		10)
			printf '%s\n' 'STOP authorized_keys differs from the baseline: a key was removed or not restored'
			return 1
			;;
		*)
			printf '%s\n' 'STOP files differ from the baseline'
			return 1
			;;
	esac
}
