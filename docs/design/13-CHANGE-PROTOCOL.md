# 13. The change protocol

Newton changes a device in six modes, and every mode follows the same contract:
the ten rules below hold wherever Newton writes. Each cell of the contract table
names the tests that prove one rule in one mode, so a rule that nothing proves
today is a gap and not a promise. `mcp/tests/test_protocol_contract.py` reads
that table and fails when a cited test is gone, when a mode cell is empty, when
a row is missing, or when a gap has no bullet of its own.

## Modes

- **OpenWrt installed**: the router runs the Newton program
  (`device/openwrt/newton-router/newton-router`) and the guard
  (`device/openwrt/newton-guard/newton-guard`); the host drives it with
  `scripts/owrt-change.sh`.
- **OpenWrt no-install**: the router runs no Newton program; the host drives
  rpcd and uci over the router's HTTPS JSON-RPC web API
  (`mcp/newton_mcp/noinstall_flow.py`, `mcp/newton_mcp/noinstall_read.py`).
- **VyOS/Junos**: the device holds its own revert in a commit-confirm
  (`mcp/newton_mcp/vendor_change.py`, `mcp/newton_mcp/adapters/vendor_write.py`,
  `mcp/newton_mcp/adapters/junos_write.py`).
- **CHR**: the router reboots into a backup that a scheduler entry loads
  (`mcp/newton_mcp/adapters/routeros_write.py`).
- **AD write**: one reversible change on a domain controller
  (`mcp/newton_mcp/ad/write/apply.py`).
- **AD build**: the staged company build, one checkpoint per stage
  (`mcp/newton_mcp/ad/build/run.py`).

## Rules

1. Owner's yes in chat, plus the explanation sealed into the plan hash.
2. Plan sealed: the batch, explanation and probes are fixed at plan time.
3. Out-of-band approval bound to the plan digest and its time window.
4. Diff unchanged between plan and apply.
5. Undo armed before the first write (guard / rpcd timer / commit-confirm /
   scheduler+backup / DC undo / checkpoint for AD build).
6. Verify over fresh connections.
7. Confirm only after a verified record (the record on the router in installed
   mode).

   The host (newton-ctl) is trusted and the agent cannot read the router key
   (`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`, "Trust boundaries"). The
   verify record therefore defends the device against host bugs, crashes and
   partial runs, not against a host that crafts hostile arguments.
8. A fixed set of outcomes. An unknown outcome is never reported as success and
   never retried blindly.
9. After an automatic restore, the running settings are shown to match, or
   Newton says plainly they may not and prints the fix.  A restore at boot is
   the one case with nothing to compare: the services started from the
   restored files, so the status says `running=boot`, and no comparison and
   no fix belong to it.
10. Controller lost mid-change: the device ends in the pre-change state or the
    confirmed state, never in between (recorded runs that kill the controller at
    set points, on fakes and on the lab router).

## Contract table

<!-- contract-table:start -->
| # | Rule | OpenWrt installed | OpenWrt no-install | VyOS/Junos | CHR | AD write | AD build |
|---|---|---|---|---|---|---|---|
| 1 | Owner's yes | `mcp/tests/test_explanation_plan.py::test_owner_confirmation_must_be_boolean_true`<br>`mcp/tests/test_explanation_plan.py::test_changing_any_explanation_field_changes_the_plan_hash`<br>`mcp/tests/test_approve_explanation.py::test_newton_approve_refuses_a_record_without_the_owner_chat_yes` | `mcp/tests/test_noinstall_flow.py::test_changing_any_explanation_field_changes_the_no_install_plan_hash`<br>`mcp/tests/test_noinstall_apply.py::test_a_record_without_the_owner_yes_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_a_record_whose_explanation_was_edited_and_hashed_again_is_refused` | `mcp/tests/test_vendor_flow.py::test_the_explanation_is_a_field_of_the_vyos_plan_hash`<br>`mcp/tests/test_junos_flow.py::test_the_explanation_is_a_field_of_the_junos_plan_hash` | `mcp/tests/test_routeros_flow.py::test_a_chr_plan_without_the_explanation_or_the_owner_yes_calls_no_device`<br>`mcp/tests/test_routeros_flow.py::test_the_explanation_and_the_owner_yes_are_fields_of_the_chr_plan_hash` | n/a: the AD write plan carries no explanation and no chat yes; the owner approves in their own terminal with a passphrase | n/a: the build plan carries no explanation and no chat yes; the owner approves the plan in their own terminal with a passphrase  |
| 2 | Plan sealed at plan time | `device/openwrt/newton-router/tests/test_seal.py::test_plan_digest_changes_with_every_ingredient`<br>`mcp/tests/test_explanation_plan.py::test_an_edited_explanation_on_disk_without_a_new_hash_is_refused_at_apply` | `mcp/tests/test_noinstall_apply.py::test_a_record_whose_explanation_was_edited_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_a_record_whose_probes_were_edited_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_a_record_whose_checks_were_edited_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_a_record_whose_explanation_claims_were_edited_is_refused` | `mcp/tests/test_vendor_flow.py::test_tampered_record_is_refused_without_device_calls`<br>`mcp/tests/test_vendor_flow.py::test_a_tampered_record_is_refused_before_any_device_call` | `mcp/tests/test_routeros_flow.py::test_an_edited_chr_record_is_refused_before_any_device_call`<br>`mcp/tests/test_routeros_flow.py::test_a_chr_record_whose_batch_was_edited_after_the_plan_does_not_verify` | `mcp/tests/ad/write/test_write_approve.py::test_editing_the_risk_of_the_plan_file_changes_the_digest`<br>`mcp/tests/ad/write/test_write_request.py::test_the_canonical_bytes_hold_the_lines_in_order`<br>`mcp/tests/ad/write/test_write_request.py::test_the_digest_is_the_sha256_of_the_canonical_bytes`  | `mcp/tests/ad/build/test_build_plan.py::test_every_field_changes_the_digest`  |
| 3 | Approval bound to digest | `device/openwrt/newton-router/tests/test_approval.py::test_apply_prod_wrong_ingredient_token_bad_approval`<br>`device/openwrt/newton-router/tests/test_approval.py::test_apply_ex3_edited_exp_repro_bad_approval`<br>`device/openwrt/newton-router/tests/test_approval.py::test_apply_now_after_exp_refused_approval_window` | `mcp/tests/test_noinstall_apply.py::test_an_approval_for_another_plan_hash_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_an_expired_approval_is_refused` | `mcp/tests/test_vendor_flow.py::test_a_vyos_apply_with_an_approval_for_another_plan_hash_is_refused`<br>`mcp/tests/test_junos_flow.py::test_a_junos_apply_with_an_approval_for_another_plan_hash_is_refused`<br>`mcp/tests/test_vendor_flow.py::test_a_vyos_apply_with_an_expired_approval_is_refused`<br>`mcp/tests/test_junos_flow.py::test_a_junos_apply_with_an_expired_approval_is_refused` | `mcp/tests/test_routeros_flow.py::test_a_chr_apply_with_an_approval_for_another_plan_hash_is_refused`<br>`mcp/tests/test_routeros_flow.py::test_a_chr_apply_with_an_expired_approval_is_refused` | `mcp/tests/ad/test_samba_write_helper.py::test_a_bad_token_is_refused`<br>`mcp/tests/ad/test_samba_write_helper.py::test_an_expired_approval_is_refused` | `mcp/tests/ad/build/test_build_approve.py::test_the_token_of_a_server_verifies_only_with_its_own_key`<br>`mcp/tests/ad/build/test_build_helper.py::test_the_helper_refuses_a_plan_byte_that_changed`<br>`mcp/tests/ad/build/test_build_helper.py::test_the_helper_refuses_a_token_whose_window_has_passed`  |
| 4 | Diff unchanged plan to apply | `device/openwrt/newton-router/tests/test_apply.py::test_apply_plan_changed_diff`<br>`mcp/tests/test_server.py::test_plan_edited_after_approval_is_refused` | `mcp/tests/test_noinstall_apply.py::test_a_record_whose_diff_is_not_the_diff_of_its_batch_is_refused`<br>`mcp/tests/test_noinstall_apply.py::test_the_router_changed_since_the_plan_is_refused_before_the_apply` | `mcp/tests/test_vendor_flow.py::test_stale_base_hash_is_an_error_before_apply` | `mcp/tests/test_routeros_flow.py::test_a_chr_whose_base_changed_since_the_plan_is_refused_before_any_change_line` | `mcp/tests/ad/write/test_write_apply.py::test_a_conflict_at_the_apply_sends_no_confirm` | `mcp/tests/ad/build/test_build_run.py::test_a_plan_changed_after_its_approval_runs_nothing`  |
| 5 | Undo armed before write | `device/openwrt/newton-router/tests/test_apply.py::test_apply_happy_path_t90`<br>`device/openwrt/newton-router/tests/test_flow.py::test_happy_full_flow_through_real_guard_and_helper` | `mcp/tests/test_rpcd_txn.py::test_apply_stages_and_applies_in_one_session`<br>`mcp/tests/test_noinstall_apply.py::test_a_failing_mandatory_check_gives_no_confirm_and_the_router_rolls_it_back` | `mcp/tests/test_junos_flow.py::test_the_apply_of_a_junos_confirms_through_its_own_operations`<br>`mcp/tests/test_vendor_write.py::test_apply_script_carries_commit_confirm_with_no_prompt` | `mcp/tests/test_routeros_write.py::test_the_apply_arms_and_reads_the_receipt_before_the_lines`<br>`mcp/tests/test_routeros_write.py::test_a_failed_arm_sends_no_change_line` | `mcp/tests/ad/test_samba_write_helper.py::test_the_apply_follows_the_order_of_the_steps`<br>`mcp/tests/ad/test_samba_write_helper.py::test_an_apply_whose_timer_cannot_be_armed_writes_nothing` | `mcp/tests/ad/build/test_build_run.py::test_each_irreversible_stage_stops_for_approval_with_its_checkpoint`<br>`mcp/tests/ad/build/test_build_run.py::test_an_unverified_checkpoint_stops_the_run`  |
| 6 | Verify over fresh connections | `tests/protocol/test_owrt_change_fresh_ssh.py::test_every_verify_round_of_an_apply_runs_as_its_own_ssh_process`<br>`tests/protocol/test_owrt_change_fresh_ssh.py::test_every_verify_round_of_an_apply_runs_as_its_own_ssh_process_in_the_password_lane`<br>`tests/protocol/test_owrt_change_fresh_ssh.py::test_the_extra_verify_round_of_a_held_apply_is_a_fresh_ssh` | `mcp/tests/test_noinstall_apply.py::test_a_check_that_cannot_log_in_is_not_verified_and_gives_no_confirm` | `mcp/tests/test_vendor_change.py::test_meta_reusing_the_apply_call_for_verify_is_caught`<br>`mcp/tests/test_vendor_flow.py::test_apply_with_approval_confirms_in_the_safe_order`<br>`mcp/tests/test_junos_write.py::test_the_end_to_end_happy_path_confirms` | `mcp/tests/test_vendor_change.py::test_the_chr_happy_path_is_confirmed` | `mcp/tests/ad/write/test_write_sessions.py::test_the_read_back_of_every_dc_runs_over_a_session_of_its_own` | `mcp/tests/ad/build/test_build_fresh_connections.py::test_the_read_back_of_a_stage_reads_the_server_over_a_new_connection` |
| 7 | Confirm after verified record | `device/openwrt/newton-router/tests/test_verify_record.py::test_confirm_without_a_verify_refuses`<br>`device/openwrt/newton-router/tests/test_verify_record.py::test_confirm_after_three_passes_succeeds` | `mcp/tests/test_rpcd_txn.py::test_confirm_refuses_when_the_checks_failed`<br>`mcp/tests/test_rpcd_txn.py::test_confirm_refuses_when_the_change_is_not_ours` | `mcp/tests/test_vendor_change.py::test_probe_failure_aborts_before_any_confirm`<br>`mcp/tests/test_junos_write.py::test_a_failing_probe_takes_the_recover_path`<br>`mcp/tests/test_junos_write.py::test_a_partial_commit_is_rolled_back` | `mcp/tests/test_vendor_change.py::test_a_failed_probe_rolls_the_chr_change_back`<br>`mcp/tests/test_vendor_change.py::test_a_withheld_confirm_leaves_the_chr_revert_armed` | `mcp/tests/ad/write/test_write_apply.py::test_the_confirm_goes_out_only_when_every_dc_matches`<br>`mcp/tests/ad/write/test_write_apply.py::test_a_lagging_dc_gives_not_tested_and_an_abort`<br>`mcp/tests/ad/write/test_write_apply.py::test_a_dc_whose_planning_image_matches_but_whose_outcome_does_not_is_never_matched` | `mcp/tests/ad/build/test_build_approve.py::test_the_stage_approval_refuses_an_unverified_checkpoint`  |
| 8 | Fixed set of outcomes | `mcp/tests/test_server.py::test_classify_apply_strict_terminal_contract`<br>`mcp/tests/test_server.py::test_apply_timeout_burns_approval`<br>`mcp/tests/test_server.py::test_replayed_approval_is_refused` | `mcp/tests/test_noinstall_apply.py::test_a_lost_answer_that_applied_nothing_is_never_confirmed`<br>`mcp/tests/test_noinstall_apply.py::test_a_lost_answer_the_router_cannot_reach_gives_unknown_and_a_run_record`<br>`mcp/tests/test_noinstall_apply.py::test_a_used_approval_is_not_replayed_by_a_second_apply` | `mcp/tests/test_vendor_change.py::test_meta_rollback_without_the_hash_check_is_caught`<br>`mcp/tests/test_vendor_flow.py::test_verify_exception_leaves_pending_and_consumes_approval`<br>`mcp/tests/test_junos_write.py::test_a_timer_that_fires_before_the_confirm_is_unknown` | `mcp/tests/test_vendor_change.py::test_a_read_back_that_never_comes_is_unknown`<br>`mcp/tests/test_routeros_write.py::test_a_device_that_never_answers_is_not_loaded_twice` | `mcp/tests/ad/write/test_write_outcome_claims.py::test_an_unmarked_answer_is_never_reported_as_nothing_changed`<br>`mcp/tests/ad/write/test_write_apply.py::test_a_lagging_dc_gives_not_tested_and_an_abort`<br>`mcp/tests/ad/write/test_write_outcome_claims.py::test_a_second_apply_of_a_plan_that_reached_the_dc_is_refused_before_it_is_sent` | `mcp/tests/ad/build/test_build_run.py::test_a_refused_journal_read_keeps_only_the_fixed_words`<br>`mcp/tests/ad/build/test_build_run.py::test_a_dropped_session_that_does_not_end_in_rebooting_is_connection_lost`  |
| 9 | Running state shown after restore | `device/openwrt/newton-router/tests/test_running_after_restore.py::test_a_restored_session_whose_health_check_passes_says_match`<br>`device/openwrt/newton-router/tests/test_running_after_restore.py::test_a_failed_health_check_says_differs`<br>`mcp/tests/test_running_after_restore.py::test_a_running_network_that_does_not_match_names_the_next_step` | `mcp/tests/test_noinstall_running_after_rollback.py::test_a_change_the_rpcd_timer_rolled_back_says_the_running_state_is_unproven`<br>`mcp/tests/test_noinstall_running_after_rollback.py::test_an_owner_script_the_router_rolled_back_says_the_running_state_is_unproven`<br>`mcp/tests/test_noinstall_running_after_rollback.py::test_a_confirmed_change_says_nothing_about_the_running_state` | n/a: the commit-confirm revert rewrites the running configuration itself; there is no file copy that can drift from it | n/a: the router reboots into its backup, so it runs what it booted from | n/a: the DC undo writes the before-image into the directory itself; the directory has no running copy apart from what is stored | n/a: the build puts nothing back by itself; a stage stops where it is and the checkpoint before it is the way back  |
| 10 | Controller lost mid-change | `tests/protocol/test_controller_loss.py::test_a_controller_lost_after_the_apply_before_the_first_verify`<br>`tests/protocol/test_controller_loss.py::test_c_controller_lost_during_the_confirm`<br>`tests/protocol/test_controller_loss.py::test_e_controller_lost_after_the_confirm_answered_stays_confirmed` | `mcp/tests/test_controller_loss_noinstall.py::test_a_controller_lost_after_the_apply_before_the_first_verify`<br>`mcp/tests/test_controller_loss_noinstall.py::test_a_controller_lost_after_the_verify_before_the_confirm`<br>`mcp/tests/test_controller_loss_noinstall.py::test_a_controller_lost_after_the_confirm_stays_confirmed` | `mcp/tests/test_controller_loss_vendor.py::test_a_vyos_controller_lost_after_the_verify_before_the_confirm`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_vyos_controller_lost_after_the_apply_before_the_first_verify`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_vyos_controller_lost_after_the_confirm_stays_confirmed`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_junos_controller_lost_after_the_confirm_stays_confirmed`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_junos_controller_lost_after_the_apply_before_the_first_verify`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_junos_controller_lost_after_the_verify_before_the_confirm` | `mcp/tests/test_controller_loss_vendor.py::test_a_chr_controller_lost_after_the_apply_before_the_first_verify`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_chr_controller_lost_after_the_verify_before_the_confirm`<br>`mcp/tests/test_controller_loss_vendor.py::test_a_chr_controller_lost_after_the_confirm_stays_confirmed` | `mcp/tests/ad/test_samba_write_helper.py::test_the_sweep_runs_an_overdue_undo_and_never_confirms` | `mcp/tests/ad/build/test_build_run.py::test_a_runner_killed_during_a_rebooting_stage_resumes_from_the_journal`<br>`mcp/tests/ad/build/test_build_run.py::test_a_runner_killed_after_the_helper_recorded_a_checkpoint_reuses_it`  |
<!-- contract-table:end -->

## Live runs

Rule 10 on a real router, 2026-11-26: the lab router Beryl (GL.iNet GL-MT3000, OpenWrt 25.12.6, router program 1.3.4),
driven by the lab runner (`lab/newton-lab-test.py`, field `controller_loss`), with the scenarios
`lab/scenarios-pulsar/p-cl-01-lost-before-first-verify.toml`, `p-cl-02-lost-in-second-verify.toml` and
`p-cl-03-lost-in-confirm.toml`. In each run the runner killed the whole host process group when the matching ssh call
appeared, waited past the guard deadline, and asked a new host process for the status.

| Scenario | Kill point | Router status line after the deadline | Result |
|---|---|---|---|
| p-cl-01 | first `verify` | `rolled-back sid=... guard=restored:deadline rpcd=- config=base boot=same running=match` | pass |
| p-cl-02 | second `verify` | `rolled-back sid=... guard=restored:deadline rpcd=- config=base boot=same running=match` | pass |
| p-cl-03 | `confirm` | `rolled-back sid=... guard=restored:deadline rpcd=- config=base boot=same running=match` | pass |

In p-cl-03 the kill reached the confirm before the router confirmed, so the guard restored; a confirmed end state is
proved on the fake router by `tests/protocol/test_controller_loss.py::test_e_controller_lost_after_the_confirm_answered_stays_confirmed`.
No run showed `running=differs`, so the fix command the host prints for that case
(`reload_config; /etc/init.d/firewall restart; wifi reload`) was not exercised on the router.

## Gaps

None (2026-11-26): every rule has tests in every mode where it applies, and an `n/a` with its reason where it
cannot apply. A rule that loses its proof in some mode goes back here as `G<n>`, in the form
`- G<n> (rule <r>, <mode>): <what no test proves>. Closed by: <who>.`
