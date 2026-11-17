# ==============================================================================
# FILE: eval_harness.py
# DESCRIPTION: Offline Deterministic Evaluation & Regression Harness for
#              IntuneRAGApp. Validates IngestionAgent, RetrievalEngine,
#              18-step lifecycle state resolution, and CPU prompt token budgets
#              without loading the GGUF model into RAM.
# ==============================================================================

import os
import sys
import json
import time
import tempfile
import argparse
from pathlib import Path
from typing import Dict, List, Any

from core.orchestrator import IngestionAgent, RetrievalEngine

GOLDEN_FILE_PATH = Path("tests") / "golden_cases.json"
REVIEW_QUEUE_DIR = Path("review_queue")

# Performance & Context Budgets for CPU-Only Laptops
MAX_INGEST_AND_INDEX_MS = 250.0  # Max allowed time for test batch ingestion + O(1) indexing
MAX_PROMPT_TOKENS = 260          # Max allowed tokens sent to llama.cpp prefill to keep TTFT < 1s


DEFAULT_GOLDEN_CASES: List[Dict[str, Any]] = [
    {
        "case_id": "1_zscaler_esp_toast_1008_installed",
        "description": "Zscaler Client Connector: Benign LogonUser 1008 (PopToastNotification) during DeviceSetup ESP must NOT override final ResultantAppState: 1 (Installed).",
        "app_id": "eaf40cc2-32da-4739-8bb2-1f67a2671135",
        "expect_absent": False,
        "log_lines": [
            '<![LOG[[Win32App][EspManager] In EspPhase: DeviceSetup. App eaf40cc2-32da-4739-8bb2-1f67a2671135 has been registered. App name: Zscaler Client Connector]LOG]!><time="08:19:50.5698471" date="7-17-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][ExecutionActionHandler] Handler completed with action status: Success. App: eaf40cc2-32da-4739-8bb2-1f67a2671135]LOG]!><time="08:21:03.7710767" date="7-17-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App] LogonUser failed with error code : 1008]LOG]!><time="08:21:03.8533935" date="7-17-2026" component="AppWorkload" context="" type="3" thread="15" file="">',
            '<![LOG[[Win32App] Skip PopToastNotification since failed to query userToken]LOG]!><time="08:21:03.8533935" date="7-17-2026" component="AppWorkload" context="" type="3" thread="15" file="">',
            '<![LOG[[Win32App][DetectionActionHandler] Detection for policy with id: eaf40cc2-32da-4739-8bb2-1f67a2671135 resulted in action status: Success and detection state: Detected.]LOG]!><time="08:21:03.8533935" date="7-17-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][ReportingManager] Sending status to company portal based on report: {"ApplicationId":"eaf40cc2-32da-4739-8bb2-1f67a2671135","ResultantAppState":1,"CanGenerateComplianceState":true,"DetectionState":1,"EnforcementState":1000,"EnforcementErrorCode":0,"InstallContext":2}]LOG]!><time="08:21:03.8634127" date="7-17-2026" component="AppWorkload" context="" type="1" thread="15" file="">'
        ],
        "expected": {
            "is_already_installed": True,
            "has_real_failure": False,
            "had_benign_toast_1008": True,
            "error_code": "0 (Installed)",
            "stopping_step_contains": "Step 18",
            "not_in_key_error_line": ["PopToastNotification", "LogonUser failed"]
        }
    },
    {
        "case_id": "2_firefox_store_reeval_skip_installed",
        "description": "Mozilla Firefox (MS Store App): Initial ResultantAppState: null + ReevaluationScheduleManager skip followed by ResultantAppState: 1 must NOT hallucinate a session context failure.",
        "app_id": "ec927865-53f7-439e-8d0b-3b7aedf21932",
        "expect_absent": False,
        "log_lines": [
            '<![LOG[[Win32App][ReportingManager] App with id: ec927865-53f7-439e-8d0b-3b7aedf21932 and prior AppAuthority: V2 could not be loaded from store. Reporting state initialized with initial values. ReportingState: {"ApplicationId":"ec927865-53f7-439e-8d0b-3b7aedf21932","Name":"[Stef] - Mozilla Firefox (MS Store App) - x64 & ARM","ResultantAppState":null,"InstallContext":2}]LOG]!><time="03:40:00.1000000" date="11-3-2026" component="AppWorkload" context="" type="1" thread="10" file="">',
            '<![LOG[[Win32App][ReevaluationScheduleManager] Skip saving the last evaluation check-in time as the previous evaluation check-in time is not expired. App: ec927865-53f7-439e-8d0b-3b7aedf21932]LOG]!><time="03:41:00.3709119" date="11-3-2026" component="AppWorkload" context="" type="1" thread="10" file="">',
            '<![LOG[[Win32App][ReportingManager] Sending status to company portal based on report: {"ApplicationId":"ec927865-53f7-439e-8d0b-3b7aedf21932","ResultantAppState":1,"CanGenerateComplianceState":true,"EnforcementState":1000,"InstallContext":2}]LOG]!><time="03:41:05.0000000" date="11-3-2026" component="AppWorkload" context="" type="1" thread="10" file="">'
        ],
        "expected": {
            "is_already_installed": True,
            "has_real_failure": False,
            "has_explicit_token_error": False,
            "error_code": "0 (Installed)",
            "stopping_step_contains": "Step 18",
            "not_in_key_error_line": ["ReevaluationScheduleManager"]
        }
    },
    {
        "case_id": "3_company_portal_store_system_token_failure",
        "description": "Company Portal (New Store): Genuine SYSTEM Context token failure (1008) must be caught, V3Processor Base64 noise dropped, and broken Sysnative/Not-logged text omitted.",
        "app_id": "6f3c5a37-6be9-4a98-ac0d-a6f93ec663e7",
        "expect_absent": False,
        "log_lines": [
            '<![LOG[[Win32App] Get policies = [{"Id":"6f3c5a37-6be9-4a98-ac0d-a6f93ec663e7","Name":"Company Portal (New Store)","InstallContext":2,"PackageIdentifier":"9WZDNCRFJ3PZ"}]]LOG]!><time="05:37:00.0000000" date="7-21-2026" component="AppWorkload" context="" type="1" thread="12" file="">',
            '<![LOG[[Win32App][WinGetAppExecutionExecutor] WTSQueryUserToken failed with error code: 1008 for app 6f3c5a37-6be9-4a98-ac0d-a6f93ec663e7 in session 0. Action status: Failed]LOG]!><time="05:38:01.0000000" date="7-21-2026" component="AppWorkload" context="" type="3" thread="12" file="">',
            '<![LOG[[Win32App][V3Processor] Done processing subgraph. eyJBc3NlbWJseUZpbGVWZXJzaW9uIjoiMS4xMDMuMTAxLjAiLCJBcHAiOiI2ZjNjNWEzNy02YmU5LTRhOTgtYWMwZC1hNmY5M2VjNjYzZTcifQ==]LOG]!><time="05:38:07.0224678" date="7-21-2026" component="AppWorkload" context="" type="1" thread="12" file="">'
        ],
        "expected": {
            "is_already_installed": False,
            "has_real_failure": True,
            "is_store_app": True,
            "has_explicit_token_error": True,
            "error_code": "1008",
            "not_in_key_error_line": ["Done processing subgraph"],
            "not_in_fix": ["Not logged in captured chunk"]
        }
    },
    {
        "case_id": "4_qualys_simulated_esp_not_installed",
        "description": "Qualys Cloud Agent: [Simulated] ESP handlers returning action status: Success with detection state: NotDetected must NOT be marked as 0 (Installed) or as a fatal failure.",
        "app_id": "459c05d4-97a5-41ba-9425-b1178c7448f4",
        "expect_absent": False,
        "log_lines": [
            '<![LOG[[Win32App] Get policies = [{"Id":"459c05d4-97a5-41ba-9425-b1178c7448f4","Name":"Qualys Cloud Agent","InstallCommandLine":"Install.cmd","InstallContext":2}]]LOG]!><time="05:36:03.6476881" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][SimulatedDetectionActionHandler] Detection for policy with id: 459c05d4-97a5-41ba-9425-b1178c7448f4 resulted in action status: Success and detection state: NotDetected.]LOG]!><time="05:36:10.9309880" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][SimulatedExecutionActionHandler] Handler completed with action status: Success. App: 459c05d4-97a5-41ba-9425-b1178c7448f4]LOG]!><time="05:36:10.9785665" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][ReportingManager] App with id: 459c05d4-97a5-41ba-9425-b1178c7448f4 and prior AppAuthority: V2 could not be loaded from store. ReportingState: {"ApplicationId":"459c05d4-97a5-41ba-9425-b1178c7448f4","ResultantAppState":null}]LOG]!><time="05:36:26.6743626" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">'
        ],
        "expected": {
            "is_already_installed": False,
            "has_real_failure": False,
            "error_code": "None (0)",
            "not_in_fix": ["provisioningReport"]
        }
    },
    {
        "case_id": "5_grs_and_null_guid_noise_filtering",
        "description": "GRSManager Cleared/Reading lines and null GUID (00000000-...) must be completely dropped during ingestion and never create an app dossier.",
        "app_id": "f755024c-3fdd-4a92-8f0a-bc8750fe023d",
        "expect_absent": True,
        "log_lines": [
            '<![LOG[[Win32App][GRSManager] Cleared GRS value for app: f755024c-3fdd-4a92-8f0a-bc8750fe023d and user: 00000000-0000-0000-0000-000000000000.]LOG]!><time="05:36:19.9554477" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">',
            '<![LOG[[Win32App][GRSManager] Reading GRS values from storage path: 00000000-0000-0000-0000-000000000000\\GRS\\hash\\f755024c-3fdd-4a92-8f0a-bc8750fe023d.]LOG]!><time="05:36:20.0409770" date="7-21-2026" component="AppWorkload" context="" type="1" thread="15" file="">'
        ],
        "expected": {}
    }
]


def ensure_golden_dataset(path: Path) -> List[Dict[str, Any]]:
    """Creates tests/golden_cases.json if missing, then loads all golden test cases."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with open(path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_GOLDEN_CASES, f, indent=2)
        print(f"[INIT] Created baseline golden dataset at: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def promote_flagged_cases(golden_path: Path, review_dir: Path) -> int:
    """Promotes flagged JSON cases from review_queue/ into tests/golden_cases.json."""
    if not review_dir.exists():
        print(f"[PROMOTE] No '{review_dir}' folder found yet.")
        return 0

    cases = ensure_golden_dataset(golden_path)
    existing_ids = {c["case_id"] for c in cases}
    added = 0

    for fpath in sorted(review_dir.glob("*.json")):
        with open(fpath, "r", encoding="utf-8") as f:
            flagged = json.load(f)
        cid = flagged.get("case_id", fpath.stem)
        if cid not in existing_ids and "log_lines" in flagged and "expected" in flagged:
            cases.append(flagged)
            existing_ids.add(cid)
            added += 1

    if added > 0:
        with open(golden_path, "w", encoding="utf-8") as f:
            json.dump(cases, f, indent=2)
        print(f"[PROMOTE] Added {added} new case(s) to {golden_path}.")
    else:
        print("[PROMOTE] No new valid cases found to promote.")
    return added


def estimate_llm_prompt_tokens(verified_root_cause: str) -> int:
    """Estimates the token count of the prompt sent to llama.cpp prefill (~4 chars/token)."""
    system_prompt = (
        "You are a Senior Microsoft Intune Escalation Engineer. "
        "Summarize the Verified Status/Root Cause below in 2 clear, direct sentences starting with '• Analysis Summary:'. "
        "Never invent errors if the Verified Status states the app is Installed or has No Failure."
    )
    user_prompt = (
        f"Verified Status/Root Cause: {verified_root_cause}\n"
        f"Write the '• Analysis Summary:' now:"
    )
    return (len(system_prompt) + len(user_prompt)) // 4


def run_evaluation_suite(cases: List[Dict[str, Any]]) -> bool:
    print("=" * 88)
    print("INTUNE RAG AGENT - DETERMINISTIC EVALUATION & LATENCY HARNESS (CPU-ONLY MODE)")
    print("=" * 88)

    # Combine all golden log lines into a temporary AppWorkload.log file
    combined_lines = []
    for c in cases:
        combined_lines.extend(c.get("log_lines", []))

    with tempfile.NamedTemporaryFile(
        mode="w", suffix="_AppWorkload.log", delete=False, encoding="utf-8"
    ) as tmp_log:
        tmp_log.write("\n".join(combined_lines))
        tmp_path = tmp_log.name

    try:
        ingestion = IngestionAgent()
        retrieval = RetrievalEngine()

        t0 = time.perf_counter()
        nodes = ingestion.process_files([tmp_path])
        ingest_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        retrieval.build_index(nodes)
        index_ms = (time.perf_counter() - t1) * 1000.0
        total_prep_ms = ingest_ms + index_ms
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    passed_count = 0
    failures: List[str] = []

    for c in cases:
        case_id = c["case_id"]
        app_id = c["app_id"].lower()
        expect_absent = c.get("expect_absent", False)
        exp = c.get("expected", {})
        case_errors: List[str] = []

        t_lookup_start = time.perf_counter()
        hit = retrieval.search_with_metadata(query=app_id, exact_match_keyword=app_id)
        lookup_ms = (time.perf_counter() - t_lookup_start) * 1000.0

        if expect_absent:
            if app_id in retrieval.app_dossiers:
                case_errors.append(f"Expected App ID '{app_id}' to be filtered out as noise, but a dossier was built.")
            if "00000000-0000-0000-0000-000000000000" in retrieval.app_dossiers:
                case_errors.append("Null GUID '00000000-...' leaked into app_dossiers.")
        else:
            if app_id not in retrieval.app_dossiers or hit.get("evidence") == "No matching device logs found.":
                case_errors.append(f"App ID '{app_id}' was not indexed into app_dossiers.")
            else:
                dossier = retrieval.app_dossiers[app_id]

                # 1. Exact Field Assertions
                for field in [
                    "is_already_installed",
                    "has_real_failure",
                    "is_store_app",
                    "has_explicit_token_error",
                    "had_benign_toast_1008",
                    "error_code"
                ]:
                    if field in exp:
                        actual_val = dossier.get(field)
                        if actual_val != exp[field]:
                            case_errors.append(
                                f"Field '{field}' mismatch: expected {exp[field]!r}, got {actual_val!r}"
                            )

                # 2. Substring Assertions on Stopping Step
                if "stopping_step_contains" in exp:
                    target_sub = exp["stopping_step_contains"].lower()
                    actual_step = dossier.get("stopping_step", "")
                    if target_sub not in actual_step.lower():
                        case_errors.append(
                            f"Stopping step mismatch: expected '{ exp['stopping_step_contains'] }' in '{actual_step}'"
                        )

                # 3. Negative Assertions on Key Error Line (Ensure noise never becomes the key log record)
                for forbidden_str in exp.get("not_in_key_error_line", []):
                    key_line = dossier.get("key_error_line", "")
                    if forbidden_str.lower() in key_line.lower():
                        case_errors.append(
                            f"Forbidden noise '{forbidden_str}' appeared in key_error_line: '{key_line[:120]}'"
                        )

                # 4. Negative Assertions on Actionable Fix (Ensure broken templates never appear)
                for forbidden_fix in exp.get("not_in_fix", []):
                    fix_text = dossier.get("verified_actionable_fix", "")
                    if forbidden_fix.lower() in fix_text.lower():
                        case_errors.append(
                            f"Forbidden template text '{forbidden_fix}' appeared in verified_actionable_fix."
                        )

                # 5. Prompt Token Budget Check (Protects CPU TTFT)
                est_tokens = estimate_llm_prompt_tokens(dossier.get("verified_root_cause", ""))
                if est_tokens > MAX_PROMPT_TOKENS:
                    case_errors.append(
                        f"LLM prompt token budget exceeded: {est_tokens} tokens > max {MAX_PROMPT_TOKENS} tokens."
                    )

        if not case_errors:
            passed_count += 1
            status_str = "PASS"
            detail_str = (
                "Noise filtered cleanly (0 dossiers built)"
                if expect_absent
                else f"Code: {retrieval.app_dossiers[app_id]['error_code']} | Lookup: {lookup_ms:.3f}ms | Prompt: ~{estimate_llm_prompt_tokens(retrieval.app_dossiers[app_id]['verified_root_cause'])} toks"
            )
            print(f"[{status_str}] {case_id:<44} | {detail_str}")
        else:
            print(f"[FAIL] {case_id:<44} | {len(case_errors)} assertion(s) failed")
            for err in case_errors:
                failures.append(f"  - [{case_id}] {err}")

    # Check overall Python Ingestion + O(1) Indexing latency ceiling
    if total_prep_ms > MAX_INGEST_AND_INDEX_MS:
        failures.append(
            f"  - [LATENCY BUDGET] Ingestion + Indexing took {total_prep_ms:.2f}ms (exceeds {MAX_INGEST_AND_INDEX_MS}ms budget)."
        )

    print("-" * 88)
    print(
        f"Summary: {passed_count}/{len(cases)} Cases Passed  |  "
        f"Ingestion: {ingest_ms:.2f}ms  |  O(1) Dossier Build: {index_ms:.2f}ms  |  "
        f"Indexed Chunks: {len(nodes)}"
    )
    print("=" * 88)

    if failures:
        print("\nFAILURE DETAILS:")
        for f_msg in failures:
            print(f_msg)
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the IntuneRAGApp deterministic evaluation harness.")
    parser.add_argument(
        "--promote",
        action="store_true",
        help="Promote flagged JSON cases from review_queue/ into tests/golden_cases.json before running."
    )
    args = parser.parse_args()

    if args.promote:
        promote_flagged_cases(GOLDEN_FILE_PATH, REVIEW_QUEUE_DIR)

    golden_cases = ensure_golden_dataset(GOLDEN_FILE_PATH)
    success = run_evaluation_suite(golden_cases)
    sys.exit(0 if success else 1)
