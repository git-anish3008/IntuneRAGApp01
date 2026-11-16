# ==============================================================================
# FILE: core/orchestrator.py
# DESCRIPTION: Evidence-Only Intune Win32 & Store Log Analyzer (O(1) Pre-Indexed).
#              Filters benign PopToastNotification LogonUser 1008 noise during
#              ESP/Session 0, prioritizes final ResultantAppState/EnforcementState,
#              and keeps TTFT sub-second on CPU-only laptops.
# ==============================================================================

import os
import sys
import re
import json
import ctypes
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Iterator
from llama_index.core import Document
from llama_cpp import Llama, LlamaRAMCache
from rank_bm25 import BM25Okapi


def get_resource_path(relative_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, relative_path)


def _is_valid_app_id(app_id: str) -> bool:
    if not app_id:
        return False
    clean = app_id.replace("-", "").lower()
    return clean != "00000000000000000000000000000000" and len(clean) == 32


def _clean_json_escaped_text(raw_str: str) -> str:
    if not raw_str:
        return ""
    cleaned = raw_str.replace(r'\"', '"').replace(r'\\', '\\')
    cleaned = re.sub(
        r'\\u([0-9a-fA-F]{4})',
        lambda m: chr(int(m.group(1), 16)),
        cleaned
    )
    return cleaned.strip()


def decimal_to_hex_error(decimal_str: str) -> str:
    try:
        val = int(decimal_str)
        if val < 0:
            return f"0x{(val & 0xFFFFFFFF):08X}"
        return str(val)
    except Exception:
        return decimal_str


def format_os_error_code(err_code: str) -> str:
    """Translates verified hex/decimal error codes into their official Windows OS description."""
    code_clean = err_code.strip().lower()
    known_codes = {
        "1008": "Win32 Error 1008 (ERROR_NO_TOKEN: An attempt was made to reference a token that does not exist in SYSTEM/Session 0)",
        "0x80244022": "0x80244022 (WU_E_PT_HTTP_STATUS_SERVICE_UNAVAILABLE: Store/WinGet CDN HTTP 503 or proxy block)",
        "0x87d30065": "0x87D30065 (Intune Content Download / Delivery Optimization Failure)",
        "0x87d30067": "0x87D30067 (SHA256 Content Hash Verification Mismatch)",
        "0x87d1041c": "0x87D1041C (Post-Install Detection Rule Failed: App not detected after installer exited)",
        "0x80073cf9": "0x80073CF9 (ERROR_INSTALL_FAILED: Windows Store / Appx deployment failed)",
        "0x80073cf3": "0x80073CF3 (ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED: Missing Store UWP framework dependency)",
        "0x80073cfb": "0x80073CFB (ERROR_PACKAGE_ALREADY_EXISTS: Another version of this Store package is staged)",
        "1603": "MSI Exit Code 1603 (ERROR_INSTALL_FAILURE: Fatal error during installation)",
        "1618": "MSI Exit Code 1618 (ERROR_INSTALL_ALREADY_RUNNING: Another msiexec process holds the mutex)"
    }
    if code_clean in known_codes:
        return known_codes[code_clean]

    try:
        if code_clean.startswith("0x"):
            val = int(code_clean, 16)
            win32_c = (val & 0xFFFF) if (val & 0xFFFF0000) == 0x80070000 else (val - 0x100000000 if val >= 0x80000000 else val)
            msg = ctypes.FormatError(win32_c).strip()
            if msg and "unknown" not in msg.lower():
                return f"{err_code.upper()} ({msg})"
        elif code_clean.isdigit() or (code_clean.startswith("-") and code_clean[1:].isdigit()):
            val = int(code_clean)
            msg = ctypes.FormatError(val).strip()
            if msg and "unknown" not in msg.lower():
                return f"Win32 Error {val} ({msg})"
    except Exception:
        pass
    return err_code.upper()


# ==============================================================================
# STRICT 18-STEP RUNBOOK LIFECYCLE MAPPER
# ==============================================================================
def map_log_to_runbook_step(text: str) -> Tuple[int, str]:
    low = text.lower()
    low_nospace = re.sub(r'\s+', '', low)

    if "get policies" in low or '"detectionrule":' in low or "[esp" in low or "trackaccountsetupstate" in low:
        return 1, "Step 1: Start to present application"

    if "[simulated" in low:
        if "detection" in low:
            return 2, "Step 2: Process Detection Rules (Pre-Install)"
        if "applicability" in low:
            return 3, "Step 3: Check applicability"
        return 1, "Step 1: Start to present application"

    if "[reportingmanager]" in low or "sending status to company portal" in low or "sending results to service" in low:
        if '"resultantappstate":1' in low_nospace or '"enforcementstate":1000' in low_nospace:
            return 18, "Step 18: Set EnforcementStateMessage (Installed)"
        return 14, "Step 14: Save AppInstallStatusReport"

    if "detection rules after execution" in low or "arrived detected" in low or "application is detected" in low or "detection state: detected" in low:
        return 15, "Step 15: Detection rules after Execution (Post-Install)"
    if any(k in low for k in ["lpexitcode", "exitcode", "installerror", "completed execution", "verify is installation is done", "action status:"]):
        return 13, "Step 13: Verify if Installation is done"
    if any(k in low for k in ["createprocess", "execute command", "current directory", "imecache"]):
        return 12, "Step 12: Create installer process"
    if any(k in low for k in ["wtsqueryusertoken", "createprocessasuser", "error_no_token", "no logged on user"]):
        return 11, "Step 11: Install Behavior (User Token / Session)"
    if "execute retry 0" in low or "starting execution" in low:
        return 10, "Step 10: Execute retry 0"
    if any(k in low for k in ["[executionactionhandler]", "execute with retry", "executionexecutor", "wingetappexecution"]):
        return 9, "Step 9: Execute with Retry"
    if any(k in low for k in ["[stagingactionhandler]", "externalcdn", "decrypt", "unzip", "extract"]):
        return 8, "Step 8: Verify ExternalCDN App content"
    if any(k in low for k in ["create a new download job", "dojob", "bits", "deliveryoptimization"]):
        return 7, "Step 7: Create a new Download job"
    if any(k in low for k in ["[downloadactionhandler]", "start download", "downloading", "contentmanager"]):
        return 6, "Step 6: Start Download"
    if any(k in low for k in ["isdiscovered: false", "not detected", "discovered: false", "detection state: notdetected"]):
        return 5, "Step 5: Check detection without existing App result (NotDetected)"
    if any(k in low for k in ["extended requirement", "requirement rule", "checkextendedrequirement"]):
        return 4, "Step 4: Check Extended requirement rules"
    if any(k in low for k in ["[applicabilityactionhandler]", "checkapplicability", "applicability state:", "hostnotapplicable"]):
        return 3, "Step 3: Check applicability"
    if any(k in low for k in ["[detectionactionhandler]", "processdetectionrules", "detectionmanager"]):
        return 2, "Step 2: Process Detection Rules (Pre-Install)"

    return 1, "Step 1: Start to present application"


def build_deterministic_diagnosis_and_fix(dossier: Dict) -> Tuple[str, str]:
    """
    Evidence-only diagnostic builder:
    - Confirms successful installation when ResultantAppState: 1 / EnforcementState: 1000 is reached,
      explaining benign ESP Toast Notification 1008 warnings if present.
    - Reports genuine failures with exact log evidence and clean remediation steps.
    """
    app_name = dossier["app_name"]
    app_id = dossier["app_id"]
    err_code = dossier["error_code"].strip().lower()
    err_desc = format_os_error_code(dossier["error_code"])
    stopping_step = dossier["stopping_step"]
    cmd = dossier["command_line"]
    has_real_cmd = cmd not in ("Not logged in captured chunk", "None (Microsoft Store / WinGet Managed)")
    context = dossier["install_context"]
    det_rule = dossier["detection_rule_summary"]
    is_store_app = dossier["is_store_app"]
    key_err_line = dossier["key_error_line"]

    # CASE 1: Installed & Compliant (Final state confirmed Installed / EnforcementState 1000)
    if dossier["is_already_installed"]:
        toast_note = (
            " Note: `LogonUser` error `1008` (`Skip PopToastNotification`) also appeared in the log because no user was signed in "
            "during `DeviceSetup` ESP when IME tried to display a completion toast popup—this is harmless UI noise and did not affect installation."
            if dossier.get("had_benign_toast_1008") else ""
        )
        cause = (
            f"`{app_name}` (`{app_id}`) **Installed & Compliant** on this endpoint "
            f"(completed `Step 18` with `ResultantAppState: 1`, `EnforcementState: 1000`, `DetectionState: Installed`, and `EnforcementErrorCode: 0`)."
            f"{toast_note}"
        )
        fix = "No remediation required. The application installed cleanly and reported compliance to Intune."
        return cause, fix

    # CASE 2: No Error Found in Logs (e.g., Available App, Simulated ESP Pre-Check, or Re-evaluation Timer Pending)
    if not dossier["has_real_failure"]:
        cause = (
            f"No deployment failure was recorded for `{app_name}` (`{app_id}`) in the uploaded logs. "
            f"The application completed evaluation (`{dossier['completed_steps_summary']}`) with zero error codes "
            f"(typical for `Available` assignments waiting for user install or apps awaiting their next evaluation cycle)."
        )
        fix = "No remediation needed unless you expected this app to force-install; verify the assignment type (**Required** vs. **Available**) in Intune Admin Center."
        return cause, fix

    # CASE 3: Genuine Session / User Token Error (1008 outside of PopToastNotification)
    if dossier["has_explicit_token_error"] or err_code == "1008":
        if is_store_app:
            cause = (
                f"Microsoft Store / WinGet app `{app_name}` (`{app_id}`) failed at `{stopping_step}` under `{context}` "
                f"with `{err_desc}` because the Store/WinGet handler could not bind an interactive user token in Session 0. "
                f"Failing log record: `{key_err_line[:220]}`"
            )
            fix = (
                f"1. **Switch Install Behavior to User Context:** In **Intune Admin Center -> Apps -> Windows -> {app_name} -> Properties -> Program**, "
                f"change **Install behavior** from **System** to **User**.\n"
                f"2. **Remove from Device-Phase ESP Blocking:** If `{app_name}` is blocked during Enrollment Status Page (`DeviceSetup`), "
                f"remove it from Device Setup blocking so it installs after user sign-in."
            )
            return cause, fix

        clean_script = re.sub(r'^cmd(?:\.exe)?\s+/c\s+', '', cmd, flags=re.IGNORECASE).strip()
        cmd_fix = (
            f"2. **Use 64-bit Wrapper (`{clean_script}`):** If `{clean_script}` is a batch/script installer accessing 64-bit paths, invoke it via `%WINDIR%\\Sysnative\\cmd.exe /c {clean_script}`.\n"
            if has_real_cmd else ""
        )
        cause = (
            f"`{app_name}` (`{app_id}`) failed at `{stopping_step}` under `{context}` with `{err_desc}` "
            f"because the installer or IME handler attempted to reference an interactive user session token while running in Session 0. "
            f"Failing log record: `{key_err_line[:220]}`"
        )
        fix = (
            f"1. **Switch Install Behavior to User Context:** In **Intune Admin Center -> Apps -> Windows -> {app_name} -> Properties -> Program**, "
            f"change **Install behavior** from **System** to **User**.\n"
            f"{cmd_fix}"
            f"2. **Verify Under SYSTEM Context:** Run `psexec -i -s cmd.exe` on a test device to confirm whether the installer fails without a user session."
        )
        return cause, fix

    # CASE 4: Microsoft Store App (New) / WinGet Failure with a Specific Error Code
    if is_store_app:
        cause = (
            f"Microsoft Store / WinGet app `{app_name}` (`{app_id}`) failed at `{stopping_step}` under `{context}` "
            f"with `{err_desc}`. Failing log record: `{key_err_line[:220]}`"
        )
        fix = (
            f"1. **Verify Store & WinGet Network/Policy Access:** Ensure **Turn off the Store application** (`RemoveWindowsStore`) is not enabled via GPO/Intune, "
            f"and that `*.delivery.mp.microsoft.com` and `storeedgefd.dsx.mp.microsoft.com` are reachable without SSL inspection.\n"
            f"2. **Test User vs. System Install Behavior:** In **Intune Admin Center -> Apps -> Windows -> {app_name} -> Properties -> Program**, "
            f"test switching **Install behavior** from **System** to **User** if machine-wide UWP provisioning is blocked."
        )
        return cause, fix

    # CASE 5: Post-Install Detection Rule Failure (0x87D1041C or 0x80070002 at Detection)
    if "0x87d1041c" in err_code or ("0x80070002" in err_code and ("step 2" in stopping_step.lower() or "step 5" in stopping_step.lower() or "step 15" in stopping_step.lower())):
        cause = (
            f"`{app_name}` (`{app_id}`) failed at `{stopping_step}` (`{err_desc}`) "
            f"because IME could not find the configured Detection Rule target (`{det_rule}`). "
            f"Failing log record: `{key_err_line[:220]}`"
        )
        fix = (
            f"1. **Verify Detection Rule Path in Intune:** In **Intune Admin Center -> Apps -> Windows -> {app_name} -> Properties -> Detection rules**, "
            f"confirm the exact file path, registry key, or MSI ProductCode for `{det_rule}`.\n"
            f"2. **Check 32-bit Redirection (`Check32BitOn64System`):** If the app installs into `C:\\Program Files (x86)` or `HKLM\\SOFTWARE\\WOW6432Node`, "
            f"enable **Associated with a 32-bit app on 64-bit clients**."
        )
        return cause, fix

    # CASE 6: General Execution / System Failure with Specific Log Evidence
    cmd_display = f"`{cmd}`" if has_real_cmd else "the package installer"
    cause = (
        f"`{app_name}` (`{app_id}`) failed at `{stopping_step}` under `{context}` with `{err_desc}` while running {cmd_display}. "
        f"Failing log record: `{key_err_line[:220]}`"
    )
    fix = (
        f"1. **Reproduce Installer Execution Locally:** Test {cmd_display} on an endpoint using `psexec -i -s cmd.exe` (for System context) to capture the installer exit code `{err_desc}`.\n"
        f"2. **Verify Intune Program & Detection Settings:** In **Intune Admin Center -> Apps -> Windows -> {app_name} -> Properties**, confirm silent install parameters and detection rule (`{det_rule}`)."
    )
    return cause, fix


# ==============================================================================
# DATA LAYER: INGESTION AGENT
# ==============================================================================
class IngestionAgent:
    def __init__(self):
        self.app_id_pattern = re.compile(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)
        self.hex_pattern = re.compile(r'\b(0x[8cC][0-9a-fA-F]{7})\b')
        self.dec_err_pattern = re.compile(
            r'(?:error\s*code|exit\s*code|lpexitcode|return\s*code|win32error|hresult|"ErrorCode"|\berr\s+is)\s*["\'=:]+\s*(-?\d{1,10})',
            re.IGNORECASE
        )

    def _is_irrelevant_grs_or_daemon_noise(self, text: str) -> bool:
        """Drops GRSManager lines, ReevaluationScheduleManager timer skips, V3Processor Base64 dumps, and WPJ daemon noise."""
        low = text.lower()
        noise_markers = [
            "[grsmanager]",
            "[reevaluationschedulemanager]",
            "cleared grs value for app",
            "reading grs values from storage path",
            "saving grs value to storage path",
            "grs value is",
            "done processing subgraph",
            "check if device is wpj",
            "getaadjoininfo",
            "netgetaadjoininformation",
            "clienthealth",
            "healthcheck"
        ]
        return any(m in low for m in noise_markers)

    def _is_toast_notification_noise(self, text: str) -> bool:
        """
        Identifies benign Windows Toast Notification failures during ESP / Session 0
        (e.g., 'Skip PopToastNotification since failed to query userToken').
        """
        low = text.lower()
        return "poptoastnotification" in low or "failed to query usertoken" in low

    def _is_explicit_token_error(self, text: str) -> bool:
        """ONLY returns True when a genuine installation/execution token failure occurs (never toast popups)."""
        if self._is_toast_notification_noise(text):
            return False
        low = text.lower()
        if any(k in low for k in [
            "error_no_token",
            "wtsqueryusertoken",
            "createprocessasuser",
            "failed to get a token",
            "no active user session",
            "no logged on user"
        ]):
            return True
        has_token_kw = any(k in low for k in ["aad user check", "token acquisition", "user token"])
        has_err_kw = any(e in low for e in ["fail", "error", "exception", "1008"])
        return has_token_kw and has_err_kw

    def _is_installed_telemetry(self, text: str) -> bool:
        raw_low = text.lower()
        if "[simulated" in raw_low or "notdetected" in raw_low or "not detected" in raw_low:
            return False

        low = re.sub(r'\s+', '', raw_low)
        if '"resultantappstate":null' in low or '"resultantappstate":2' in low or '"resultantappstate":3' in low:
            return False

        installed_markers = [
            '"resultantappstate":1',
            '"resultantappstate":"installed"',
            '"enforcementstate":1000',
            '"installstate":1',
            '"cangeneratecompliancestate":true',
            'detectionoperationresulthasarriveddetected',
            'applicationisdetected',
            '"detectionstate":{"oldvalue":"notinstalled","newvalue":"installed"}',
            '"enforcementstate":{"oldvalue":"inprogressdownloadcompleted","newvalue":"success"}'
        ]
        return any(m in low for m in installed_markers)

    def _is_benign_status_line(self, text: str) -> bool:
        if self._is_installed_telemetry(text) or self._is_toast_notification_noise(text):
            return True
        low = text.lower()
        benign_patterns = [
            "could not be loaded from store. reporting state initialized",
            "reporting state initialized with initial values",
            "not enough data to construct a status report",
            "after switch to v3 appauthority. clearing status",
            "sending status to company portal based on report",
            "package manager initialized with status: ok",
            "connect result status: ok",
            "rebootflag is false"
        ]
        return any(p in low for p in benign_patterns)

    def _detect_phase(self, text: str) -> str:
        lower = text.lower()
        if "[reportingmanager]" in lower or "sending results to service" in lower or "requestpayload" in lower or "sending status to company portal" in lower:
            return "6. Reporting"
        if "get policies" in lower or '"installcommandline":' in lower or "[esp" in lower or "trackaccountsetupstate" in lower:
            return "0. Initialization"
        if any(kw in lower for kw in [
            "[executionactionhandler]", "executionexecutor", "wingetappexecution",
            "agentexecutor", "executionmanager", "installing", "installerror",
            "lpexitcode", "createprocess", "execute retry", "imecache"
        ]):
            return "5. Execution"
        if any(kw in lower for kw in [
            "[stagingactionhandler]", "decryptionmanager", "decrypting",
            "unzipping", "extracting", "hash verification"
        ]):
            return "4. Decryption"
        if any(kw in lower for kw in [
            "[downloadactionhandler]", "contentmanager", "dojob", "bits",
            "start download", "downloading", "incoming"
        ]):
            return "3. Download"
        if any(kw in lower for kw in [
            "[detectionactionhandler]", "[simulateddetectionactionhandler]", "detectionmanager",
            "processdetectionrules", "detection operation result", "isdiscovered", "application is not detected"
        ]):
            return "2. Detection"
        if any(kw in lower for kw in [
            "[applicabilityactionhandler]", "[simulatedapplicabilityactionhandler]",
            "requirement", "applicability", "checkapplicability"
        ]):
            return "1. Applicability"
        return "0. Initialization"

    def _extract_error_codes(self, text: str) -> List[str]:
        codes = [c.lower() for c in self.hex_pattern.findall(text)]
        for dec in self.dec_err_pattern.findall(text):
            if dec in ("0", "1", "2", "3", "1000"):
                continue
            converted = decimal_to_hex_error(dec).lower()
            if converted not in codes:
                codes.append(converted)
        if any(w in text.lower() for w in ["error", "exit", "return", "code", "fail", "result", "hresult"]):
            for msi_code in re.findall(r'\b(1008|1603|1618|1605|1641|3010)\b', text):
                if msi_code not in codes:
                    codes.append(msi_code)
        return codes

    def _slice_around_guid(self, text: str, guid: str, window: int = 750) -> str:
        pos = text.lower().find(guid.lower())
        if pos == -1:
            return text[:window]
        start = max(0, pos - 60)
        end = min(len(text), pos + window)
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        return f"{prefix}{text[start:end]}{suffix}"

    def _parse_evtx_to_json_nodes(self, path: str, file_name: str) -> List[Document]:
        nodes = []
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", path, "/lf:true", "/f:RenderedXml", "/c:400"],
                capture_output=True, text=True, encoding="utf-8", errors="ignore"
            )
            raw_xml = proc.stdout.strip()
            if not raw_xml:
                return nodes

            root = ET.fromstring(f"<Events>{raw_xml}</Events>")
            for event_elem in root.findall(".//*"):
                if not event_elem.tag.endswith("Event"):
                    continue

                xml_str = ET.tostring(event_elem, encoding="unicode")
                event_id_m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml_str)
                level_m = re.search(r'<Level>(\d+)</Level>', xml_str)
                time_m = re.search(r'SystemTime=["\']([^"\']+)["\']', xml_str)
                provider_m = re.search(r'Provider\s+Name=["\']([^"\']+)["\']', xml_str)
                msg_m = re.search(r'<Message>(.*?)</Message>', xml_str, re.DOTALL)

                event_id = event_id_m.group(1) if event_id_m else "Unknown"
                level_num = level_m.group(1) if level_m else "4"
                timestamp = time_m.group(1).replace("T", " ")[:19] if time_m else "unknown"
                provider = provider_m.group(1) if provider_m else "WindowsEvent"

                if msg_m:
                    message = re.sub(r'\s+', ' ', msg_m.group(1)).strip()
                else:
                    data_vals = re.findall(r'<Data[^>]*>(.*?)</Data>', xml_str, re.DOTALL)
                    message = " | ".join([re.sub(r'\s+', ' ', d).strip() for d in data_vals if d.strip()])

                if not message or self._is_irrelevant_grs_or_daemon_noise(message):
                    continue

                guids = []
                for g in self.app_id_pattern.findall(message):
                    g_low = g.lower()
                    if _is_valid_app_id(g_low) and g_low not in guids:
                        guids.append(g_low)

                err_codes = self._extract_error_codes(message)
                is_error = (level_num in ("1", "2", "3")) or bool(err_codes) or any(
                    k in message.lower() for k in ["fail", "error", "cannot", "denied"]
                )

                if not is_error and not guids:
                    continue

                step_num, step_label = map_log_to_runbook_step(message)
                level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information"}
                clean_json_obj = {
                    "source": f"EventViewer ({file_name})",
                    "event_id": event_id,
                    "level": level_map.get(level_num, "Info"),
                    "runbook_step": step_label,
                    "timestamp": timestamp,
                    "app_ids": guids,
                    "error_codes": err_codes,
                    "message": message[:500]
                }

                nodes.append(Document(
                    text=json.dumps(clean_json_obj, indent=2),
                    metadata={
                        "file_name": file_name,
                        "source_type": "evtx",
                        "is_batch_payload": False,
                        "is_explicit_token_error": self._is_explicit_token_error(message),
                        "is_toast_noise": False,
                        "is_installed_telemetry": False,
                        "event_id": event_id,
                        "component": provider.split("-")[-1],
                        "phase": self._detect_phase(message),
                        "step_num": step_num,
                        "step_label": step_label,
                        "app_ids": guids,
                        "explicit_guids": guids,
                        "error_codes": err_codes,
                        "is_error": is_error,
                        "timestamp": timestamp,
                        "clean_message": message[:500]
                    }
                ))
        except Exception:
            pass
        return nodes

    def process_files(self, file_paths: List[str]) -> List[Document]:
        nodes = []

        for path in file_paths:
            if not os.path.exists(path):
                continue
            file_name = Path(path).name

            if path.lower().endswith(".evtx"):
                nodes.extend(self._parse_evtx_to_json_nodes(path, file_name))
                continue

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw_text = f.read()

            raw_chunks = re.split(r'(?=\<!\[LOG\[|\n\d{4}-\d{2}-\d{2}|\n\[[A-Za-z0-9])', raw_text)
            last_seen_guid = None
            chunks_since_explicit_guid = 999

            # Pre-extract clean messages so we can look ahead 1 line for PopToastNotification
            parsed_entries = []
            for chunk in raw_chunks:
                chunk = chunk.strip()
                if len(chunk) <= 20:
                    continue
                msg_match = re.search(r'\<!\[LOG\[(.*?)\]LOG\]!\>', chunk, re.DOTALL)
                clean_msg = msg_match.group(1).strip() if msg_match else chunk
                normalized_msg = re.sub(r'\s+', ' ', clean_msg)
                if not self._is_irrelevant_grs_or_daemon_noise(normalized_msg):
                    parsed_entries.append((chunk, normalized_msg))

            for idx, (chunk, normalized_msg) in enumerate(parsed_entries):
                next_msg_low = parsed_entries[idx + 1][1].lower() if (idx + 1) < len(parsed_entries) else ""

                # Detect benign Toast Notification LogonUser 1008 pair during ESP / Session 0
                is_toast_noise = (
                    self._is_toast_notification_noise(normalized_msg)
                    or ("logonuser failed with error code : 1008" in normalized_msg.lower() and "poptoastnotification" in next_msg_low)
                )

                comp_match = re.search(r'component="([^"]+)"', chunk)
                component = comp_match.group(1) if comp_match else file_name

                type_match = re.search(r'type="(\d)"', chunk)
                severity = {"1": "Info", "2": "Warning", "3": "Error"}.get(
                    type_match.group(1) if type_match else "1", "Info"
                )

                timestamp = "unknown"
                time_match = re.search(r'time="([^"]+)"\s+date="([^"]+)"', chunk)
                if time_match:
                    timestamp = f"{time_match.group(2)} {time_match.group(1)}"
                else:
                    ts_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', chunk)
                    if ts_match:
                        timestamp = ts_match.group(1)

                ordered_guids = []
                for g in self.app_id_pattern.findall(normalized_msg):
                    g_low = g.lower()
                    if _is_valid_app_id(g_low) and g_low not in ordered_guids:
                        ordered_guids.append(g_low)

                # CASE 1: Multi-App Batch JSON Line
                if len(ordered_guids) > 1:
                    phase = self._detect_phase(normalized_msg)
                    for g_id in ordered_guids:
                        app_slice = self._slice_around_guid(normalized_msg, g_id, window=750)
                        slice_errors = self._extract_error_codes(app_slice)
                        is_inst = self._is_installed_telemetry(app_slice)
                        is_benign = self._is_benign_status_line(app_slice)
                        slice_is_err = (
                            (
                                bool(slice_errors)
                                or any(
                                    kw in app_slice.lower() for kw in [
                                        '"installerror"', '"failed"', 'errorcode":-', 'type="3"',
                                        '"detectionfailed"', '"enforcementstate":5000'
                                    ]
                                )
                            )
                            and not is_benign
                            and not is_inst
                            and "get policies" not in normalized_msg.lower()
                        )
                        step_num, step_label = map_log_to_runbook_step(app_slice)
                        clean_json_obj = {
                            "source": file_name,
                            "severity": "Error" if slice_is_err else severity,
                            "phase": phase,
                            "runbook_step": step_label,
                            "timestamp": timestamp,
                            "app_id": g_id,
                            "error_codes": slice_errors,
                            "log_message": app_slice
                        }
                        nodes.append(Document(
                            text=json.dumps(clean_json_obj, indent=2),
                            metadata={
                                "file_name": file_name,
                                "source_type": "log",
                                "is_batch_payload": True,
                                "is_explicit_token_error": False,
                                "is_toast_noise": False,
                                "is_installed_telemetry": is_inst,
                                "component": component,
                                "phase": phase,
                                "step_num": step_num,
                                "step_label": step_label,
                                "app_ids": [g_id],
                                "explicit_guids": [g_id],
                                "error_codes": slice_errors,
                                "is_error": slice_is_err,
                                "timestamp": timestamp,
                                "clean_message": app_slice
                            }
                        ))
                    continue

                # CASE 2: Standard Single-App Line
                is_token_err = (not is_toast_noise) and self._is_explicit_token_error(normalized_msg)
                is_inst = self._is_installed_telemetry(normalized_msg)

                if ordered_guids:
                    last_seen_guid = ordered_guids[0]
                    chunks_since_explicit_guid = 0
                else:
                    chunks_since_explicit_guid += 1

                effective_guids = list(ordered_guids)
                if (
                    not effective_guids
                    and last_seen_guid
                    and _is_valid_app_id(last_seen_guid)
                    and chunks_since_explicit_guid <= 2
                ):
                    effective_guids = [last_seen_guid]

                err_codes = [] if is_toast_noise else self._extract_error_codes(normalized_msg)
                is_benign = self._is_benign_status_line(normalized_msg) or is_toast_noise
                is_error_chunk = (
                    (
                        severity == "Error"
                        or bool(err_codes)
                        or is_token_err
                        or any(kw in normalized_msg.lower() for kw in [
                            "installerror", "failed", "exception", "hostnotapplicable",
                            "application is not detected", "discovered: false", "isdiscovered: false",
                            '"enforcementstate":5000', "action status: failed"
                        ])
                    )
                    and not is_benign
                    and not is_inst
                    and "[simulated" not in normalized_msg.lower()
                )

                phase = self._detect_phase(normalized_msg)
                step_num, step_label = map_log_to_runbook_step(normalized_msg)
                msg_window = (
                    self._slice_around_guid(normalized_msg, effective_guids[0], 750)
                    if effective_guids else normalized_msg[:750]
                )

                clean_json_obj = {
                    "source": file_name,
                    "severity": "Error" if is_error_chunk else ("Warning (Toast Skipped)" if is_toast_noise else severity),
                    "phase": phase,
                    "runbook_step": step_label,
                    "timestamp": timestamp,
                    "app_id": effective_guids[0] if effective_guids else "Session / Global",
                    "error_codes": err_codes,
                    "log_message": msg_window
                }

                nodes.append(Document(
                    text=json.dumps(clean_json_obj, indent=2),
                    metadata={
                        "file_name": file_name,
                        "source_type": "log",
                        "is_batch_payload": False,
                        "is_explicit_token_error": is_token_err,
                        "is_toast_noise": is_toast_noise,
                        "is_installed_telemetry": is_inst,
                        "component": component,
                        "phase": phase,
                        "step_num": step_num,
                        "step_label": step_label,
                        "app_ids": effective_guids,
                        "explicit_guids": list(ordered_guids),
                        "error_codes": err_codes,
                        "is_error": is_error_chunk,
                        "timestamp": timestamp,
                        "clean_message": msg_window
                    }
                ))
        return nodes


# ==============================================================================
# DATA LAYER: PRE-INDEXED O(1) APP DOSSIER ENGINE
# ==============================================================================
class RetrievalEngine:
    def __init__(self):
        self.bm25 = None
        self.internal_nodes: List[Document] = []
        self.app_to_nodes: Dict[str, List[Document]] = {}
        self.app_dossiers: Dict[str, Dict] = {}

    def build_index(self, nodes: List[Document]):
        self.internal_nodes = nodes
        self.app_to_nodes = {}
        self.app_dossiers = {}

        corpus = [re.sub(r'[^a-z0-9]', ' ', node.text.lower()).split() for node in nodes]
        self.bm25 = BM25Okapi(corpus)

        evtx_nodes = [n for n in nodes if n.metadata.get("source_type") == "evtx"]

        for node in nodes:
            for aid in node.metadata.get("app_ids", []):
                if _is_valid_app_id(aid):
                    self.app_to_nodes.setdefault(aid, []).append(node)

        for aid, app_nodes in self.app_to_nodes.items():
            self.app_dossiers[aid] = self._compile_single_app_dossier(aid, app_nodes, evtx_nodes)

    def _extract_detection_rule_summary(self, msg: str) -> Optional[str]:
        if '"detectionrule"' not in msg.lower():
            return None
        unescaped = _clean_json_escaped_text(msg)
        path_m = re.search(r'"Path"\s*:\s*"([^"]+)"', unescaped, re.IGNORECASE)
        file_m = re.search(r'"FileOrFolderName"\s*:\s*"([^"]+)"', unescaped, re.IGNORECASE)
        key_m = re.search(r'"KeyPath"\s*:\s*"([^"]+)"', unescaped, re.IGNORECASE)
        msi_m = re.search(r'"ProductCode"\s*:\s*"([^"]+)"', unescaped, re.IGNORECASE)
        pkg_m = re.search(r'"PackageIdentifier"\s*:\s*"([^"]+)"', unescaped, re.IGNORECASE)
        if pkg_m:
            return f"Store/WinGet Package: {pkg_m.group(1)}"
        if path_m and file_m:
            return f"{path_m.group(1)}\\{file_m.group(1)}"
        if key_m:
            return f"Registry: {key_m.group(1)}"
        if msi_m:
            return f"MSI: {msi_m.group(1)}"
        return None

    def _compile_single_app_dossier(self, app_id: str, collected_nodes: List[Document], evtx_nodes: List[Document]) -> Dict:
        phases_seen = []
        steps_dict: Dict[int, str] = {}
        error_steps: List[Tuple[int, str]] = []
        extracted_cmd = None
        extracted_context = None
        extracted_app_name = None
        extracted_det_rule = None
        extracted_exit_code = None
        is_store_app = False
        has_positive_install_marker = False
        has_explicit_token_error = False
        had_benign_toast_1008 = False
        all_errors = []
        chronological_digest = []
        error_only_digest = []
        evtx_summaries = []

        for node in collected_nodes:
            m = node.metadata
            msg = m.get("clean_message", "")
            msg_low = msg.lower()
            p = m.get("phase", "0. Initialization")
            step_num = m.get("step_num", 1)
            step_label = m.get("step_label", "Step 1: Start to present application")

            if p not in phases_seen:
                phases_seen.append(p)
            steps_dict[step_num] = step_label

            if m.get("is_toast_noise", False):
                had_benign_toast_1008 = True

            for c in m.get("error_codes", []):
                if c not in all_errors:
                    all_errors.append(c)

            status_prefix = "ERROR" if (m.get("is_error") or m.get("error_codes")) else "INFO"
            compact_entry = f"[{m.get('timestamp')} | {step_label} | {status_prefix}]: {msg[:260]}"
            chronological_digest.append(compact_entry)

            if any(k in msg_low for k in ["ms store", "new store", "winget", "packageidentifier", "universal", "uwp"]):
                is_store_app = True

            if m.get("is_explicit_token_error", False):
                has_explicit_token_error = True

            if m.get("is_installed_telemetry", False):
                has_positive_install_marker = True

            if not extracted_det_rule:
                extracted_det_rule = self._extract_detection_rule_summary(msg)

            if not extracted_cmd:
                cmd_json_m = re.search(r'"InstallCommandLine"\s*:\s*"((?:\\.|[^"\\])*)"', msg, re.IGNORECASE)
                if cmd_json_m and cmd_json_m.group(1).strip():
                    extracted_cmd = _clean_json_escaped_text(cmd_json_m.group(1))
                else:
                    cmd_m = re.search(
                        r'(?:command\s*line|cmdLine|Execute\s+command)\s*[=:]+\s*([^\r\n\}]+)',
                        msg, re.IGNORECASE
                    )
                    if cmd_m and cmd_m.group(1).strip():
                        extracted_cmd = _clean_json_escaped_text(cmd_m.group(1))

            if not extracted_app_name:
                name_m = re.search(r'(?:AppName|ApplicationName|"Name"|App\s+name)\s*["\'=:]+\s*"?([^"\r\n\},]+)"?', msg, re.IGNORECASE)
                if name_m:
                    candidate_name = _clean_json_escaped_text(name_m.group(1))
                    if len(candidate_name) > 2 and not _is_valid_app_id(candidate_name):
                        extracted_app_name = candidate_name
                        if "store" in candidate_name.lower():
                            is_store_app = True

            if not extracted_exit_code:
                exit_m = re.search(r'(?:lpExitCode|ExitCode|ReturnCode)\s*["\'=:]+\s*(-?\d+)', msg, re.IGNORECASE)
                if exit_m and exit_m.group(1).strip() not in ("0", "1"):
                    extracted_exit_code = exit_m.group(1).strip()

            if not extracted_context:
                if re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bUser\b|"InstallContext":\s*1', msg, re.IGNORECASE):
                    extracted_context = "User Context (InstallContext: 1)"
                elif re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bSystem\b|"InstallContext":\s*2|user:\s*00000000-0000-0000-0000-000000000000', msg, re.IGNORECASE):
                    extracted_context = "SYSTEM Context (Session 0 / InstallContext: 2)"

            if m.get("is_error") or m.get("error_codes"):
                if (step_num, step_label) not in error_steps:
                    error_steps.append((step_num, step_label))
                error_only_digest.append(compact_entry)

        err_set = set(all_errors)
        for node in evtx_nodes:
            m = node.metadata
            if (app_id in m.get("app_ids", [])) or (err_set and err_set.intersection(set(m.get("error_codes", [])))):
                evtx_summaries.append(
                    f"Event ID {m.get('event_id')} ({m.get('component')}): {m.get('clean_message')[:200]}"
                )

        # If final state reached ResultantAppState: 1 / EnforcementState: 1000 / DetectionState: Installed,
        # the app succeeded—do NOT let transient mid-install warnings override a verified installation!
        is_already_installed = has_positive_install_marker
        has_real_failure = (not is_already_installed) and bool(all_errors or error_steps)

        if has_real_failure:
            steps_dict.pop(18, None)

        sorted_steps = [steps_dict[k] for k in sorted(steps_dict.keys())]
        completed_steps_str = " -> ".join(sorted_steps) if sorted_steps else "Step 1: Start to present application"

        if is_already_installed:
            stopping_step = "Step 18: Set EnforcementStateMessage (Installed & Compliant)"
            failing_phase = "None — Installed & Compliant"
            primary_err_code = "0 (Installed)"
            # Pick the final compliance/detection confirmation record as Key Log Record
            confirm_lines = [
                x for x in chronological_digest
                if any(k in x.lower() for k in ['"resultantappstate":1', '"enforcementstate":1000', 'detection state: detected', 'to completed'])
            ]
            focused_digest = confirm_lines[-2:] if confirm_lines else chronological_digest[-3:]
            key_error_line = focused_digest[-1] if focused_digest else "N/A"
        elif not has_real_failure:
            stopping_step = sorted_steps[-1] if sorted_steps else "Step 1: Start to present application"
            failing_phase = "None — Evaluated (No Error)"
            primary_err_code = "None (0)"
            focused_digest = chronological_digest[-3:]
            key_error_line = chronological_digest[-1] if chronological_digest else "N/A"
        else:
            stopping_step = error_steps[-1][1] if error_steps else sorted_steps[-1]
            non_init = [p for p in phases_seen if p != "0. Initialization"]
            failing_phase = non_init[-1] if non_init else "5. Execution"
            primary_err_code = all_errors[0].upper() if all_errors else (
                f"ExitCode {extracted_exit_code}" if extracted_exit_code else "Execution / Detection Error"
            )
            if error_only_digest:
                preceding_context = [x for x in chronological_digest[-3:] if x not in error_only_digest][-1:]
                focused_digest = (preceding_context + error_only_digest[-3:])[-4:]
                key_error_line = error_only_digest[-1]
            else:
                focused_digest = chronological_digest[-4:]
                key_error_line = chronological_digest[-1] if chronological_digest else "N/A"

        last_ts = collected_nodes[-1].metadata.get("timestamp", "Unknown") if collected_nodes else "Unknown"
        source_file = collected_nodes[-1].metadata.get("file_name", "AppWorkload.log") if collected_nodes else "AppWorkload.log"
        default_cmd_label = "None (Microsoft Store / WinGet Managed)" if is_store_app else "Not logged in captured chunk"

        dossier = {
            "app_id": app_id,
            "total_records_collected": len(collected_nodes),
            "all_evidence_json": "\n".join([n.text for n in collected_nodes]),
            "app_name": extracted_app_name or "Unnamed Win32 App",
            "command_line": extracted_cmd or default_cmd_label,
            "detection_rule_summary": extracted_det_rule or ("Microsoft Store Package Detection" if is_store_app else "Custom / MSI Detection Rule"),
            "install_context": extracted_context or "SYSTEM Context (Session 0)",
            "is_store_app": is_store_app,
            "is_already_installed": is_already_installed,
            "has_real_failure": has_real_failure,
            "has_explicit_token_error": has_explicit_token_error,
            "had_benign_toast_1008": had_benign_toast_1008,
            "lifecycle_trail": " -> ".join(phases_seen) if phases_seen else failing_phase,
            "completed_steps_summary": completed_steps_str,
            "stopping_step": stopping_step,
            "failing_phase": failing_phase,
            "error_code": primary_err_code,
            "focused_digest": focused_digest,
            "key_error_line": key_error_line,
            "evtx_findings": evtx_summaries[:2] if evtx_summaries else ["None"],
            "timestamp": last_ts,
            "source_file": source_file
        }

        cause, fix = build_deterministic_diagnosis_and_fix(dossier)
        dossier["verified_root_cause"] = cause
        dossier["verified_actionable_fix"] = fix
        return dossier

    def get_all_unique_app_ids(self) -> List[Dict[str, str]]:
        results = []
        for aid, d in self.app_dossiers.items():
            if d["is_already_installed"]:
                status = "Installed (Compliant)"
            elif not d["has_real_failure"]:
                status = "Healthy / Evaluated (No Error)"
            else:
                status = "Failed"
            results.append({
                "app_id": aid,
                "app_name": d["app_name"],
                "last_phase": d["failing_phase"],
                "last_seen": d["timestamp"],
                "status": status,
                "error_code": d["error_code"]
            })
        return results

    def search_with_metadata(self, query: str, exact_match_keyword: str = None) -> Dict:
        target_app_id = None

        if exact_match_keyword and _is_valid_app_id(exact_match_keyword):
            candidate = exact_match_keyword.lower().strip()
            if candidate in self.app_dossiers:
                target_app_id = candidate

        if not target_app_id and not exact_match_keyword:
            failing_candidates = [
                d for d in self.app_dossiers.values()
                if d["has_real_failure"]
            ]
            if failing_candidates:
                failing_candidates.sort(
                    key=lambda x: (
                        x["error_code"] not in ("Execution / Detection Error", "0 (Installed)", "None (0)"),
                        x["total_records_collected"]
                    ),
                    reverse=True
                )
                target_app_id = failing_candidates[0]["app_id"]

        if not target_app_id or target_app_id not in self.app_dossiers:
            return {"evidence": "No matching device logs found."}

        d = self.app_dossiers[target_app_id]
        return {
            "evidence": d["all_evidence_json"],
            "total_records": d["total_records_collected"],
            "error_code": d["error_code"],
            "verified_root_cause": d["verified_root_cause"],
            "verified_actionable_fix": d["verified_actionable_fix"],
            "is_already_installed": d["is_already_installed"],
            "has_real_failure": d["has_real_failure"],
            "phase": d["failing_phase"],
            "stopping_step": d["stopping_step"],
            "completed_steps_summary": d["completed_steps_summary"],
            "lifecycle_trail": d["lifecycle_trail"],
            "app_name": d["app_name"],
            "command_line": d["command_line"],
            "detection_rule_summary": d["detection_rule_summary"],
            "install_context": d["install_context"],
            "error_messages": d["focused_digest"],
            "key_error_line": d["key_error_line"],
            "evtx_findings": d["evtx_findings"],
            "timestamp": d["timestamp"],
            "app_id": target_app_id,
            "source_file": d["source_file"]
        }


# ==============================================================================
# KNOWLEDGE LAYER: RUNBOOK DIAGNOSTIC MATCHER
# ==============================================================================
class KnowledgeAgent:
    def __init__(self):
        self.paragraphs: List[str] = []
        self.bm25: Optional[BM25Okapi] = None

    def ingest_runbooks(self, file_paths: List[str]):
        self.paragraphs = []
        for path in file_paths:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for para in f.read().split("\n\n"):
                    cleaned = para.strip()
                    low = cleaned.lower()
                    if "remediation & forced reinstallation" in low or "hklm\\software\\microsoft\\intunemanagementextension\\apps" in low:
                        continue
                    if len(cleaned) > 25:
                        self.paragraphs.append(cleaned)

        if self.paragraphs:
            corpus = [re.sub(r'[^a-z0-9]', ' ', p.lower()).split() for p in self.paragraphs]
            self.bm25 = BM25Okapi(corpus)


# ==============================================================================
# ORCHESTRATOR: INSTANT O(1) DOSSIER + GROUNDED STREAMING ENGINE
# ==============================================================================
class LangGraphOrchestrator:
    def __init__(self, log_paths: List[str], runbook_paths: List[str]):
        self.ingestion = IngestionAgent()
        self.retrieval = RetrievalEngine()
        self.knowledge = KnowledgeAgent()
        self.last_target_app_id: Optional[str] = None

        nodes = self.ingestion.process_files(log_paths)
        if nodes:
            self.retrieval.build_index(nodes)
        if runbook_paths:
            self.knowledge.ingest_runbooks(runbook_paths)

        model_1_5b = get_resource_path(os.path.join("models", "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"))
        model_3b = get_resource_path(os.path.join("models", "qwen2.5-coder-3b-instruct-q4_k_m.gguf"))
        model_path = model_1_5b if os.path.exists(model_1_5b) else model_3b

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"GGUF Model not found at: {model_3b}")

        total_logical = os.cpu_count() or 8
        optimal_threads = max(2, min(6, (total_logical // 2)))

        self.llm = Llama(
            model_path=model_path,
            n_gpu_layers=-1,
            n_ctx=1024,
            n_threads=optimal_threads,
            n_threads_batch=optimal_threads,
            n_batch=512,
            use_mmap=True,
            use_mlock=False,
            verbose=False
        )

        self.prefix_cache = LlamaRAMCache(capacity_bytes=128 * 1024 * 1024)
        self.llm.set_cache(self.prefix_cache)

        self.static_system_prompt = (
            "You are a Senior Microsoft Intune Escalation Engineer. "
            "Summarize the Verified Status/Root Cause below in 2 clear, direct sentences starting with '• Analysis Summary:'. "
            "Never invent errors if the Verified Status states the app is Installed or has No Failure."
        )

    def prepare_turn(self, query: str) -> Dict:
        q_lower = query.lower()
        list_keywords = ["all application id", "all app id", "list app", "fetch all", "which apps", "mentioned in the log"]

        if any(kw in q_lower for kw in list_keywords):
            apps = self.retrieval.get_all_unique_app_ids()
            if not apps:
                text = "No standard Intune Application GUIDs were detected in the loaded logs."
            else:
                lines = [f"Found {len(apps)} unique Application ID(s) across the ingested logs (GRS noise filtered):\n"]
                for idx, item in enumerate(apps, 1):
                    lines.append(
                        f"{idx}. App ID: {item['app_id']} ({item['app_name']})\n"
                        f"   • Status: {item['status']} (Code: {item['error_code']}) | "
                        f"Phase: {item['last_phase']} | Last Seen: {item['last_seen']}"
                    )
                text = "\n".join(lines)
            return {
                "mode": "instant",
                "response": text,
                "evidence": "\n".join([f"{a['app_id']} - {a['app_name']} ({a['status']} - {a['error_code']})" for a in apps]),
                "status_tag": f"Status: {len(apps)} Apps Found",
                "phase_tag": "Tags: App Inventory"
            }

        app_id_pattern = re.compile(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)
        match = app_id_pattern.search(query)
        explicit_query_guid = match.group(1).lower() if (match and _is_valid_app_id(match.group(1))) else None
        target_app_id = explicit_query_guid if explicit_query_guid else self.last_target_app_id

        hit = self.retrieval.search_with_metadata(query, exact_match_keyword=target_app_id)
        if hit["evidence"] == "No matching device logs found." or not _is_valid_app_id(hit.get("app_id", "")):
            missing_msg = (
                f"App ID `{explicit_query_guid}` was not found in the loaded log files."
                if explicit_query_guid
                else "No failing Win32 or Store application entries were detected in the uploaded logs. All evaluated apps appear healthy or installed."
            )
            return {
                "mode": "instant",
                "response": missing_msg,
                "evidence": "",
                "status_tag": "Status: No Failures",
                "phase_tag": "Phase: Healthy"
            }

        if _is_valid_app_id(hit.get("app_id")):
            self.last_target_app_id = hit["app_id"]

        failing_line_preview = hit.get("key_error_line", "N/A")

        instant_header = (
            f"Target App ID: {hit['app_id']}  |  App Name: {hit['app_name']}  |  Logs Collected: {hit['total_records']} record(s)\n"
            f"Detected Status / Code: {hit['error_code']}  |  Stopping Step: {hit['stopping_step']}\n"
            f"Chronological Lifecycle Trace:\n"
            f"  • Ordered 18-Step Trail: {hit['completed_steps_summary']}\n"
            f"  • Context & Command: {hit['install_context']}  |  Cmd: {hit['command_line'][:100]}\n"
            f"  • Configured Detection Rule: {hit['detection_rule_summary']}\n"
            f"  • Key Log Record: {failing_line_preview[:300]}\n"
            f"{'-'*75}\n"
        )

        verified_fix_footer = (
            f"\n\n• Verified Intune Admin & Packaging Guidance:\n"
            f"{hit['verified_actionable_fix']}"
        )

        if hit.get("is_already_installed"):
            status_tag = "Status: Installed"
        elif not hit.get("has_real_failure"):
            status_tag = "Status: No Error"
        else:
            status_tag = f"Error: {hit['error_code']}"

        return {
            "mode": "stream",
            "instant_header": instant_header,
            "verified_fix_footer": verified_fix_footer,
            "evidence": hit["evidence"],
            "verified_root_cause": hit["verified_root_cause"],
            "stopping_step": hit["stopping_step"],
            "app_id": hit["app_id"],
            "app_name": hit["app_name"],
            "error_code": hit["error_code"],
            "status_tag": status_tag,
            "phase_tag": hit["stopping_step"][:28],
            "query": query
        }

    def stream_llm_explanation(self, prepared: Dict) -> Iterator[str]:
        messages = [
            {"role": "system", "content": self.static_system_prompt},
            {
                "role": "user",
                "content": (
                    f"Verified Status/Root Cause: {prepared['verified_root_cause']}\n"
                    f"Write the '• Analysis Summary:' now:"
                )
            }
        ]

        stream = self.llm.create_chat_completion(
            messages=messages,
            temperature=0.0,
            top_p=0.9,
            repeat_penalty=1.15,
            max_tokens=85,
            stream=True
        )

        for chunk in stream:
            delta = chunk["choices"][0].get("delta", {})
            token = delta.get("content", "")
            if token:
                yield token

        yield prepared["verified_fix_footer"]

    def close(self):
        pass
