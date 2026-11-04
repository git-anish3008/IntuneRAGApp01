import os
import sys
import re
import json
import ctypes
import subprocess
import xml.etree.ElementTree as ET
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Iterator
from llama_index.core import Document
from llama_cpp import Llama, LlamaRAMCache
from rank_bm25 import BM25Okapi


def get_resource_path(relative_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, relative_path)

# Remove the all the possibe invalid app_id values (null GUIDs, placeholders, etc.) from the list of app_ids.
def _is_valid_app_id(app_id: str) -> bool:
    """Filters out null GUIDs (00000000-0000-0000-0000-000000000000) and placeholders."""
    if not app_id:
        return False
    clean = app_id.replace("-", "").lower()
    return clean != "00000000000000000000000000000000" and len(clean) == 32

# Convert all decimal error codes to hex format for consistency, but leave non-numeric strings unchanged.
def decimal_to_hex_error(decimal_str: str) -> str:
    try:
        val = int(decimal_str)
        if val < 0:
            return f"0x{(val & 0xFFFFFFFF):08X}"
        return str(val)
    except Exception:
        return decimal_str

# Context-aware Intune error analyzer
def decode_contextual_intune_error(error_code: str, phase: str, log_lines_text: str, lifecycle_trail: str) -> str:
    """
    Context-aware Intune error analyzer: combines the Error Code + Failing Phase + Actual Log Text
    so generic Win32 codes like 0x80070002 are never reduced to unhelpful OS boilerplate.
    """
    code_clean = error_code.strip().lower()
    log_lower = log_lines_text.lower()
    phase_lower = phase.lower()

    if "getaadjoininfo" in log_lower or "check if device is wpj" in log_lower or "netgetaadjoininformation" in log_lower:
        return (
            "Workplace Join (WPJ) / Entra Join Lookup Exception (0x80070002 / -2147024894 in NetGetAadJoinInformation): "
            "IME called GetAADJoinInfo to check for a Workplace Join certificate/registry state under "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo or HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\WorkplaceJoin, "
            "and Windows returned 0x80070002 (Key/Certificate Not Found). Note: If the device is purely Entra Joined (without secondary WPJ), "
            "this is a background IME check; if device check-in is failing, verify PRT and join state via `dsregcmd /status`."
        )

    if "0x87d1041c" in code_clean or (
        "5. execution -> 2. detection" in lifecycle_trail.lower()
        and ("not detected" in log_lower or "discovered: false" in log_lower or "detection" in phase_lower)
    ):
        return (
            "Post-Install Detection Rule Failure (Execution -> Detection Mismatch): "
            "The application reached 5. Execution and the installer process exited, but during the subsequent "
            "2. Detection check, IME's DetectionManager could not find the expected file path, registry key, or MSI ProductCode "
            "(returning Not Discovered / 0x80070002 / 0x87D1041C). Either the silent installer exited prematurely/rolled back, "
            "or the Intune Detection Rule path/WOW6432Node setting does not match what the installer actually wrote."
        )

    if code_clean == "0x80070002":
        if "detection" in phase_lower or "detect" in log_lower:
            return (
                "Intune Detection Rule Target Not Found (0x80070002 in 2. Detection): "
                "IME evaluated the app's Detection Rule (File, Registry key, or MSI ProductCode), and Windows returned "
                "0x80070002 because that target path/key does not exist on disk/registry. Since the lifecycle reached "
                f"[{lifecycle_trail}], the installer either failed to create the target file/registry key during 5. Execution "
                "or wrote it to a 32-bit redirected path (HKLM\\SOFTWARE\\WOW6432Node or Program Files (x86))."
            )
        if "execution" in phase_lower or "createprocess" in log_lower or "imecache" in log_lower:
            return (
                "Win32 Installer Executable Not Found in IMECache (0x80070002 in 5. Execution): "
                "IME extracted the .intunewin payload into C:\\Windows\\IMECache\\<AppGUID>_1, but CreateProcess failed with "
                "0x80070002 because the executable/script name in the Intune 'Install command' does not match the files inside the package root."
            )
        if "download" in phase_lower or "decrypt" in phase_lower or "staging" in log_lower or "incoming" in log_lower:
            return (
                "Missing Staged .intunewin Payload (0x80070002 in Download/Decryption): "
                "IME attempted to decrypt or move the downloaded package in C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Content, "
                "but the file was missing (often quarantined by Antivirus/Defender or cleaned up mid-transfer)."
            )

    intune_specific = {
        "1008": (
            "ERROR_NO_TOKEN (Win32 Error 1008: 'An attempt was made to reference a token that does not exist'). "
            "The installer or IME component running in SYSTEM context (Session 0) attempted to query an interactive user token, "
            "HKCU registry hive, or WTSQueryUserToken when no user session token was bound."
        ),
        "0x80244022": (
            "WU_E_PT_HTTP_STATUS_SERVICE_UNAVAILABLE (0x80244022 / -2145107934). "
            "WinGetAppExecutionExecutor failed because the Microsoft Store / WinGet CDN returned HTTP 503 or corporate SSL inspection blocked SYSTEM-context WinGet traffic."
        ),
        "0x87d30065": "Intune Win32 Content Download / Network Staging Failure (0x87D30065) from Azure CDN / Delivery Optimization.",
        "0x87d30067": "Intune Win32 SHA256 Content Hash Verification Mismatch (0x87D30067) during Phase 4 (Decryption).",
        "0x87d30000": "Intune Win32 Applicability / Requirement Rule Not Met (0x87D30000).",
        "1603": "ERROR_INSTALL_FAILURE (MSI Exit Code 1603): Fatal error during installation execution/rollback inside C:\\Windows\\IMECache.",
        "1618": "ERROR_INSTALL_ALREADY_RUNNING (MSI Exit Code 1618): Another msiexec.exe installation is holding the _MSIExecute mutex.",
        "3010": "ERROR_SUCCESS_REBOOT_REQUIRED (Exit Code 3010): Installation succeeded, but a reboot is required to complete."
    }
    if code_clean in intune_specific:
        return intune_specific[code_clean]

    if code_clean in ("n/a", "see log", "none", "none (0)", "0", "0x0", "0x00000000", ""):
        return f"No explicit OS error code thrown; inspect the exact phase transition [{lifecycle_trail}] and log message below."

    try:
        if code_clean.startswith("0x"):
            val = int(code_clean, 16)
            if (val & 0xFFFF0000) == 0x80070000:
                win32_code = val & 0xFFFF
                os_msg = ctypes.FormatError(win32_code).strip()
                if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                    return f"HRESULT {error_code.upper()} (Win32 Error {win32_code} during {phase}): {os_msg}"
            signed_val = val - 0x100000000 if val >= 0x80000000 else val
            os_msg = ctypes.FormatError(signed_val).strip()
            if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                return f"Windows OS Error {error_code.upper()} (during {phase}): {os_msg}"
        else:
            val = int(code_clean)
            os_msg = ctypes.FormatError(val).strip()
            if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                return f"Windows Win32 Error {val} (during {phase}): {os_msg}"
    except Exception:
        pass

    return f"Installer / Intune Return Code {error_code.upper()} logged during {phase}"


def build_ime_force_retry_commands(app_id: str) -> str:
    clean_id = app_id if _is_valid_app_id(app_id) else "<App-GUID>"
    return (
        f"\n• Force Immediate Intune IME Re-Evaluation (Bypass 24h GRS Timer):\n"
        f"  ```powershell\n"
        f"  Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Microsoft\\IntuneManagementExtension\\Win32Apps' -Recurse -ErrorAction SilentlyContinue |\n"
        f"      Where-Object {{ $_.Name -match '{clean_id}' }} | Remove-Item -Recurse -Force\n"
        f"  Remove-Item -Path 'C:\\Windows\\IMECache\\{clean_id}*' -Recurse -Force -ErrorAction SilentlyContinue\n"
        f"  Restart-Service -Name IntuneManagementExtension -Force\n"
        f"  ```"
    )


# ==============================================================================
# DATA LAYER: APP-ISOLATED INGESTION AGENT (.LOG & .EVTX)
# ==============================================================================
class IngestionAgent:
    def __init__(self):
        self.app_id_pattern = re.compile(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)
        self.hex_pattern = re.compile(r'\b(0x[8cC][0-9a-fA-F]{7})\b')
        self.dec_err_pattern = re.compile(
            r'(?:error\s*code|exit\s*code|lpexitcode|return\s*code|win32error|hresult|"ErrorCode"|\berr\s+is)\s*["\'=:]+\s*(-?\d{1,10})',
            re.IGNORECASE
        )

    def _is_global_device_noise(self, text: str) -> bool:
        low = text.lower()
        global_markers = [
            "aad user check",
            "graph audience",
            "check if device is wpj",
            "getaadjoininfo",
            "netgetaadjoininformation",
            "emsagent",
            "clienthealth",
            "healthcheck",
            "poller",
            "impersonate",
            "get token",
            "token acquisition"
        ]
        return any(m in low for m in global_markers)

    def _is_benign_status_line(self, text: str) -> bool:
        low = text.lower()
        benign_patterns = [
            "could not be loaded from store. reporting state initialized",
            "reporting state initialized with initial values",
            "handler completed with action status: success",
            "detection operation result has arrived detected",
            "package manager initialized with status: ok",
            "connect result status: ok",
            "rebootflag is false"
        ]
        return any(p in low for p in benign_patterns)

    def _detect_phase(self, text: str) -> str:
        lower = text.lower()
        if "[reportingmanager]" in lower or "sending results to service" in lower or "requestpayload" in lower or "sending status to company portal" in lower:
            return "6. Reporting"
        if "get policies" in lower or self._is_global_device_noise(lower):
            return "0. Initialization"
        if any(kw in lower for kw in [
            "[executionactionhandler]", "executionexecutor", "wingetappexecution",
            "agentexecutor", "executionmanager", "installing", "installerror",
            "lpexitcode", "createprocess", "command line", "imecache"
        ]):
            return "5. Execution"
        if any(kw in lower for kw in ["decrypt", "unzip", "extract", "hash", "decryptionmanager"]):
            return "4. Decryption"
        if any(kw in lower for kw in ["download", "bits", "dojob", "cdn", "incoming", "staging", "contentmanager"]):
            return "3. Download"
        if any(kw in lower for kw in [
            "[detectionactionhandler]", "detect", "isdiscovered", "detectionmanager",
            "processdetectionrules", "application is not detected"
        ]):
            return "2. Detection"
        if any(kw in lower for kw in ["requirement", "applicability", "checkapplicability", "grs", "grsmanager"]):
            return "1. Applicability"
        return "0. Initialization"

    def _extract_error_codes(self, text: str) -> List[str]:
        codes = [c.lower() for c in self.hex_pattern.findall(text)]
        for dec in self.dec_err_pattern.findall(text):
            if dec in ("0", "1"):
                continue
            converted = decimal_to_hex_error(dec).lower()
            if converted not in codes:
                codes.append(converted)
        for msi_code in re.findall(r'\b(1008|1603|1618|1605|1641|3010)\b', text):
            if msi_code not in codes:
                codes.append(msi_code)
        return codes

    def _slice_around_guid(self, text: str, guid: str, window: int = 900) -> str:
        pos = text.lower().find(guid.lower())
        if pos == -1:
            return text[:window]
        start = max(0, pos - 80)
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

                if not message:
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

                level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information"}
                clean_json_obj = {
                    "source": f"EventViewer ({file_name})",
                    "provider": provider.split("-")[-1],
                    "event_id": event_id,
                    "level": level_map.get(level_num, "Info"),
                    "timestamp": timestamp,
                    "app_ids": guids,
                    "error_codes": err_codes,
                    "message": message[:700]
                }

                nodes.append(Document(
                    text=json.dumps(clean_json_obj, indent=2),
                    metadata={
                        "file_name": file_name,
                        "source_type": "evtx",
                        "is_batch_payload": False,
                        "event_id": event_id,
                        "component": provider.split("-")[-1],
                        "phase": self._detect_phase(message),
                        "app_ids": guids,
                        "explicit_guids": guids,
                        "error_codes": err_codes,
                        "is_error": is_error,
                        "timestamp": timestamp,
                        "clean_message": message[:700]
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

            chunks = re.split(r'(?=\<!\[LOG\[|\n\d{4}-\d{2}-\d{2}|\n\[[A-Za-z0-9])', raw_text)
            last_seen_guid = None
            chunks_since_explicit_guid = 999

            for chunk in chunks:
                chunk = chunk.strip()
                if len(chunk) <= 20:
                    continue

                msg_match = re.search(r'\<!\[LOG\[(.*?)\]LOG\]!\>', chunk, re.DOTALL)
                clean_msg = msg_match.group(1).strip() if msg_match else chunk
                normalized_msg = re.sub(r'\s+', ' ', clean_msg)

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
                        app_slice = self._slice_around_guid(normalized_msg, g_id, window=900)
                        slice_errors = self._extract_error_codes(app_slice)
                        is_benign = self._is_benign_status_line(app_slice)
                        slice_is_err = (
                            (
                                bool(slice_errors)
                                or any(
                                    kw in app_slice.lower() for kw in [
                                        '"installerror"', '"failed"', 'errorcode":-', 'type="3"',
                                        '"notdetected"', '"detectionfailed"'
                                    ]
                                )
                            )
                            and not is_benign
                        )
                        clean_json_obj = {
                            "source": file_name,
                            "component": component,
                            "severity": "Error" if slice_is_err else severity,
                            "phase": phase,
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
                                "component": component,
                                "phase": phase,
                                "app_ids": [g_id],
                                "explicit_guids": [g_id],
                                "error_codes": slice_errors,
                                "is_error": slice_is_err,
                                "timestamp": timestamp,
                                "clean_message": app_slice
                            }
                        ))
                    continue

                # CASE 2: Standard Single-App or Device Line
                is_global_noise = self._is_global_device_noise(normalized_msg)

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
                    and not is_global_noise
                ):
                    effective_guids = [last_seen_guid]

                err_codes = self._extract_error_codes(normalized_msg)
                is_benign = self._is_benign_status_line(normalized_msg)
                is_error_chunk = (
                    (
                        severity == "Error"
                        or bool(err_codes)
                        or any(kw in normalized_msg.lower() for kw in [
                            "installerror", "error", "failed", "exception",
                            "not detected", "discovered: false", "isdiscovered: false"
                        ])
                    )
                    and not is_global_noise
                    and not is_benign
                )

                phase = self._detect_phase(normalized_msg)
                msg_window = (
                    self._slice_around_guid(normalized_msg, effective_guids[0], 900)
                    if effective_guids else normalized_msg[:900]
                )

                clean_json_obj = {
                    "source": file_name,
                    "component": component,
                    "severity": severity,
                    "phase": phase,
                    "timestamp": timestamp,
                    "app_id": effective_guids[0] if effective_guids else "Device-Level / Global",
                    "error_codes": err_codes,
                    "log_message": msg_window
                }

                nodes.append(Document(
                    text=json.dumps(clean_json_obj, indent=2),
                    metadata={
                        "file_name": file_name,
                        "source_type": "log",
                        "is_batch_payload": False,
                        "is_global_noise": is_global_noise,
                        "component": component,
                        "phase": phase,
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
# DATA LAYER: AUTOMATED PER-APP DOSSIER & EVENT VIEWER CORRELATOR
# ==============================================================================
class RetrievalEngine:
    def __init__(self):
        self.bm25 = None
        self.internal_nodes: List[Document] = []

    def build_index(self, nodes: List[Document]):
        self.internal_nodes = nodes
        corpus = [re.sub(r'[^a-z0-9]', ' ', node.text.lower()).split() for node in nodes]
        self.bm25 = BM25Okapi(corpus)

    def get_all_unique_app_ids(self) -> List[Dict[str, str]]:
        app_summary = {}
        for node in self.internal_nodes:
            for app_id in node.metadata.get("explicit_guids", []):
                if not _is_valid_app_id(app_id):
                    continue
                has_err = node.metadata.get("is_error", False)
                err_codes = node.metadata.get("error_codes", [])
                prev = app_summary.get(app_id, {})
                prev_status = prev.get("status", "Processed")
                prev_code = prev.get("error_code", "None")

                new_code = err_codes[0] if err_codes else prev_code
                new_status = "Failed" if (has_err or prev_status == "Failed") else "Processed"

                node_phase = node.metadata.get("phase", "Unknown")
                prev_phase = prev.get("last_phase", "0. Initialization")
                best_phase = node_phase if (node_phase != "0. Initialization" or not prev) else prev_phase

                app_summary[app_id] = {
                    "app_id": app_id,
                    "last_phase": best_phase,
                    "last_seen": node.metadata.get("timestamp", "unknown"),
                    "status": new_status,
                    "error_code": new_code
                }
        return list(app_summary.values())

    def _build_app_dossier(self, app_id: str, primary_idx: int) -> Dict[str, str]:
        phases_seen = []
        extracted_cmd = None
        extracted_context = None
        extracted_app_name = None
        extracted_exit_code = None
        all_errors = []
        active_phase_error_msgs = []
        init_error_msgs = []
        batch_error_msgs = []
        active_phase_all_msgs = []
        all_app_msgs = []
        evtx_summaries = []

        for idx, node in enumerate(self.internal_nodes):
            m = node.metadata
            if app_id in m.get("app_ids", []):
                p = m.get("phase", "0. Initialization")
                if p not in phases_seen:
                    phases_seen.append(p)
                for c in m.get("error_codes", []):
                    if c not in all_errors:
                        all_errors.append(c)

                msg = m.get("clean_message", "")
                formatted_line = f"[{m.get('file_name')} | {p} | {m.get('timestamp')}]: {msg}"
                all_app_msgs.append(formatted_line)
                if p not in ("0. Initialization", "6. Reporting") and not m.get("is_batch_payload"):
                    active_phase_all_msgs.append(formatted_line)

                if not extracted_cmd:
                    cmd_m = re.search(
                        r'(?:InstallCommandLine|command\s*line|cmdLine|Execute\s+command)\s*["\'=:]+\s*([^"\r\n\}]+)',
                        msg, re.IGNORECASE
                    )
                    if cmd_m:
                        extracted_cmd = cmd_m.group(1).strip()

                if not extracted_app_name:
                    name_m = re.search(r'(?:AppName|ApplicationName|"Name")\s*["\'=:]+\s*"([^"]+)"', msg, re.IGNORECASE)
                    if name_m:
                        extracted_app_name = name_m.group(1).strip()

                if not extracted_exit_code:
                    exit_m = re.search(r'(?:lpExitCode|ExitCode|ReturnCode)\s*["\'=:]+\s*(-?\d+)', msg, re.IGNORECASE)
                    if exit_m:
                        extracted_exit_code = exit_m.group(1).strip()

                if not extracted_context:
                    if re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bUser\b|"InstallContext":\s*1', msg, re.IGNORECASE):
                        extracted_context = "User Context"
                    elif re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bSystem\b|"InstallContext":\s*2', msg, re.IGNORECASE):
                        extracted_context = "SYSTEM Context (Session 0)"

                if m.get("is_error") or m.get("error_codes"):
                    if m.get("is_batch_payload"):
                        batch_error_msgs.append(formatted_line)
                    elif p != "0. Initialization":
                        active_phase_error_msgs.append(formatted_line)
                    else:
                        init_error_msgs.append(formatted_line)

        err_set = set(all_errors)
        for node in self.internal_nodes:
            m = node.metadata
            if m.get("source_type") == "evtx":
                if (app_id in m.get("app_ids", [])) or (err_set and err_set.intersection(set(m.get("error_codes", [])))):
                    evtx_summaries.append(
                        f"Event ID {m.get('event_id')} ({m.get('component')}): {m.get('clean_message')[:250]}"
                    )

        non_init_phases = [p for p in phases_seen if p != "0. Initialization"]
        failing_phase = non_init_phases[-1] if non_init_phases else (phases_seen[-1] if phases_seen else "0. Initialization")

        best_error_messages = (
            active_phase_error_msgs[-3:]
            or active_phase_all_msgs[-3:]
            or batch_error_msgs[-2:]
            or init_error_msgs[-2:]
            or all_app_msgs[-3:]
        )
        if not best_error_messages:
            best_error_messages = [self.internal_nodes[primary_idx].metadata.get("clean_message", "")]

        primary_err_code = all_errors[0].upper() if all_errors else (
            f"ExitCode {extracted_exit_code}" if extracted_exit_code else "None (0)"
        )

        return {
            "app_name": extracted_app_name or "Not explicitly named in log snippet",
            "command_line": extracted_cmd or "Not logged in captured chunk (check policy encryption / pre-execution fail)",
            "install_context": extracted_context or "SYSTEM / Default IME Service Context",
            "lifecycle_trail": " -> ".join(phases_seen) if phases_seen else failing_phase,
            "failing_phase": failing_phase,
            "error_code": primary_err_code,
            "error_messages": best_error_messages,
            "evtx_findings": evtx_summaries[:2] if evtx_summaries else ["No matching .evtx file uploaded (diagnosed directly from IME log telemetry)."]
        }

    def search_with_metadata(self, query: str, exact_match_keyword: str = None, top_k: int = 1) -> Dict:
        top_ids = []

        if exact_match_keyword:
            search_str = exact_match_keyword.lower().strip()
            single_app_err = []
            single_app_norm = []
            batch_app_err = []
            batch_app_norm = []

            for idx in range(len(self.internal_nodes) - 1, -1, -1):
                node = self.internal_nodes[idx]
                m = node.metadata
                if search_str in m.get("app_ids", []) or search_str in m.get("explicit_guids", []):
                    has_err = bool(m.get("error_codes")) or m.get("is_error", False)
                    is_batch = m.get("is_batch_payload", False)
                    if has_err and not is_batch:
                        single_app_err.append(idx)
                    elif not has_err and not is_batch:
                        single_app_norm.append(idx)
                    elif has_err and is_batch:
                        batch_app_err.append(idx)
                    else:
                        batch_app_norm.append(idx)

            top_ids = (single_app_err + single_app_norm + batch_app_err + batch_app_norm)[:top_k]

        if not top_ids and not exact_match_keyword and self.bm25:
            enriched_query = f"{query} installerror error failed exitcode 0x80244022 0x87d30065 1603 1008"
            clean_query = re.sub(r'[^a-z0-9]', ' ', enriched_query.lower())
            bm25_scores = self.bm25.get_scores(clean_query.split())

            adjusted_scores = []
            for idx, score in enumerate(bm25_scores):
                node = self.internal_nodes[idx]
                m = node.metadata
                if m.get("is_global_noise", False):
                    adjusted_scores.append(-999.0)
                    continue
                node_apps = m.get("app_ids", [])
                if node_apps and all(not _is_valid_app_id(aid) for aid in node_apps):
                    adjusted_scores.append(-999.0)
                    continue

                bonus = 0.0
                if m.get("error_codes"):
                    bonus += 18.0
                if m.get("app_ids"):
                    bonus += 10.0
                if not m.get("is_batch_payload", False):
                    bonus += 12.0
                if m.get("phase") not in ("0. Initialization", "6. Reporting"):
                    bonus += 8.0
                adjusted_scores.append(score + bonus)

            top_ids = [int(idx) for idx in np.argsort(adjusted_scores)[::-1][:top_k] if adjusted_scores[idx] > -100]

        if not top_ids:
            return {"evidence": "No matching device logs found."}

        primary_idx = top_ids[0]
        primary_node = self.internal_nodes[primary_idx]
        primary_ts = primary_node.metadata.get("timestamp", "Unknown")

        if exact_match_keyword and _is_valid_app_id(exact_match_keyword):
            primary_app_id = exact_match_keyword.lower().strip()
        else:
            found_app_ids = [aid for aid in primary_node.metadata.get("app_ids", []) if _is_valid_app_id(aid)]
            primary_app_id = found_app_ids[0] if found_app_ids else "Not found in chunk"

        source_file = primary_node.metadata.get("file_name", "IntuneManagementExtension.log")
        dossier = self._build_app_dossier(primary_app_id, primary_idx)

        decoded_err = decode_contextual_intune_error(
            error_code=dossier["error_code"],
            phase=dossier["failing_phase"],
            log_lines_text="\n".join(dossier["error_messages"]),
            lifecycle_trail=dossier["lifecycle_trail"]
        )

        app_specific_evidence = [
            node.text for node in self.internal_nodes
            if primary_app_id in node.metadata.get("app_ids", []) and not node.metadata.get("is_batch_payload", False)
        ][-4:]

        if not app_specific_evidence:
            app_specific_evidence = [
                node.text for node in self.internal_nodes
                if primary_app_id in node.metadata.get("app_ids", [])
            ][-4:] or [primary_node.text]

        return {
            "evidence": "\n".join(app_specific_evidence),
            "error_code": dossier["error_code"],
            "decoded_error": decoded_err,
            "phase": dossier["failing_phase"],
            "lifecycle_trail": dossier["lifecycle_trail"],
            "app_name": dossier["app_name"],
            "command_line": dossier["command_line"],
            "install_context": dossier["install_context"],
            "error_messages": dossier["error_messages"],
            "evtx_findings": dossier["evtx_findings"],
            "timestamp": primary_ts,
            "app_id": primary_app_id,
            "source_file": source_file
        }


# ==============================================================================
# KNOWLEDGE LAYER: ACTIONABLE RUNBOOK RETRIEVAL
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
                    if len(cleaned) > 25:
                        self.paragraphs.append(cleaned)

        if self.paragraphs:
            corpus = [re.sub(r'[^a-z0-9]', ' ', p.lower()).split() for p in self.paragraphs]
            self.bm25 = BM25Okapi(corpus)

    def get_actionable_runbook_guidance(self, query: str, error_code: str, phase: str, error_messages: List[str]) -> str:
        if not self.bm25 or not self.paragraphs:
            return ""
        err_text = " ".join(error_messages)
        combined_query = re.sub(
            r'[^a-z0-9]', ' ',
            f"{error_code} {phase} {err_text} remediation fix resolution".lower()
        ).split()
        scores = self.bm25.get_scores(combined_query)

        adjusted = []
        for idx, s in enumerate(scores):
            p_low = self.paragraphs[idx].lower()
            bonus = 0.0
            if "18-step deployment lifecycle" in p_low or "start to present application" in p_low:
                bonus -= 20.0
            if error_code.lower() in p_low and error_code.lower() not in ("see log", "none (0)"):
                bonus += 25.0
            if any(w in p_low for w in ["remediation", "fix", "verify", "check", "solution", "cause", "error"]):
                bonus += 5.0
            adjusted.append(s + bonus)

        best_idx = int(np.argmax(adjusted))
        if adjusted[best_idx] > 0:
            return re.sub(r'[\r\n]+', ' ', self.paragraphs[best_idx]).strip()[:400]
        return ""


# ==============================================================================
# ORCHESTRATOR
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
            n_ctx=1536,
            n_threads=optimal_threads,
            n_threads_batch=optimal_threads,
            n_batch=256,
            use_mmap=True,
            use_mlock=False,
            verbose=False
        )

        self.prefix_cache = LlamaRAMCache(capacity_bytes=128 * 1024 * 1024)
        self.llm.set_cache(self.prefix_cache)

        self.static_system_prompt = (
            "You are a Senior Microsoft Intune Escalation Engineer. "
            "Analyze the Exact App Log Lines and Contextual Intune Diagnosis below. "
            "NEVER repeat generic phrases like 'failed due to a system error where it could not find the specified file'. "
            "Instead, explicitly cite the exact component, method/exception, and lifecycle phase from the log lines:\n"
            "• Exact Technical Root Cause: (Cite the exact log action/exception, phase transition, and why it failed)\n"
            "• Intune Admin & Endpoint Fix: (Give 3 concrete Intune Portal / PowerShell / packaging steps to fix it)"
        )

    def prepare_turn(self, query: str) -> Dict:
        q_lower = query.lower()
        list_keywords = ["all application id", "all app id", "list app", "fetch all", "which apps", "mentioned in the log"]

        if any(kw in q_lower for kw in list_keywords):
            apps = self.retrieval.get_all_unique_app_ids()
            if not apps:
                text = "No standard Intune Application GUIDs were detected in the loaded logs."
            else:
                lines = [f"Found {len(apps)} unique Application ID(s) across the ingested logs:\n"]
                for idx, item in enumerate(apps, 1):
                    lines.append(
                        f"{idx}. App ID: {item['app_id']}\n"
                        f"   • Status: {item['status']} (Error: {item['error_code'].upper()}) | "
                        f"Phase: {item['last_phase']} | Last Seen: {item['last_seen']}"
                    )
                text = "\n".join(lines)
            return {
                "mode": "instant",
                "response": text,
                "evidence": "\n".join([f"{a['app_id']} ({a['status']} - {a['error_code']})" for a in apps]),
                "status_tag": f"Status: {len(apps)} Apps Found",
                "phase_tag": "Tags: App Inventory"
            }

        app_id_pattern = re.compile(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)
        match = app_id_pattern.search(query)
        explicit_query_guid = match.group(1).lower() if (match and _is_valid_app_id(match.group(1))) else None
        target_app_id = explicit_query_guid if explicit_query_guid else self.last_target_app_id

        hit = self.retrieval.search_with_metadata(query, exact_match_keyword=target_app_id, top_k=1)
        if hit["evidence"] == "No matching device logs found." or not _is_valid_app_id(hit.get("app_id", "")):
            missing_msg = (
                f"App ID `{explicit_query_guid}` was not found in the currently loaded log files."
                if explicit_query_guid
                else "Could not find matching valid Win32 application error entries in the uploaded logs. Try specifying a valid App ID."
            )
            return {
                "mode": "instant",
                "response": missing_msg,
                "evidence": "",
                "status_tag": "Status: App Not Found",
                "phase_tag": "Phase: N/A"
            }

        if _is_valid_app_id(hit.get("app_id")):
            self.last_target_app_id = hit["app_id"]

        runbook_rule = self.knowledge.get_actionable_runbook_guidance(
            query=query,
            error_code=hit["error_code"],
            phase=hit["phase"],
            error_messages=hit["error_messages"]
        )

        evtx_line = " | ".join(hit["evtx_findings"])
        failing_line_preview = hit["error_messages"][-1] if hit["error_messages"] else "N/A"

        instant_header = (
            f"Target App ID: {hit['app_id']}  |  App Name: {hit['app_name']}  |  Source: {hit['source_file']}\n"
            f"Detected Error: {hit['error_code']}  |  Failing Phase: {hit['phase']}  |  Timestamp: {hit['timestamp']}\n"
            f"Contextual Intune Diagnosis: {hit['decoded_error']}\n"
            f"Auto-Extracted Telemetry:\n"
            f"  • Lifecycle Path Reached: {hit['lifecycle_trail']}\n"
            f"  • Install Context & Cmd: {hit['install_context']} | Cmd: {hit['command_line'][:110]}\n"
            f"  • Correlated Event Viewer (.evtx): {evtx_line}\n"
            f"  • Exact App Log Line: {failing_line_preview[:380]}\n"
            f"{'-'*75}\n"
        )

        footer_block = (
            f"\n{build_ime_force_retry_commands(hit['app_id'])}\n"
            f"{'-'*75}\n"
            f"✔ Auto-Correlated from {hit['source_file']} + Contextual Intune Phase Analyzer"
        )

        return {
            "mode": "stream",
            "instant_header": instant_header,
            "footer_block": footer_block,
            "evidence": hit["evidence"],
            "decoded_error": hit["decoded_error"],
            "lifecycle_trail": hit["lifecycle_trail"],
            "error_messages": "\n".join(hit["error_messages"]),
            "evtx_findings": evtx_line,
            "install_context": hit["install_context"],
            "command_line": hit["command_line"],
            "runbook_rule": runbook_rule,
            "app_id": hit["app_id"],
            "error_code": hit["error_code"],
            "status_tag": f"Error: {hit['error_code']}",
            "phase_tag": f"Phase: {hit['phase']}",
            "query": query
        }

    def stream_llm_explanation(self, prepared: Dict) -> Iterator[str]:
        rb_context = f"\nRunbook Guidance: {prepared['runbook_rule']}" if prepared["runbook_rule"] else ""
        messages = [
            {"role": "system", "content": self.static_system_prompt},
            {
                "role": "user",
                "content": (
                    f"Exact App Log Lines for {prepared['app_id']}:\n{prepared['error_messages'][:850]}\n\n"
                    f"Lifecycle Progression: {prepared['lifecycle_trail']}\n"
                    f"Install Context: {prepared['install_context']} | Command: {prepared['command_line']}\n"
                    f"Contextual Intune Diagnosis ({prepared['error_code']}): {prepared['decoded_error']}"
                    f"{rb_context}\n\n"
                    f"User Question: {prepared['query']}"
                )
            }
        ]

        stream = self.llm.create_chat_completion(
            messages=messages,
            temperature=0.1,
            top_p=0.9,
            repeat_penalty=1.18,
            max_tokens=200,
            stream=True
        )

        for chunk in stream:
            delta = chunk["choices"][0].get("delta", {})
            token = delta.get("content", "")
            if token:
                yield token

        yield prepared["footer_block"]

    def close(self):
        pass