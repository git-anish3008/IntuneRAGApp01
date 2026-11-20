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


def _is_valid_app_id(app_id: str) -> bool:
    """Filters out null GUIDs (00000000-0000-0000-0000-000000000000) and placeholders."""
    if not app_id:
        return False
    clean = app_id.replace("-", "").lower()
    return clean != "00000000000000000000000000000000" and len(clean) == 32


def decimal_to_hex_error(decimal_str: str) -> str:
    try:
        val = int(decimal_str)
        if val < 0:
            return f"0x{(val & 0xFFFFFFFF):08X}"
        return str(val)
    except Exception:
        return decimal_str


def decode_os_error_description(error_code: str) -> str:
    code_clean = error_code.strip().lower()
    if code_clean in ("n/a", "see log", "none", "0", "0x0", "0x00000000", ""):
        return "No Fatal Error Code Logged (Exit Code 0 / Success or Pending Evaluation)"

    intune_specific = {
        "1008": (
            "ERROR_NO_TOKEN (Win32 Error 1008: 'An attempt was made to reference a token that does not exist'). "
            "In Intune Win32 / AppWorkload.log, this happens when an installer or script running in SYSTEM context "
            "(Session 0) attempts to query an interactive user token, HKCU registry hive, or WTSQueryUserToken when no user token is bound."
        ),
        "0x80244022": (
            "WU_E_PT_HTTP_STATUS_SERVICE_UNAVAILABLE (0x80244022 / -2145107934). "
            "WinGetAppExecutionExecutor failed because the Microsoft Store / WinGet CDN returned HTTP 503 or corporate SSL inspection blocked SYSTEM-context WinGet traffic."
        ),
        "0x87d30065": "Intune Win32 Content Download / Network Staging Failure (0x87D30065) from Azure CDN / Delivery Optimization.",
        "0x87d30067": "Intune Win32 SHA256 Content Hash Verification Mismatch (0x87D30067) during Phase 4 (Decryption).",
        "0x87d1041c": "Intune Win32 Post-Install Detection Rule Failed (0x87D1041C): Installer returned 0, but DetectionManager did not detect the app afterwards.",
        "0x87d30000": "Intune Win32 Applicability / Requirement Rule Not Met (0x87D30000).",
        "1603": "ERROR_INSTALL_FAILURE (MSI Exit Code 1603): Fatal error during installation rollback (check SYSTEM vs User context, pending reboot, or custom actions).",
        "1618": "ERROR_INSTALL_ALREADY_RUNNING (MSI Exit Code 1618): Another msiexec.exe installation is holding the _MSIExecute mutex.",
        "3010": "ERROR_SUCCESS_REBOOT_REQUIRED (Exit Code 3010): Installation succeeded, but a soft reboot is required to complete."
    }
    if code_clean in intune_specific:
        return intune_specific[code_clean]

    try:
        if code_clean.startswith("0x"):
            val = int(code_clean, 16)
            if (val & 0xFFFF0000) == 0x80070000:
                win32_code = val & 0xFFFF
                os_msg = ctypes.FormatError(win32_code).strip()
                if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                    return f"HRESULT {error_code.upper()} (Win32 Error {win32_code}): {os_msg}"
            signed_val = val - 0x100000000 if val >= 0x80000000 else val
            os_msg = ctypes.FormatError(signed_val).strip()
            if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                return f"Windows OS Error {error_code.upper()}: {os_msg}"
        else:
            val = int(code_clean)
            os_msg = ctypes.FormatError(val).strip()
            if os_msg and "unknown" not in os_msg.lower() and "<no description>" not in os_msg.lower():
                return f"Windows Win32 Error {val}: {os_msg}"
    except Exception:
        pass

    return f"Installer / Intune Return Code {error_code.upper()}"


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
        # Only match valid failure HRESULT/NTSTATUS hex codes (0x8... or 0xC...) with word boundaries
        self.hex_pattern = re.compile(r'\b(0x[8cC][0-9a-fA-F]{7})\b')
        self.dec_err_pattern = re.compile(
            r'(?:error\s*code|exit\s*code|lpexitcode|return\s*code|win32error|hresult|"ErrorCode")\s*["\'=:]+\s*(-?\d{1,10})',
            re.IGNORECASE
        )

    def _detect_phase(self, text: str) -> str:
        lower = text.lower()
        # Batch reporting payloads ("Sending results to service. session RequestPayload") belong to 6. Reporting
        if "sending results to service" in lower or "requestpayload" in lower:
            return "6. Reporting"
        if "get policies" in lower:
            return "0. Initialization"
        if any(kw in lower for kw in [
            "executionexecutor", "wingetappexecution", "agentexecutor", "executionmanager",
            "installing", "installerror", "lpexitcode", "createprocess", "command line", "enforcement"
        ]):
            return "5. Execution"
        if any(kw in lower for kw in ["decrypt", "unzip", "extract", "hash", "decryptionmanager"]):
            return "4. Decryption"
        if any(kw in lower for kw in ["download", "bits", "dojob", "cdn", "incoming", "staging", "contentmanager"]):
            return "3. Download"
        if any(kw in lower for kw in ["detect", "isdiscovered", "detectionmanager", "processdetectionrules"]):
            return "2. Detection"
        if any(kw in lower for kw in ["requirement", "applicability", "checkapplicability", "grs", "grsmanager"]):
            return "1. Applicability"
        if any(kw in lower for kw in ["report", "statusservice", "compliance", "reportingmanager"]):
            return "6. Reporting"
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

    def _slice_around_guid(self, text: str, guid: str, window: int = 450) -> str:
        """Slices long log lines directly around the target App ID so batch JSON lines never show the wrong app."""
        pos = text.lower().find(guid.lower())
        if pos == -1:
            return text[:window]
        start = max(0, pos - 90)
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

                # Preserve order of appearance of GUIDs
                ordered_guids = []
                for g in self.app_id_pattern.findall(normalized_msg):
                    g_low = g.lower()
                    if _is_valid_app_id(g_low) and g_low not in ordered_guids:
                        ordered_guids.append(g_low)

                # CASE 1: Multi-App Batch JSON Line (e.g. "Get policies" or "Sending results to service. session RequestPayload")
                # Split into isolated per-app nodes so error codes and App IDs never bleed across apps!
                if len(ordered_guids) > 1:
                    phase = self._detect_phase(normalized_msg)
                    for g_id in ordered_guids:
                        app_slice = self._slice_around_guid(normalized_msg, g_id, window=420)
                        slice_errors = self._extract_error_codes(app_slice)
                        slice_is_err = bool(slice_errors) or any(
                            kw in app_slice.lower() for kw in ['"installerror"', '"failed"', 'errorcode":-', 'type="3"']
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

                # CASE 2: Standard Single-App Log Line
                if ordered_guids:
                    last_seen_guid = ordered_guids[0]

                is_aad_noise = "aad user check" in normalized_msg.lower() or "graph audience" in normalized_msg.lower()
                effective_guids = list(ordered_guids)
                if not effective_guids and last_seen_guid and _is_valid_app_id(last_seen_guid) and not is_aad_noise:
                    effective_guids = [last_seen_guid]

                err_codes = self._extract_error_codes(normalized_msg)
                is_error_chunk = (
                    severity == "Error"
                    or bool(err_codes)
                    or any(kw in normalized_msg.lower() for kw in ["installerror", "error", "failed", "exception"])
                ) and not is_aad_noise

                phase = self._detect_phase(normalized_msg)
                msg_window = (
                    self._slice_around_guid(normalized_msg, effective_guids[0], 550)
                    if effective_guids else normalized_msg[:550]
                )

                clean_json_obj = {
                    "source": file_name,
                    "component": component,
                    "severity": severity,
                    "phase": phase,
                    "timestamp": timestamp,
                    "app_id": effective_guids[0] if effective_guids else "N/A",
                    "error_codes": err_codes,
                    "log_message": msg_window
                }

                nodes.append(Document(
                    text=json.dumps(clean_json_obj, indent=2),
                    metadata={
                        "file_name": file_name,
                        "source_type": "log",
                        "is_batch_payload": False,
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
        all_errors = []
        single_app_error_msgs = []
        batch_error_msgs = []
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

                if not extracted_context:
                    if re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bUser\b|"InstallContext":\s*1', msg, re.IGNORECASE):
                        extracted_context = "User Context"
                    elif re.search(r'\b(?:RunAs|InstallContext|Context)\b.*?\bSystem\b|"InstallContext":\s*2', msg, re.IGNORECASE):
                        extracted_context = "SYSTEM Context (Session 0)"

                if m.get("is_error") or m.get("error_codes"):
                    if m.get("is_batch_payload"):
                        batch_error_msgs.append(formatted_line)
                    else:
                        single_app_error_msgs.append(formatted_line)

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

        # Prefer dedicated single-app error lines over batch payload slices, or fallback to the last seen log line for that app
        best_error_messages = single_app_error_msgs[-3:] or batch_error_msgs[-2:] or all_app_msgs[-2:]
        if not best_error_messages:
            best_error_messages = [self.internal_nodes[primary_idx].metadata.get("clean_message", "")]

        return {
            "app_name": extracted_app_name or "Not explicitly named in log snippet",
            "command_line": extracted_cmd or "Not logged in captured chunk (check policy encryption / pre-execution fail)",
            "install_context": extracted_context or "SYSTEM / Default IME Service Context",
            "lifecycle_trail": " -> ".join(phases_seen) if phases_seen else failing_phase,
            "failing_phase": failing_phase,
            "error_code": all_errors[0].upper() if all_errors else "None (0)",
            "error_messages": best_error_messages,
            "evtx_findings": evtx_summaries[:2] if evtx_summaries else ["No matching .evtx file uploaded (diagnosed directly from IME log telemetry)."]
        }

    def search_with_metadata(self, query: str, exact_match_keyword: str = None, top_k: int = 1) -> Dict:
        top_ids = []

        # 1. Exact App ID search: Prioritize dedicated single-app error lines over batch reporting lines!
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

            top_ids = (single_app_err + batch_app_err + single_app_norm + batch_app_norm)[:top_k]

        # 2. General query search (when no specific App ID was provided)
        if not top_ids and not exact_match_keyword and self.bm25:
            enriched_query = f"{query} installerror error failed exitcode 0x80244022 0x87d30065 1603 1008"
            clean_query = re.sub(r'[^a-z0-9]', ' ', enriched_query.lower())
            bm25_scores = self.bm25.get_scores(clean_query.split())

            adjusted_scores = []
            for idx, score in enumerate(bm25_scores):
                node = self.internal_nodes[idx]
                m = node.metadata
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
                    bonus += 12.0  # Strongly prefer dedicated single-app execution logs over batch JSON arrays
                if m.get("phase") not in ("0. Initialization", "6. Reporting"):
                    bonus += 8.0
                if "aad user check" in node.text.lower():
                    bonus -= 30.0
                adjusted_scores.append(score + bonus)

            top_ids = [int(idx) for idx in np.argsort(adjusted_scores)[::-1][:top_k] if adjusted_scores[idx] > -100]

        if not top_ids:
            return {"evidence": "No matching device logs found."}

        primary_idx = top_ids[0]
        primary_node = self.internal_nodes[primary_idx]
        primary_ts = primary_node.metadata.get("timestamp", "Unknown")

        # CRITICAL FIX: If the user asked for a specific App ID, NEVER overwrite it with another GUID!
        if exact_match_keyword and _is_valid_app_id(exact_match_keyword):
            primary_app_id = exact_match_keyword.lower().strip()
        else:
            found_app_ids = [aid for aid in primary_node.metadata.get("app_ids", []) if _is_valid_app_id(aid)]
            primary_app_id = found_app_ids[0] if found_app_ids else "Not found in chunk"

        source_file = primary_node.metadata.get("file_name", "AppWorkload.log")
        dossier = self._build_app_dossier(primary_app_id, primary_idx)

        # Collect only evidence chunks that actually belong to primary_app_id
        app_specific_evidence = [
            node.text for node in self.internal_nodes
            if primary_app_id in node.metadata.get("app_ids", [])
        ][-4:]

        if not app_specific_evidence:
            app_specific_evidence = [primary_node.text]

        return {
            "evidence": "\n".join(app_specific_evidence),
            "error_code": dossier["error_code"],
            "decoded_error": decode_os_error_description(dossier["error_code"]),
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
            "You have ALREADY read the logs and Event Viewer for the user—NEVER tell the user to check logs or Event Viewer. "
            "Using the Decoded OS Error, Failing Log Lines, and Runbook, write:\n"
            "• Exact Root Cause: (Explain specifically why the target App ID failed or succeeded based on the log lines)\n"
            "• Intune Admin & Endpoint Fix: (Give 3 specific, actionable configuration or command fixes)"
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
            f"OS / Intune Error Definition: {hit['decoded_error']}\n"
            f"Auto-Extracted Telemetry:\n"
            f"  • Lifecycle Path Reached: {hit['lifecycle_trail']}\n"
            f"  • Install Context & Cmd: {hit['install_context']} | Cmd: {hit['command_line'][:90]}\n"
            f"  • Correlated Event Viewer (.evtx): {evtx_line}\n"
            f"  • Exact App Log Line: {failing_line_preview[:200]}\n"
            f"{'-'*75}\n"
        )

        footer_block = (
            f"\n{build_ime_force_retry_commands(hit['app_id'])}\n"
            f"{'-'*75}\n"
            f"✔ Auto-Correlated from {hit['source_file']} + Windows OS Error Table"
        )

        return {
            "mode": "stream",
            "instant_header": instant_header,
            "footer_block": footer_block,
            "evidence": hit["evidence"],
            "decoded_error": hit["decoded_error"],
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
                    f"App ID: {prepared['app_id']} | Error Code: {prepared['error_code']}\n"
                    f"Decoded Error Meaning: {prepared['decoded_error']}\n"
                    f"Install Context: {prepared['install_context']} | Command: {prepared['command_line']}\n"
                    f"Correlated Event Viewer: {prepared['evtx_findings']}\n"
                    f"Failing Log Lines for {prepared['app_id']}:\n{prepared['error_messages'][:600]}"
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
            max_tokens=180,
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
