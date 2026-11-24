# Intune Win32 & Store Log Troubleshooting Agent (Local Hybrid RAG + Deterministic Dossier Engine)

An offline, low-memory AI troubleshooting engine built for **Microsoft Intune Win32 and Store/WinGet application failures**. Engineered specifically to run within a strict **16 GB system RAM** (and CPU-only corporate endpoints) using a quantized 3B parameter LLM (`qwen2.5-coder-3b-instruct-q4_k_m.gguf`), deterministic log indexing, hybrid runbook retrieval, and an automated multi-tier evaluation harness.

---

## 1. What Problem This Solves

In enterprise Microsoft Intune environments, diagnosing why a Win32 or Store app failed requires correlating fragmented, multi-megabyte CMTrace logs (`AppWorkload.log`, `IntuneManagementExtension.log`, `AgentExecutor.log`) and Windows Event Viewer (`.evtx`) records across an **18-step deployment lifecycle**.

* **Privacy & Compliance Blocker:** Enterprise device logs contain internal hostnames, user contexts, internal UNC paths, and proprietary app configurations—making public cloud LLMs unusable without strict data-redaction pipelines.
* **Signal-to-Noise Ratio:** Raw IME logs are flooded with background daemon chatter (`GRSManager`, `ReevaluationScheduleManager`), multi-app JSON payloads (`Get policies`, `RequestPayload`), and benign warnings (e.g., `LogonUser` error `1008` during `PopToastNotification` in Session 0) that mislead both junior admins and naive RAG pipelines.
* **Hardware Constraints:** Standard corporate admin laptops and local workstations typically have 16 GB RAM and limited or zero discrete GPU VRAM, ruling out large 7B–70B models or heavy vector database servers.

This system ingests raw `.log` and `.evtx` files in memory, isolates per-app execution timelines in $O(1)$ lookup time, retrieves relevant troubleshooting guidance from an embedded Intune runbook via hybrid search, and generates grounded, non-hallucinated root cause explanations locally.

---

## 2. Architectural Evolution: From Naive Log RAG to Hybrid Grounding

Building a reliable diagnostic engine on a 3B model required three major architectural pivots as real-world failure modes emerged:

### Stage 1: Naive Chunk-and-Embed Prototype (Failed)

* **Initial Approach:** Split `.log` files into text chunks, embed them into a vector index, and ask a local LLM *"Why did the app fail?"*
* **Why It Failed:**
  1. **Vector similarity blurs exact identifiers:** To an embedding model, `0x80244022` and `0x80244023` sit nearly adjacent in vector space despite representing completely different Windows errors.
  2. **Loss of chronological state:** Top-$k$ semantic retrieval pulled isolated warning lines (like benign `1008` toast popups) while missing downstream `ResultantAppState: 1` / `EnforcementState: 1000` success records, causing the 3B model to hallucinate failures on healthy apps.
  3. **Cross-app error bleeding:** Multi-app JSON policy payloads caused error codes from App A to bleed into App B's context window.

### Stage 2: $O(1)$ Deterministic App Dossiers + 18-Step Lifecycle Mapping

* **The Pivot:** Removed vector embeddings from the log layer entirely. Built `IngestionAgent` and `RetrievalEngine` to parse logs in RAM into structured, per-GUID **App Dossiers**.
* **Key Engineering Decisions:**
  * **Noise & Toast Filtering:** Strips `GRSManager`, `ReevaluationScheduleManager`, and `PopToastNotification` `1008` noise at ingestion.
  * **Multi-App JSON Slicing:** Splits batch `Get policies` and `ReportingManager` payloads around each individual GUID so error codes never cross-contaminate.
  * **ESP Queue vs. Failure Separation:** Distinguishes apps genuinely failing execution from apps paused in Autopilot/ESP (`DeviceSetup`) after `[Simulated]` pre-checks.
  * **Strict Context Budgeting (`n_ctx=2048`):** Pre-compiles each app's exact command line, install context (`SYSTEM` vs. `User`), detection rule, stopping step, and decoded Windows OS/HRESULT description (`ctypes.FormatError`) into a compact dossier that fits comfortably inside a 2048-token context window.

### Stage 3: Hybrid Runbook RAG (BM25 + CPU Vector RRF) + Evaluation Harness

* **The Pivot:** While deterministic rules handled known Win32 failure patterns, unfamiliar errors required semantic runbook lookup—and ongoing parser changes risked silent regressions.
* **Key Engineering Decisions:**
  * **Asymmetric Hybrid Retrieval (`KnowledgeAgent`):** Kept logs deterministic while upgrading runbook search to **Reciprocal Rank Fusion (RRF)** combining **BM25** (exact error codes like `0x87D1041C`, `1603`, `1618`) with **CPU-offloaded `FastEmbed` (`BAAI/bge-small-en-v1.5`)** cosine similarity—leaving rest of the RAM free for Qwen 2.5 3B.
  * **3-Tier Automated Evaluation Harness (`eval_harness.py`):** Added regression testing (`golden_cases.json`), live UI edge-case capture (`Flag Case` $\rightarrow$ `review_queue/` $\rightarrow$ `--promote`), and per-turn latency telemetry (`telemetry/perf.jsonl`).

---

## 3. System Pipeline

```text
  [.log / .evtx Files]
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. IngestionAgent (In-Memory RAM Parser)                    │
│  • Filters GRSManager, ReevaluationSchedule & Toast 1008    │
│  • Splits multi-app JSON payloads per GUID                  │
│  • Maps entries to the 18-Step Win32 Lifecycle              │
└──────────┬──────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. RetrievalEngine (O(1) Pre-Indexed App Dossiers)          │
│  • Groups nodes by GUID -> builds deterministic state sheet │
│  • Classifies: Installed | ESP Queued | Evaluated | Failed  │
│  • Extracts Cmd, Context, Detection Rule & OS Error Meaning │
└──────────┬──────────────────────────────────────────────────┘
           │
           ├──────────────────────────────┐
           ▼                              ▼
┌───────────────────────────┐  ┌──────────────────────────────┐
│ 3a. Instant Routing       │  │ 3b. KnowledgeAgent (Hybrid)  │
│  • Full App Inventory     │  │  • BM25 + bge-small-en-v1.5  │
│  • Missing GUID Guardrail │  │  • CPU ONNX + RRF Fusion     │
└───────────────────────────┘  └──────────┬───────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. LangGraphOrchestrator + Qwen 2.5 Coder 3B (GGUF)         │
│  • Streams grounded Analysis Summary (n_ctx=2048, temp=0.0) │
│  • Supports multi-turn follow-up Q&A on active App GUID     │
│  • Logs ingest/index/TTFT metrics to telemetry/perf.jsonl   │
└─────────────────────────────────────────────────────────────┘

## Application Demo

[[▶ Watch SOUP - Intune Win32 Troubleshooter Demo](./Demo2.mp4)](https://github.com/git-anish3008/IntuneRAGApp01/blob/main/Demo2.mp4)
