# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

block_cipher = None

# Collect native C++ DLLs for llama_cpp and UI theme assets for customtkinter
llama_cpp_binaries = collect_dynamic_libs('llama_cpp')
ctk_datas = collect_data_files('customtkinter')
fastembed_datas = collect_data_files('fastembed')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=llama_cpp_binaries,
    datas=[
        ('models/qwen2.5-coder-3b-instruct-q4_k_m.gguf', 'models'),
    ] + ctk_datas + fastembed_datas,
    hiddenimports=[
        'customtkinter',
        'PIL',
        'llama_cpp',
        'rank_bm25',
        'langgraph',
        'qdrant_client',
        'fastembed',
        'llama_index.core',
        'llama_index.embeddings.fastembed',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['streamlit', 'matplotlib', 'notebook'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IntuneRAGAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # Keep False so DLLs and GGUF weights aren't corrupted
    console=False,      # Hides the black command prompt window!
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='IntuneRAGAgent',
)