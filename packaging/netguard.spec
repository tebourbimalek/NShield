# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for NetGuard (Windows, one-dir build).

Build from the repo root:
    pip install pyinstaller
    pyinstaller packaging/netguard.spec

The resulting folder is `dist/NetGuard/`. Ship it zipped, or feed it to
Inno Setup (packaging/installer.iss) to produce a one-click installer.
"""

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "backend", "main.py")],
    pathex=[os.path.join(ROOT, "backend")],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "frontend", "dist"), os.path.join("frontend", "dist")),
        (os.path.join(ROOT, "backend", "config.example.yaml"), "backend"),
    ],
    hiddenimports=[
        "scapy.all",
        "scapy.layers.inet",
        "scapy.layers.inet6",
        "scapy.layers.l2",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
    ] + collect_submodules("scapy"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name="NetGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # windowless: no console ever
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "frontend", "public", "favicon.ico")
        if os.path.exists(os.path.join(ROOT, "frontend", "public", "favicon.ico"))
        else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="NetGuard",
)
