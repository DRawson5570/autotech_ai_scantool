# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for ELM327 Gateway App - Single File Build.

Build with:
    pip install pyinstaller
    python -m PyInstaller gateway_app.spec --noconfirm

Output: dist/ELM327_Gateway.exe (single file!)
"""

block_cipher = None

a = Analysis(
    ['elm327_gateway/app.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'aiohttp',
        'serial',
        'serial.tools',
        'serial.tools.list_ports',
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'pystray',
        'PIL',
        'pydantic',
        # Our modules
        'elm327_gateway.service',
        'elm327_gateway.connection',
        'elm327_gateway.protocol',
        'elm327_gateway.pids',
        'elm327_gateway.bidirectional',
        'elm327_gateway.session',
        'elm327_gateway.server',
        'elm327_gateway.autodetect',
        'elm327_gateway.reverse_tunnel',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'tkinter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ELM327_Gateway',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # Console visible for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
