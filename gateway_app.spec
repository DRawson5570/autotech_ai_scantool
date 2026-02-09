# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for ELM327 Gateway App.

Build with:
    pip install pyinstaller
    pyinstaller gateway_app.spec --noconfirm

Output: dist/ELM327_Gateway/ELM327_Gateway.exe
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
    [],
    exclude_binaries=True,
    name='ELM327_Gateway',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # No console window (tray app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # TODO: add car icon
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ELM327_Gateway',
)
