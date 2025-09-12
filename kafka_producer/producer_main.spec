# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['producer_main.py'],
    pathex=[
    '/work/kafka_producer',
    '/work',
    ],
    binaries=[],
    datas=[],
    hiddenimports=[
        'kafka_producer.connected_entities_producer_udp',
        'kafka_producer.file_sys_monitoring_producer_udp',
        'kafka_producer.login_events_producer_udp',
        'kafka_producer.system_monitor_producer_udp',
        "kafka_producer.new_log_monitor"
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ueba_client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)