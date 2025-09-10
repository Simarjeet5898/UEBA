# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import (
    collect_submodules,
    collect_data_files,
    collect_dynamic_libs,
)

# ----- paths -----
HERE = Path.cwd()                    # current working dir: kafka_consumer
ROOT = HERE.parent                  # .../UEBA_BACKEND
KC   = ROOT / "kafka_consumer"
AI   = ROOT / "ai_models"

pathex = [str(ROOT), str(KC)]

# ----- datas -----
datas = []
# ship registry if present
if (KC / "client_registry.json").exists():
    datas.append((str(KC / "client_registry.json"), "."))

# bundle entire ai_models tree preserving ROOT-relative layout (so loaders using BASE_DIR work)
if AI.exists():
    for p in AI.rglob("*"):
        if p.is_file():
            datas.append((str(p), str(p.relative_to(ROOT))))

# ----- hidden imports (app modules only; add ML stacks below) -----
hiddenimports = [
    "kafka_consumer.udp_dispatcher",
    "kafka_consumer.application_usage_consumer_udp",
    "kafka_consumer.authentication_monitoring_consumer_udp",
    "kafka_consumer.process_monitoring_consumer_udp",
    "kafka_consumer.SRU_consumer_udp",
    "kafka_consumer.login_events_consumer_udp",
    "kafka_consumer.connected_entities_consumer_udp",
    "kafka_consumer.file_sys_monitoring_consumer_udp",
    "kafka_consumer.helper",
    "kafka_consumer.SIEM_connector",
    "kafka_consumer.SOAR_connector",
    "kafka_consumer.config_consumer",
    "api_server",
    "db_connector",
    "rabbit_mq.send",
    "structures.structures",
]

# ---- bundle ML stacks (modules, data files, .so) ----
ML_MODULES = ["sklearn", "numpy", "pandas", "tensorflow", "keras"]
ml_hidden = []
ml_datas = []
ml_bins = []
for mod in ML_MODULES:
    ml_hidden += collect_submodules(mod)
    ml_datas  += collect_data_files(mod, include_py_files=False)
    ml_bins   += collect_dynamic_libs(mod)

hiddenimports = hiddenimports + ml_hidden
datas = datas + ml_datas
binaries = ml_bins

block_cipher = None

a = Analysis(
    ["consumer_main.py"],     # spec file lives in kafka_consumer/
    pathex=pathex,
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    a.zipfiles,
    a.datas,
    name="ueba_server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,   # keep console to see logs/errors
)
