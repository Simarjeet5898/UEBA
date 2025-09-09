# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files
import os

# ---------- helpers ----------
def optional_collect_submodules(pkg):
    try:
        return collect_submodules(pkg)
    except Exception:
        return []

def optional_collect_data(pkg):
    try:
        return collect_data_files(pkg)
    except Exception:
        return []

# ---------- paths ----------
BASE_DIR = Path(os.getcwd()).resolve()
AI_DIR   = (BASE_DIR / 'ai_models').resolve()

# ---------- hiddenimports ----------
hiddenimports = [
    # your app modules
    'kafka_consumer.udp_dispatcher',
    'kafka_consumer.application_usage_consumer_udp',
    'kafka_consumer.authentication_monitoring_consumer_udp',
    'kafka_consumer.process_monitoring_consumer_udp',
    'kafka_consumer.SRU_consumer_udp',
    'kafka_consumer.login_events_consumer_udp',
    'kafka_consumer.connected_entities_consumer_udp',
    'kafka_consumer.file_sys_monitoring_consumer_udp',
    'kafka_consumer.helper',
    'kafka_consumer.SIEM_connector',
    'kafka_consumer.SOAR_connector',
    'kafka_consumer.config_consumer',
    'api_server',
    'db_connector',
    'rabbit_mq.send',
    'structures.structures',
]

# Only collect what truly needs it. Let PyInstaller hooks handle pandas/sklearn/tensorflow/keras.
hiddenimports += optional_collect_submodules('numpy')
hiddenimports += optional_collect_submodules('joblib')

# ---------- data files ----------
datas  = []
datas += optional_collect_data('numpy')
datas += optional_collect_data('pandas')
datas += optional_collect_data('sklearn')

# bundle entire ai_models tree
if AI_DIR.exists():
    datas += [
        (str(p), str(p.relative_to(BASE_DIR)))
        for p in AI_DIR.rglob('*') if p.is_file()
    ]

# ---------- analysis ----------
a = Analysis(
    ['kafka_consumer/consumer_main.py'],
    pathex=[
        str(BASE_DIR / 'kafka_consumer'),
        str(BASE_DIR),
    ],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],          # rely on built-in + hooks-contrib if installed
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # trim size / silence missing-test noise
        'matplotlib','seaborn',
        'torch','torchvision','torchaudio',
        'ipykernel','jupyter','notebook',
        'xgboost','numba',
        'pandas.tests',
        'sklearn.tests',
        # keras/tensorflow internals & legacy probes that aren't needed at runtime
        'keras.src.backend.torch',
        'tensorflow.__internal__',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ueba_server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)
