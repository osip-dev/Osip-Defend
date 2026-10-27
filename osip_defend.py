#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import codecs
import subprocess
import base64
import re
import fnmatch
import copy
import ctypes
import hashlib
import json
import os
import queue
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'
if IS_WINDOWS:
    import winreg

TEST_SAMPLES = {f'OSIP.Demo.{i:02d}': f'OSIP-DEFEND harmless test sample {i:02d}\n'.encode()
                for i in range(1, 9)}
SIGNATURES = {hashlib.sha256(data).hexdigest(): name for name, data in TEST_SAMPLES.items()}
GREEN, RED, MUTED = '#00ff41', '#ff5874', '#a1adbd'
MAX_LOGS = 2000

CWS_PROJECT = 'https://github.com/mrkaban/Open-CWS-Anti-virus'
DEFAULT_SETTINGS = {
    'default_folder': str(Path.home() / 'Downloads'), 'engine_mode': 'both',
    'recursive': True, 'heuristics': True, 'heuristic_days': 3, 'excludes': [],
    'monitor_roots': [], 'monitor_extensions': ['.exe', '.bat'], 'monitor_delay_ms': 800,
    'animations': True, 'font_size': 14, 'log_limit': 2000, 'av_timeout_minutes': 60,
    'cws_executable': '', 'cws_database': '', 'cws_sha256': '',
    'cws_archives': True, 'cws_max_file_mb': 100, 'cws_max_scan_mb': 400,
}


def validate_settings(data):
    if not isinstance(data, dict): raise ValueError('Настройки должны быть JSON-объектом')
    result = copy.deepcopy(DEFAULT_SETTINGS)
    for key, value in data.items():
        if key not in result: continue
        default = result[key]
        if isinstance(default, bool):
            if type(value) is not bool: raise ValueError(f'{key}: требуется логическое значение')
        elif isinstance(default, int):
            if type(value) is not int: raise ValueError(f'{key}: требуется целое число')
        elif isinstance(default, str):
            if not isinstance(value, str) or len(value) > 32768: raise ValueError(f'{key}: неверная строка')
        elif isinstance(default, list):
            if not isinstance(value, list) or len(value) > 200 or any(not isinstance(x, str) or len(x)>4096 for x in value):
                raise ValueError(f'{key}: неверный список')
        result[key] = copy.deepcopy(value)
    bounds = {'heuristic_days': (1, 365), 'monitor_delay_ms': (100, 10000), 'font_size': (12, 18),
              'log_limit': (100, 10000), 'av_timeout_minutes': (1, 1440),
              'cws_max_file_mb': (1, 2048), 'cws_max_scan_mb': (1, 4096)}
    for key, (low, high) in bounds.items():
        if not low <= result[key] <= high: raise ValueError(f'{key}: диапазон {low}–{high}')
    if result['engine_mode'] not in {'both','defender','cws'}: raise ValueError('Неизвестный режим движков')
    if result['cws_max_scan_mb'] < result['cws_max_file_mb']: raise ValueError('Лимит контейнера CWS не должен быть меньше лимита файла')
    ext = [x.strip().lower() for x in result['monitor_extensions'] if x.strip()]
    if not ext or any(not re.fullmatch(r'\.[a-z0-9]{1,12}', x) for x in ext):
        raise ValueError('Расширения: например .exe, .bat, .dll')
    result['monitor_extensions'] = list(dict.fromkeys(ext))
    pin = result['cws_sha256']
    if pin and not re.fullmatch('[0-9a-f]{64}', pin): raise ValueError('Неверный SHA-256 доверенного CWS')
    for key in ['monitor_roots', 'excludes']:
        result[key] = list(dict.fromkeys(x.strip() for x in result[key] if x.strip()))
    return result


class SettingsStore:
    def __init__(self, directory):
        self.path = Path(directory) / 'settings.json'
        self.error = ''

    def load(self):
        try:
            if not self.path.exists(): return copy.deepcopy(DEFAULT_SETTINGS)
            if self.path.stat().st_size > 1024 * 1024: raise ValueError('Настройки больше 1 МиБ')
            return validate_settings(json.loads(self.path.read_text(encoding='utf-8')))
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            return copy.deepcopy(DEFAULT_SETTINGS)

    def save(self, values):
        values = validate_settings(values)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=self.path.parent,
                                             prefix='settings-', suffix='.tmp', delete=False) as stream:
                temporary = stream.name
                json.dump(values, stream, ensure_ascii=False, indent=2)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary and os.path.exists(temporary): os.unlink(temporary)
        return values


def excluded_path(path, root, patterns):
    relative = os.path.relpath(path, root).replace('\\', '/').casefold()
    name = Path(path).name.casefold()
    return any(fnmatch.fnmatchcase(relative, x.replace('\\', '/').casefold()) or
               fnmatch.fnmatchcase(name, x.casefold()) for x in patterns)


def monitor_roots(settings):
    roots = settings['monitor_roots'] or [os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'Temp'),
                                        os.environ.get('PUBLIC', r'C:\Users\Public'), tempfile.gettempdir()]
    return list(dict.fromkeys(os.path.abspath(os.path.expandvars(os.path.expanduser(x))) for x in roots))


def locate_cws(configured=''):
    if configured:
        path = Path(os.path.expandvars(os.path.expanduser(configured)))
        return str(path.resolve()) if path.is_file() else None
    roots = [Path(os.environ.get('SystemDrive', 'C:') + os.sep) / 'Open CWS Anti-virus'] if IS_WINDOWS else []
    for key in ('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432'):
        if os.environ.get(key):
            roots.extend(Path(os.environ[key]) / name for name in ['Open CWS Anti-virus','ClamWin','ClamAV'])
    for root in roots:
        for name in ['bin/MSScmd.exe','MSScmd.exe','bin/clamscan.exe','clamscan.exe']:
            path = root / name
            if path.is_file(): return str(path.resolve())
    return None


def locate_cws_database(executable, configured=''):
    if configured:
        path = Path(os.path.expandvars(os.path.expanduser(configured)))
        return str(path.resolve()) if path.is_dir() else None
    if not executable: return None
    base = Path(executable).parent
    for path in [base / 'db', base / 'database', base.parent / 'db', base.parent / 'database']:
        if path.is_dir(): return str(path.resolve())
    return None


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def regular_info(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise OSError('Ссылка, reparse point или не обычный файл — пропущен')
    return info


def hash_file(path, cancel=None):
    before = regular_info(path)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise OSError('Файл подменён до чтения')
        while True:
            if cancel and cancel():
                raise InterruptedError('Остановлено пользователем')
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if identity(opened) != identity(os.fstat(stream.fileno())):
            raise OSError('Файл изменился при чтении — повторите проверку')
    if identity(before) != identity(regular_info(path)):
        raise OSError('Файл изменился после чтения')
    return digest.hexdigest(), before


def heuristic(path, info, days=3):
    p = Path(path)
    if p.suffix.lower() not in ('.exe', '.dll'):
        return ''
    recent = 0 <= time.time() - info.st_ctime < days * 86400
    parts = {part.lower() for part in p.parts}
    temp = bool(parts & {'temp', 'tmp'})
    impersonates = p.name.lower() in {'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
                                    'services.exe', 'explorer.exe', 'kernel32.dll', 'ntdll.dll'}
    if recent and temp and impersonates:
        return 'Недавний EXE/DLL с системным именем в Temp; возможное ложное срабатывание'
    if recent and temp and any(p.name.lower().endswith(x) for x in
                              ('.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe', '.png.exe')):
        return 'Недавний файл с двойным расширением в Temp; требуется ручная проверка'
    return ''


@dataclass(frozen=True)
class Finding:
    path: str
    sha256: str
    kind: str
    reason: str


def delete_verified(finding):
    if not IS_WINDOWS:
        raise OSError('Удаление поддерживается только в Windows')
    if finding.kind != 'test' or finding.sha256 not in SIGNATURES:
        raise OSError('Эвристика не является основанием для удаления')
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create = k32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    get_info = k32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    get_info.restype = wintypes.BOOL
    set_info = k32.SetFileInformationByHandle
    set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_info.restype = wintypes.BOOL
    class FileInfo(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('created', wintypes.FILETIME),
                    ('accessed', wintypes.FILETIME), ('written', wintypes.FILETIME),
                    ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                    ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                    ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]
    class Disposition(ctypes.Structure):
        _fields_ = [('delete', wintypes.BOOL)]
    handle = create(os.path.abspath(finding.path), 0x80000000 | 0x10000, 1, None,
                    3, 0x00200000 | 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = FileInfo()
        if not get_info(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & (0x400 | 0x10) or info.links > 1:
            raise OSError('Ссылка, каталог или файл с hard link: удаление запрещено')
        fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
        handle = None
        with os.fdopen(fd, 'rb') as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
            if digest.hexdigest() != finding.sha256:
                raise OSError('SHA-256 изменился: удаление отменено')
            disposition = Disposition(True)
            raw_handle = msvcrt.get_osfhandle(stream.fileno())
            if not set_info(raw_handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if handle is not None:
            close(handle)


def self_test():
    with tempfile.TemporaryDirectory() as folder:
        for name, data in TEST_SAMPLES.items():
            p = Path(folder) / name
            p.write_bytes(data)
            digest, _ = hash_file(p)
            assert SIGNATURES[digest] == name
        p = Path(folder) / 'clean.txt'
        p.write_text('ordinary document', encoding='utf-8')
        assert hash_file(p)[0] not in SIGNATURES
        try:
            hash_file(p, lambda: True)
            raise AssertionError('Отмена не обработана')
        except InterruptedError:
            pass
        temp = Path(folder) / 'Temp'
        temp.mkdir()
        test = temp / 'svchost.exe'
        test.write_bytes(b'not executable')
        assert heuristic(test, test.stat())
        assert not heuristic(p, p.stat())
        if IS_WINDOWS:
            target = Path(folder) / 'delete-test.bin'
            target.write_bytes(TEST_SAMPLES['OSIP.Demo.01'])
            digest, _ = hash_file(target)
            delete_verified(Finding(str(target), digest, 'test', 'self-test'))
            assert not target.exists()
    print('OK: 8 сигнатур, чистый файл, отмена, эвристика' +
          (', удаление через Windows handle' if IS_WINDOWS else ' (Windows API не тестировался)'))


def command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--create-demo', metavar='FOLDER')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return True
    if args.create_demo:
        folder = Path(args.create_demo)
        folder.mkdir(parents=True, exist_ok=True)
        for name, data in TEST_SAMPLES.items():
            with (folder / (name + '.txt')).open('xb') as stream:
                stream.write(data)
        print(f'Создано 8 безопасных образцов: {folder.resolve()}')
        return True
    return False


if __name__ == '__main__' and command_line():
    sys.exit(0)

try:
    import psutil
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    from PySide6.QtCore import (Qt, QThread, Signal, QTimer, QPropertyAnimation,
                                QEasingCurve, QRectF, QSize, QPointF, QUrl)
    from PySide6.QtGui import QColor, QPainter, QPen, QFont, QLinearGradient, QRadialGradient, QIcon, QPixmap, QPainterPath, QDesktopServices, QPalette
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QFrame, QLabel,
        QPushButton, QLineEdit, QFileDialog, QProgressBar, QPlainTextEdit,
        QTableWidget, QTableWidgetItem, QHeaderView, QVBoxLayout, QHBoxLayout,
        QGridLayout, QStackedWidget, QMessageBox, QGraphicsOpacityEffect,
        QAbstractItemView, QScrollArea, QCheckBox, QComboBox, QSpinBox, QFormLayout)
except ImportError as exc:
    message = f'Не установлены зависимости: {exc}\n\npy -m pip install PySide6 watchdog psutil'
    if IS_WINDOWS:
        ctypes.windll.user32.MessageBoxW(None, message, 'OSIP-DEFEND', 0x10)
    else:
        print(message, file=sys.stderr)
    sys.exit(1)


from PySide6 import QtCore

osip_qt_resource_data = b"\
\x00\x00\x00\xa1\
\x89\
PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\
\x00\x00\x14\x00\x00\x00\x14\x08\x06\x00\x00\x00\x8d\x89\x1d\x0d\
\x00\x00\x00hIDATx\x9c\xed\xd1\xbb\x11\xc0 \
\x0c\x03P\x91A\xd2\xb2\xff8\xb4Y\x84\xb49Y>\
\x1bS\xa4A\x1d\x1f?\x0c\x00'\xbff\xccg\xf2\xdc\
\xb5\x8b1Z\x02\x19\xf9\x8e\x97Au\xcd\xde\xeeV\x02\
#\xcc\x05U\xa1\x0ac\x12\xf4\x1e\x9b\xc7\x0a3\xa0\x87\
d;\x06\x00sJ\xa6\xd8\xeb\xcet\x18m\xce\xac\xcb\
O\xf1\x8a\x22,L\xe5\x0dO\xf6\xf3\x02\xb75A\xdc\
|\xfa\xcc{\x00\x00\x00\x00IEND\xaeB`\x82\
\
\x00\x00\x00\x91\
\x89\
PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\
\x00\x00\x14\x00\x00\x00\x14\x08\x06\x00\x00\x00\x8d\x89\x1d\x0d\
\x00\x00\x00XIDATx\x9cc`\x18\x05#\
\x14\x5cy\xfc\xf5?\xb9\xea\x98p)\"d(.uL\
\xd8\x14\x11r)>u(\x06\xea\xc8r3\x92\xa2\x19\
\x9b>\x0c/\xe33\x94\x90a\x0c\x0c\x0c\x0c\x18\x9a\xf1\
\xb9\x84\x18\xcb1\x5c\x88O11\xf28\x0d\xc4\xa7\x89\
\x90e\x04\x01\xb1Ii\x14\x0cR\x00\x00\xc2\xdaAf\
\xe4\xe6{\x00\x00\x00\x00IEND\xaeB`\x82\
\
\x00\x00\x00\x8d\
\x89\
PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\
\x00\x00\x14\x00\x00\x00\x14\x08\x06\x00\x00\x00\x8d\x89\x1d\x0d\
\x00\x00\x00TIDATx\x9cc`\x18\x05C\x13\
\x5cy\xfc\xf5?2\x8d\x0f0\x12k\x182\xd0\x91\xe5\
\xc6\xa9\x8f\x89T\xc3\xf0\x89\xe35\x90\x90\xf7p\xc9c\
5\x90XobS\x87a >\xc3\x881\x94\x09\x9f\
$6C\x08\x19\xca\x84O1\xae\xd8$V\x1d^\x97\
R\xa2n\x14\x0c7\x00\x00\x9b;:e\x9b\xc8\xcbw\
\x00\x00\x00\x00IEND\xaeB`\x82\
"

osip_qt_resource_name = b"\
\x00\x04\
\x00\x07j\x00\
\x00o\
\x00s\x00i\x00p\
\x00\x09\
\x0b\x9e\x84\x87\
\x00c\
\x00h\x00e\x00c\x00k\x00.\x00p\x00n\x00g\
\x00\x08\
\x06\xe1Z'\
\x00d\
\x00o\x00w\x00n\x00.\x00p\x00n\x00g\
\x00\x06\
\x07\xc3WG\
\x00u\
\x00p\x00.\x00p\x00n\x00g\
"

osip_qt_resource_struct = b"\
\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\
\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\
\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00&\x00\x00\x00\x00\x00\x01\x00\x00\x00\xa5\
\x00\x00\x01\xa1yK)d\
\x00\x00\x00<\x00\x00\x00\x00\x00\x01\x00\x00\x01:\
\x00\x00\x01\xa1yK)c\
\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\
\x00\x00\x01\xa1yQ\x9a^\
"

def osipInitResources():
    QtCore.qRegisterResourceData(0x03, osip_qt_resource_struct, osip_qt_resource_name, osip_qt_resource_data)

def osipCleanupResources():
    QtCore.qUnregisterResourceData(0x03, osip_qt_resource_struct, osip_qt_resource_name, osip_qt_resource_data)

osipInitResources()


class ScanWorker(QThread):
    log = Signal(str, str)
    result = Signal(object)
    progress = Signal(int, int, int, int)
    completed = Signal(int, int, int, bool)

    def __init__(self, folder, options=None):
        super().__init__()
        self.folder = folder
        self.options = validate_settings(options or {})

    def run(self):
        checked = threats = errors = processed = 0
        files = []
        try:
            root_info = os.lstat(self.folder)
            if not stat.S_ISDIR(root_info.st_mode) or getattr(root_info, 'st_file_attributes', 0) & 0x400 or os.path.islink(self.folder):
                raise OSError('Корень должен быть обычной папкой, не ссылкой')
            def walk_error(exc):
                nonlocal errors
                errors += 1
                self.log.emit(str(exc), 'Ошибка')
            self.log.emit('Составление списка файлов…', 'Информация')
            for root, dirs, names in os.walk(self.folder, onerror=walk_error, followlinks=False):
                if self.isInterruptionRequested():
                    break
                safe_dirs = []
                for name in dirs:
                    try:
                        p = os.path.join(root, name)
                        info = os.lstat(p)
                        if excluded_path(p, self.folder, self.options['excludes']):
                            self.log.emit(f'Исключён каталог настройками: {p}', 'Предупреждение')
                        elif self.options['recursive'] and not os.path.islink(p) and not getattr(info, 'st_file_attributes', 0) & 0x400:
                            safe_dirs.append(name)
                    except OSError as exc:
                        walk_error(exc)
                dirs[:] = safe_dirs
                for name in names:
                    candidate = os.path.join(root, name)
                    if excluded_path(candidate, self.folder, self.options['excludes']):
                        errors += 1
                        self.log.emit(f'Исключён настройками: {candidate}', 'Предупреждение')
                    else:
                        files.append(candidate)
            total = len(files)
            last_report = 0.0
            for path in files:
                if self.isInterruptionRequested():
                    break
                try:
                    digest, info = hash_file(path, self.isInterruptionRequested)
                    checked += 1
                    reason = heuristic(path, info, self.options['heuristic_days']) if self.options['heuristics'] else ''
                    if digest in SIGNATURES:
                        threats += 1
                        self.result.emit(Finding(path, digest, 'test', SIGNATURES[digest]))
                        self.log.emit(f'Тестовая сигнатура: {path}', 'Обнаружено')
                    elif reason:
                        threats += 1
                        self.result.emit(Finding(path, digest, 'heuristic', reason))
                        self.log.emit(f'Подозрительный: {path}', 'Предупреждение')
                except InterruptedError:
                    break
                except OSError as exc:
                    errors += 1
                    self.log.emit(f'{path}: {exc}', 'Ошибка')
                processed += 1
                if time.monotonic() - last_report > .12:
                    self.progress.emit(processed, total, checked, threats)
                    self.log.emit(f'Проверено {checked} • {path}', 'Ход проверки')
                    last_report = time.monotonic()
            self.progress.emit(processed, total, checked, threats)
        except Exception as exc:
            errors += 1
            self.log.emit(f'Сканирование: {exc}', 'Ошибка')
        finally:
            self.completed.emit(checked, threats, errors, self.isInterruptionRequested())


class DeleteWorker(QThread):
    outcome = Signal(object, bool, str)

    def __init__(self, findings):
        super().__init__()
        self.findings = findings

    def run(self):
        for finding in self.findings:
            if self.isInterruptionRequested():
                break
            try:
                for proc in psutil.process_iter(['exe']):
                    try:
                        if proc.info['exe'] and os.path.normcase(os.path.abspath(proc.info['exe'])) == os.path.normcase(os.path.abspath(finding.path)):
                            raise OSError('Файл используется запущенным процессом')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                delete_verified(finding)
                self.outcome.emit(finding, True, 'Удалён подтверждённый тестовый образец')
            except Exception as exc:
                self.outcome.emit(finding, False, str(exc))


class WatchHandler(FileSystemEventHandler):
    def __init__(self, events, lost, extensions=None):
        super().__init__()
        self.events, self.lost = events, lost
        self.extensions = set(extensions or ['.exe', '.bat'])

    def enqueue(self, path):
        if Path(path).suffix.lower() in self.extensions:
            try:
                self.events.put_nowait(str(path))
            except queue.Full:
                self.lost.set()

    def on_created(self, event):
        if not event.is_directory:
            self.enqueue(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.enqueue(event.dest_path)


class MonitorWorker(QThread):
    log = Signal(str, str)
    active = Signal(bool, str)

    def __init__(self, roots, options=None):
        super().__init__()
        self.roots = roots
        self.options = validate_settings(options or {})

    def run(self):
        events = queue.Queue(maxsize=2048)
        lost = threading.Event()
        observer = Observer(timeout=.5)
        handler = WatchHandler(events, lost, self.options['monitor_extensions'])
        scheduled = []
        try:
            for root in self.roots:
                try:
                    info = os.lstat(root)
                    if not stat.S_ISDIR(info.st_mode) or os.path.islink(root) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        raise OSError('Не обычная папка')
                    observer.schedule(handler, root, recursive=True)
                    scheduled.append(root)
                except OSError as exc:
                    self.log.emit(f'Не наблюдается {root}: {exc}', 'Ошибка')
            if not scheduled:
                raise OSError('Нет доступных папок для мониторинга')
            observer.start()
            self.active.emit(True, '\n'.join(scheduled))
            pending = {}
            while not self.isInterruptionRequested():
                try:
                    path = events.get(timeout=.2)
                    if path in pending or len(pending) < 2048:
                        pending[path] = time.monotonic() + self.options['monitor_delay_ms'] / 1000
                    else:
                        lost.set()
                except queue.Empty:
                    pass
                if lost.is_set():
                    self.log.emit('Очередь переполнена: часть событий потеряна. Запустите сканирование.', 'Предупреждение')
                    lost.clear()
                for path, due in list(pending.items()):
                    if time.monotonic() < due:
                        continue
                    pending.pop(path, None)
                    try:
                        regular_info(path)
                        self.log.emit(f'Новый отслеживаемый файл: {path} — проверьте сканером. Не является доказательством заражения.', 'Предупреждение')
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        self.log.emit(f'Мониторинг {path}: {exc}', 'Ошибка')
                if not observer.is_alive() or any(not e.is_alive() for e in observer.emitters):
                    raise OSError('Поток наблюдения остановился; включите защиту повторно')
        except Exception as exc:
            self.log.emit(f'Мониторинг: {exc}', 'Ошибка')
        finally:
            observer.stop()
            if observer.is_alive():
                observer.join()
            self.active.emit(False, '')


def locate_defender():
    if not IS_WINDOWS:
        return None
    platform = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Microsoft/Windows Defender/Platform'
    def version(path):
        return tuple(int(n) for n in re.findall(r'\d+', path.name))
    try:
        candidates = [p / 'MpCmdRun.exe' for p in sorted(platform.iterdir(), key=version, reverse=True)
                      if p.is_dir() and not p.is_symlink()]
    except OSError:
        candidates = []
    for key in ('ProgramW6432', 'ProgramFiles'):
        root = os.environ.get(key)
        if root:
            candidates.append(Path(root) / 'Windows Defender/MpCmdRun.exe')
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return str(candidate.resolve())
    return None


def verify_microsoft_binary(path):
    if not IS_WINDOWS:
        raise OSError('Microsoft Defender доступен только в Windows')
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    escaped = str(path).replace("'", "''")
    script = ("[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; "
              "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; "
              "@{Status=$s.Status.ToString();Subject=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
                             '-EncodedCommand', encoded], capture_output=True, timeout=25,
                             creationflags=subprocess.CREATE_NO_WINDOW, shell=False)
    if result.returncode:
        raise OSError('Не удалось проверить цифровую подпись Defender. Проверьте политики PowerShell и права доступа.')
    try:
        data = json.loads(result.stdout.decode('utf-8-sig'))
    except (ValueError, UnicodeError):
        raise OSError('Не удалось прочитать результат проверки Authenticode') from None
    subject = str(data.get('Subject', ''))
    if data.get('Status') != 'Valid' or not re.search(r'(?:^|,\s*)O=Microsoft Corporation(?:,|$)', subject, re.I):
        raise OSError('Подпись MpCmdRun не подтверждена как действующая подпись Microsoft. Запуск запрещён.')


class DefenderWorker(QThread):
    log = Signal(str, str)
    completed = Signal(int, str, bool)

    def __init__(self, executable, folder, data_dir, update=False):
        super().__init__()
        self.executable, self.folder = executable, folder
        self.data_dir, self.update = Path(data_dir), update

    def run(self):
        process = None
        code, message, cancelled = -1, '', False
        try:
            if not IS_WINDOWS:
                raise OSError('Для запуска Microsoft Defender необходима Windows 10/11')
            if not self.update and not os.path.isdir(self.folder):
                raise OSError('Выберите доступную папку для проверки')
            self.log.emit('Проверка цифровой подписи Microsoft…', 'Информация')
            verify_microsoft_binary(self.executable)
            if self.isInterruptionRequested():
                cancelled = True
                return
            command = ([self.executable, '-SignatureUpdate'] if self.update else
                       [self.executable, '-Scan', '-ScanType', '3', '-File', self.folder, '-DisableRemediation'])
            self.data_dir.mkdir(parents=True, exist_ok=True)
            raw_path = self.data_dir / ('defender-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.log')
            with raw_path.open('wb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, shell=False,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                self.log.emit('Запущен установленный Microsoft Defender. Исходный вывод: ' + str(raw_path), 'Информация')
                encoding = 'cp' + str(ctypes.windll.kernel32.GetOEMCP())
                decoder = codecs.getincrementaldecoder(encoding)(errors='replace')
                pending = ''
                with raw_path.open('rb') as reader:
                    while True:
                        chunk = reader.read(65536)
                        if chunk:
                            pending += decoder.decode(chunk)
                            lines = pending.replace('\r', '\n').split('\n')
                            pending = lines.pop()
                            for line in lines:
                                if line.strip():
                                    self.log.emit(line[:4096], 'Вывод Defender')
                            if len(pending) > 8192:
                                self.log.emit(pending[:4096], 'Вывод Defender')
                                pending = pending[4096:]
                        if self.isInterruptionRequested() and process.poll() is None:
                            cancelled = True
                            process.terminate()
                            try:
                                process.wait(timeout=4)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=4)
                            self.log.emit('Ожидание CLI прекращено. Сканирование службы может продолжаться.', 'Предупреждение')
                        if process.poll() is not None and not chunk:
                            break
                        self.msleep(100)
                    pending += decoder.decode(b'', final=True)
                    if pending.strip():
                        self.log.emit(pending[:4096], 'Вывод Defender')
            code = process.returncode
            if cancelled:
                message = 'Ожидание прекращено. Состояние сканирования службы не подтверждено.'
            elif code == 0:
                message = ('Сигнатуры Defender обновлены.' if self.update else
                           'Defender завершил проверку с кодом 0. Подробности — в исходном выводе ниже.')
            elif code == 2 and not self.update:
                message = 'Код 2: обнаружение, требуемое действие ИЛИ ошибка проверки. Изучите вывод Defender.'
            else:
                message = f'Defender завершился с кодом {code}. Проверьте вывод, состояние службы и права администратора.'
        except Exception as exc:
            message = str(exc)
            self.log.emit(message, 'Ошибка')
        finally:
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=4)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        process.kill()
                        process.wait(timeout=4)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            self.completed.emit(code, message or 'Запуск отменён.', cancelled or self.isInterruptionRequested())


def vector_icon(name, color='#9aa7b8', size=22):
    pix = QPixmap(size * 2, size * 2)
    pix.setDevicePixelRatio(2)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 24, size / 24)
    p.setPen(QPen(QColor(color), 1.65, Qt.PenStyle.SolidLine,
                  Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    if name in ('shield', 'engine'):
        shape = QPainterPath()
        shape.moveTo(12, 2.5); shape.lineTo(20, 6); shape.lineTo(18.5, 15)
        shape.quadTo(17, 19, 12, 22); shape.quadTo(7, 19, 5.5, 15)
        shape.lineTo(4, 6); shape.closeSubpath(); p.drawPath(shape)
        p.drawLine(QPointF(8.5, 12), QPointF(11, 14.5)); p.drawLine(QPointF(11, 14.5), QPointF(16, 9))
    elif name == 'scan':
        p.drawRoundedRect(QRectF(3, 3, 13, 17), 2, 2)
        p.drawLine(7, 7, 12, 7); p.drawLine(7, 10, 10, 10)
        p.drawEllipse(QRectF(11, 12, 8, 8)); p.drawLine(18, 19, 22, 23)
    elif name == 'system':
        p.drawRoundedRect(QRectF(3, 4, 18, 13), 2, 2)
        p.drawLine(8, 21, 16, 21); p.drawLine(12, 17, 12, 21)
        p.drawLine(7, 10, 10, 13); p.drawLine(10, 13, 16, 7)
    elif name == 'settings':
        for y, x in [(6,8),(12,16),(18,10)]:
            p.drawLine(3,y,21,y); p.setBrush(QColor('#10141b'))
            p.drawEllipse(QRectF(x-2.5,y-2.5,5,5)); p.setBrush(Qt.BrushStyle.NoBrush)
    elif name == 'logs':
        p.drawRoundedRect(QRectF(4, 3, 16, 19), 2, 2)
        for y in (8, 12, 16): p.drawLine(8, y, 16, y)
    elif name == 'folder':
        path = QPainterPath(); path.moveTo(3, 7); path.lineTo(3, 5)
        path.lineTo(10, 5); path.lineTo(12, 7); path.lineTo(21, 7)
        path.lineTo(21, 20); path.lineTo(3, 20); path.closeSubpath(); p.drawPath(path)
    elif name == 'play':
        path = QPainterPath(); path.moveTo(8, 5); path.lineTo(19, 12); path.lineTo(8, 19)
        path.closeSubpath(); p.drawPath(path)
    elif name == 'alert':
        p.drawEllipse(QRectF(3, 3, 18, 18)); p.drawLine(12, 7, 12, 13); p.drawPoint(12, 17)
    else:
        p.drawRoundedRect(QRectF(4, 4, 16, 16), 3, 3)
        p.drawLine(8, 12, 16, 12); p.drawLine(12, 8, 12, 16)
    p.end()
    return QIcon(pix)


class MetricCard(QFrame):
    def __init__(self, title, value='0', detail='', accent=False):
        super().__init__()
        self.setObjectName('Metric')
        self.setMinimumHeight(92)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(3)
        top = QLabel(title.upper()); top.setObjectName('Eyebrow')
        self.value = QLabel(value); self.value.setObjectName('MetricValue')
        if accent: self.value.setStyleSheet('color: #00ff41;')
        layout.addWidget(top); layout.addWidget(self.value)
        if detail:
            hint = QLabel(detail); hint.setObjectName('Muted'); hint.setWordWrap(True)
            layout.addWidget(hint)


class CWSWorker(QThread):
    log = Signal(str, str)
    completed = Signal(int, str, bool)

    def __init__(self, executable, folder, data_dir, options):
        super().__init__()
        self.executable, self.folder = executable, folder
        self.data_dir, self.options = Path(data_dir), copy.deepcopy(options)

    def run(self):
        process = None
        code, message, cancelled = -1, '', False
        try:
            if not IS_WINDOWS: raise OSError('Этот адаптер предназначен для Windows-версии Open-CWS/ClamAV')
            exe = Path(self.executable).resolve()
            if exe.name.lower() not in {'msscmd.exe', 'clamscan.exe'}:
                raise OSError('Нужен сканер MSScmd.exe либо clamscan.exe, не GUI, установщик или BAT')
            if not self.options['cws_sha256']:
                raise OSError('Сначала подтвердите доверие пакету Open-CWS в настройках')
            actual, _ = hash_file(exe, self.isInterruptionRequested)
            if actual != self.options['cws_sha256']:
                raise OSError('CWS изменился: SHA-256 не совпадает с доверенным. Повторный запуск запрещён до проверки пакета.')
            db = locate_cws_database(str(exe), self.options['cws_database'])
            if not db: raise OSError('Укажите каталог сигнатур Open-CWS/ClamAV в настройках')
            extensions = {'.cvd','.cld','.hdb','.hsb','.ndb','.ldb','.cdb','.mdb','.sdb','.yar','.yara'}
            if not any(x.is_file() and x.suffix.lower() in extensions for x in Path(db).iterdir()):
                raise OSError('В выбранном каталоге не обнаружены базы ClamAV. Пустая база не означает отсутствие угроз.')
            folder = os.path.abspath(self.folder)
            if not os.path.isdir(folder): raise OSError('Папка проверки недоступна')
            command = [str(exe), '--database=' + db, '--infected',
                       '--recursive=' + ('yes' if self.options['recursive'] else 'no'),
                       '--scan-archive=' + ('yes' if self.options['cws_archives'] else 'no'),
                       f"--max-filesize={self.options['cws_max_file_mb']}M",
                       f"--max-scansize={self.options['cws_max_scan_mb']}M",
                       '--follow-dir-symlinks=0', '--follow-file-symlinks=0', folder]
            if self.isInterruptionRequested(): cancelled = True; return
            self.data_dir.mkdir(parents=True, exist_ok=True)
            raw = self.data_dir / ('cws-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.log')
            with raw.open('wb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, shell=False, cwd=str(exe.parent),
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                self.log.emit(f'Open-CWS/ClamAV: только отчёт. База: {db}. Исходный вывод: {raw}', 'Информация')
                decoder = codecs.getincrementaldecoder('cp' + str(ctypes.windll.kernel32.GetOEMCP()))(errors='replace')
                pending = ''
                with raw.open('rb') as reader:
                    while True:
                        chunk = reader.read(65536)
                        if chunk:
                            pending += decoder.decode(chunk)
                            lines = pending.replace('\r', '\n').split('\n'); pending = lines.pop()
                            for line in lines:
                                if line.strip(): self.log.emit(line[:4096], 'Вывод Open-CWS')
                            if len(pending) > 8192:
                                self.log.emit(pending[:4096], 'Вывод Open-CWS'); pending = pending[4096:]
                        if self.isInterruptionRequested() and process.poll() is None:
                            cancelled = True; process.terminate()
                            try: process.wait(timeout=4)
                            except subprocess.TimeoutExpired:
                                process.kill(); process.wait(timeout=4)
                        if process.poll() is not None and not chunk: break
                        self.msleep(100)
                    pending += decoder.decode(b'', final=True)
                    if pending.strip(): self.log.emit(pending[:4096], 'Вывод Open-CWS')
            code = process.returncode
            if cancelled: message = 'Проверка Open-CWS остановлена пользователем.'
            elif code == 0: message = 'Open-CWS: совпадений не найдено в пределах лимитов движка. Проверьте итоговую сводку.'
            elif code == 1: message = 'Open-CWS: обнаружены совпадения. Файлы не изменены; подробности в выводе.'
            else: message = f'Open-CWS: ошибка, код {code}. Возможны несовместимые базы или устаревший движок.'
        except InterruptedError:
            cancelled = True; message = 'Запуск Open-CWS отменён.'
        except Exception as exc:
            message = str(exc); self.log.emit(message, 'Ошибка')
        finally:
            if process and process.poll() is None:
                try: process.terminate(); process.wait(timeout=4)
                except (OSError, subprocess.TimeoutExpired):
                    try: process.kill(); process.wait(timeout=4)
                    except (OSError, subprocess.TimeoutExpired): pass
            self.completed.emit(code, message, cancelled or self.isInterruptionRequested())


class MultiEngineWorker(QThread):
    log = Signal(str, str)
    engine_result = Signal(str, int, str, bool)
    completed = Signal(int, str, bool)

    def __init__(self, folder, data_dir, options, mode='both', update=False):
        super().__init__()
        self.folder, self.data_dir = folder, data_dir
        self.options = copy.deepcopy(options)
        self.mode, self.update = mode, update

    def run(self):
        selected = ['defender'] if self.update else (['defender','cws'] if self.mode == 'both' else [self.mode])
        results, cancelled = [], False
        for engine in selected:
            if self.isInterruptionRequested(): cancelled = True; break
            child = None
            try:
                if engine == 'defender':
                    exe = locate_defender()
                    if not exe: raise OSError('Microsoft Defender: MpCmdRun.exe не найден')
                    child = DefenderWorker(exe, self.folder, self.data_dir, self.update)
                else:
                    exe = locate_cws(self.options['cws_executable'])
                    if not exe: raise OSError('Open-CWS: сканер не найден. Укажите MSScmd.exe/clamscan.exe в настройках.')
                    child = CWSWorker(exe, self.folder, self.data_dir, self.options)
                captured = []
                child.log.connect(self.log.emit, Qt.ConnectionType.DirectConnection)
                child.completed.connect(lambda *args: captured.append(args), Qt.ConnectionType.DirectConnection)
                self.log.emit('Запуск: ' + ('Microsoft Defender' if engine == 'defender' else 'Open-CWS/ClamAV'), 'Информация')
                child.start(); started = time.monotonic(); timed_out = False
                while not child.wait(100):
                    if self.isInterruptionRequested(): child.requestInterruption()
                    if time.monotonic() - started > self.options['av_timeout_minutes'] * 60:
                        timed_out = True; child.requestInterruption()
                if not captured: raise OSError('Движок не вернул результат')
                code, message, aborted = captured[-1]
                if timed_out:
                    code, aborted = -1, False
                    message = 'Достигнут тайм-аут. ' + ('Сканирование службы Microsoft может продолжаться.' if engine=='defender' else 'Процесс Open-CWS завершён.')
                if self.isInterruptionRequested(): cancelled = True
                results.append(code); self.engine_result.emit(engine, code, message, aborted)
                self.log.emit(message, 'Успех' if code == 0 and not aborted else 'Предупреждение')
            except Exception as exc:
                results.append(-1); self.engine_result.emit(engine, -1, str(exc), False)
                self.log.emit(str(exc), 'Ошибка')
            finally:
                if child and child.isRunning():
                    child.requestInterruption(); child.wait()
        if cancelled:
            summary, code = 'Задача остановлена. Не все выбранные движки могли завершить проверку.', -1
        elif len(results) == len(selected) and all(x == 0 for x in results):
            summary, code = ('Обновление системной базы завершено.' if self.update else
                             'Все выбранные движки завершились с кодом 0. Это не гарантирует безопасность файлов.'), 0
        else:
            summary, code = 'Есть обнаружения, ошибки или недоступные движки. Проверьте результаты каждого движка.', 2
        self.completed.emit(code, summary, cancelled)


class AntivirusTab(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window, self.worker = window, None
        layout = QVBoxLayout(self); layout.setSpacing(14)
        heading(layout, 'Антивирус OSIP', 'Ваш центр проверки: два независимых движка, одна папка и общий журнал.')
        box, body = card(); box.setObjectName('EngineHero')
        row = QHBoxLayout()
        icon = QLabel(); icon.setPixmap(vector_icon('shield', GREEN, 52).pixmap(52,52)); row.addWidget(icon)
        text = QVBoxLayout(); title = QLabel('OSIP Multi-Engine'); title.setObjectName('HeroTitle'); text.addWidget(title)
        hint = QLabel('Единый интерфейс. Только отчёт. Без отключения системной защиты.'); hint.setObjectName('Muted'); hint.setWordWrap(True)
        text.addWidget(hint); row.addLayout(text,1)
        details = button('Сведения о движках', self.about); row.addWidget(details); body.addLayout(row)
        self.availability = QLabel(); self.availability.setObjectName('Muted'); self.availability.setWordWrap(True); body.addWidget(self.availability)
        layout.addWidget(box)
        box, body = card()
        label = QLabel('ПАПКА И ПРОФИЛЬ ПРОВЕРКИ'); label.setObjectName('Eyebrow'); body.addWidget(label)
        row = QHBoxLayout(); self.path = QLineEdit(window.settings['default_folder']); row.addWidget(self.path,1)
        self.browse = button('Обзор',self.choose); self.browse.setIcon(vector_icon('folder')); row.addWidget(self.browse); body.addLayout(row)
        row = QHBoxLayout(); self.mode = QComboBox()
        self.mode.addItems(['Оба движка','OSIP System','OSIP Community'])
        self.mode.setToolTip('System: Microsoft Defender. Community: сканер Open-CWS/ClamAV. Это бренд интерфейса, не переименование бинарников.')
        self.mode.setCurrentIndex({'both':0,'defender':1,'cws':2}[window.settings['engine_mode']]); row.addWidget(self.mode,1)
        self.start = button('Начать проверку',self.scan,'Primary'); row.addWidget(self.start,1)
        self.refresh = button('Проверить доступность',self.detect); row.addWidget(self.refresh); body.addLayout(row)
        self.progress = QProgressBar(); self.progress.setRange(0,100); self.progress.setValue(0); self.progress.setTextVisible(False); body.addWidget(self.progress)
        self.status = QLabel('Выберите папку. Файлы по результатам внешней проверки не удаляются.'); self.status.setWordWrap(True); body.addWidget(self.status)
        notice = QLabel('Изменения настроек применяются к следующей задаче. Исключения локального сканера не передаются внешним движкам. '
                        'Microsoft использует свои облачные политики; Open-CWS ограничен возможностями и лимитами ClamAV.')
        notice.setWordWrap(True); notice.setObjectName('Muted'); body.addWidget(notice); layout.addWidget(box)
        self.results = table(['Движок','Результат']); self.results.setMinimumHeight(120); self.results.setMaximumHeight(140)
        layout.addWidget(self.results)
        row = QHBoxLayout()
        self.update = button('Обновить базу Windows',self.update_signatures); row.addWidget(self.update)
        self.security = button('Безопасность Windows',self.open_security); row.addWidget(self.security)
        row.addStretch(); self.stop = button('Прекратить задачу',self.cancel); self.stop.setEnabled(False); row.addWidget(self.stop)
        layout.addLayout(row)
        self.console = QPlainTextEdit(); self.console.setReadOnly(True); self.console.setMaximumBlockCount(window.settings['log_limit'])
        self.console.setMinimumHeight(120); self.console.setPlaceholderText('Вывод движков и результаты проверки…'); layout.addWidget(self.console,1)
        self.mode.currentIndexChanged.connect(self.detect)
        self.detect()

    def about(self):
        self.window.switch(5); self.window.settings_tab.sections.setCurrentIndex(4)

    def detect(self):
        defender = locate_defender()
        cws = locate_cws(self.window.settings['cws_executable'])
        trusted = bool(cws and self.window.settings['cws_sha256'])
        db = locate_cws_database(cws,self.window.settings['cws_database'])
        self.availability.setText('OSIP System: ' + ('CLI обнаружен' if defender else 'не найден') +
            '    /    OSIP Community: ' + ('готов к запуску (доверие проверяется перед запуском)' if trusted and db else
                                         'настройте путь, базу и доверие' if cws else 'не найден; настройте Open-CWS'))
        self.update.setEnabled(bool(defender) and not self.worker)
        selected = ['both','defender','cws'][self.mode.currentIndex()]
        usable = bool(defender) if selected=='defender' else bool(trusted and db) if selected=='cws' else bool(defender or (trusted and db))
        self.start.setEnabled(usable and not self.worker)

    def choose(self):
        folder = QFileDialog.getExistingDirectory(self,'Папка для антивируса OSIP',self.path.text())
        if folder: self.path.setText(folder)

    def scan(self):
        folder = os.path.abspath(os.path.expandvars(os.path.expanduser(self.path.text().strip())))
        if not os.path.isdir(folder): QMessageBox.warning(self,'Антивирус OSIP','Выберите существующую папку.'); return
        self.launch(folder,False)

    def update_signatures(self): self.launch('',True)

    def launch(self,folder,update):
        if self.worker: return
        mode = ['both','defender','cws'][self.mode.currentIndex()]
        self.console.clear(); self.results.setRowCount(0)
        for item in (self.start,self.update,self.refresh,self.browse,self.path,self.mode): item.setEnabled(False)
        self.stop.setEnabled(True); self.progress.setRange(0,0)
        self.status.setText('Обновление системной базы…' if update else 'Последовательная проверка выбранными движками…')
        self.worker = MultiEngineWorker(folder,self.window.data_dir,self.window.settings,mode,update)
        self.worker.log.connect(self.engine_log); self.worker.engine_result.connect(self.result)
        self.worker.completed.connect(self.complete); self.worker.finished.connect(self.released); self.worker.start()
        self.window.log('OSIP: ' + ('обновление базы Windows' if update else f'профиль {mode}, папка {folder}'),'Информация')

    def engine_log(self,text,status):
        self.console.appendPlainText(f'[{datetime.now():%H:%M:%S}] {text}')
        self.window.log(text,status)

    def result(self,engine,code,message,cancelled):
        name = 'OSIP System' if engine=='defender' else 'OSIP Community'
        row = fill_row(self.results,[name,('Отменено · ' if cancelled else f'Код {code} · ') + message],GREEN if code==0 and not cancelled else '#ffc56e')
        self.results.item(row,0).setToolTip('Microsoft Defender' if engine=='defender' else 'Open-CWS / ClamAV')

    def complete(self,code,message,cancelled):
        self.progress.setRange(0,100); self.progress.setValue(100 if code==0 and not cancelled else 0)
        self.status.setText(message); self.status.setStyleSheet('color: #00ff41;' if code==0 and not cancelled else 'color: #ffc56e;')

    def released(self):
        self.worker.deleteLater(); self.worker=None
        for item in (self.refresh,self.browse,self.path,self.mode): item.setEnabled(True)
        self.stop.setEnabled(False); self.detect()

    def cancel(self):
        if self.worker and QMessageBox.question(self,'Прекратить задачу',
            'Остановить текущий CLI и не запускать следующий движок? Проверка внутри службы Microsoft может продолжаться. '
            'Службы защиты не отключаются.',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)==QMessageBox.StandardButton.Yes:
            self.worker.requestInterruption(); self.stop.setEnabled(False); self.status.setText('Остановка задачи…')

    def open_security(self):
        try:
            if not IS_WINDOWS: raise OSError('Раздел доступен только в Windows')
            os.startfile('windowsdefender:')
        except OSError as exc: QMessageBox.warning(self,'Безопасность Windows',str(exc))


class SettingsTab(QWidget):
    def __init__(self,window):
        super().__init__(); self.window=window
        layout=QVBoxLayout(self); layout.setSpacing(16)
        heading(layout,'Настройки','Параметры сохраняются локально. Запущенные задачи продолжают работу со своим снимком настроек.')
        row=QHBoxLayout(); save=button('Сохранить настройки',self.save,'Primary'); row.addWidget(save)
        row.addWidget(button('Значения по умолчанию',self.reset)); row.addStretch(); layout.addLayout(row)
        from PySide6.QtWidgets import QTabWidget
        self.sections=QTabWidget(); layout.addWidget(self.sections,1)
        general,g=self.section('Общие'); local,l=self.section('Сканер'); monitor,m=self.section('Мониторинг'); cws,c=self.section('Open-CWS'); about,a=self.section('Сведения')
        self.folder=QLineEdit(); g.addRow('Папка по умолчанию',self.pick_row(self.folder,False))
        self.default_mode=QComboBox(); self.default_mode.addItems(['Оба движка','OSIP System','OSIP Community']); g.addRow('Профиль антивируса',self.default_mode)
        self.timeout=self.spin(1,1440); self.timeout.setSuffix(' мин'); g.addRow('Тайм-аут каждого CLI',self.timeout)
        self.animations=QCheckBox('Плавные переходы и анимация щита'); g.addRow('Оформление',self.animations)
        self.font_size=self.spin(12,18); self.font_size.setSuffix(' px'); g.addRow('Размер основного текста',self.font_size)
        self.log_limit=self.spin(100,10000); g.addRow('Максимум событий',self.log_limit)
        self.add_note(g,'Тайм-аут завершает наш CLI, но не гарантирует остановку проверки внутри службы Microsoft. '
                      'Параметры оформления и размер журнала применяются сразу.')
        self.recursive=QCheckBox('Проверять вложенные папки'); l.addRow('Рекурсия',self.recursive)
        self.heuristics=QCheckBox('Проверять подозрительные имена EXE/DLL в Temp'); l.addRow('Эвристика',self.heuristics)
        self.days=self.spin(1,365); self.days.setSuffix(' дн.'); l.addRow('Считать файл недавним',self.days)
        self.excludes=QPlainTextEdit(); self.excludes.setMaximumHeight(150); self.excludes.setPlaceholderText('*.iso\nnode_modules\ncache/*'); l.addRow('Исключения (по строке)',self.excludes)
        self.add_note(l,'Исключения — glob-шаблоны имени или относительного пути, без учёта регистра. '
                      'Применяются только к локальному SHA-256-сканеру. Эвристика не доказывает заражение. '
                      'Рекурсия применяется также к Open-CWS; Microsoft проверяет папку по собственным правилам.')
        self.roots=QPlainTextEdit(); self.roots.setMaximumHeight(180); self.roots.setPlaceholderText('Пусто — Windows Temp, Users Public и %TEMP%'); m.addRow('Папки (по строке)',self.roots)
        self.extensions=QLineEdit(); m.addRow('Расширения через запятую',self.extensions)
        self.delay=self.spin(100,10000); self.delay.setSuffix(' мс'); m.addRow('Задержка события',self.delay)
        self.add_note(m,'Поддерживаются %ПЕРЕМЕННЫЕ_СРЕДЫ%. Настройки применятся при следующем включении наблюдателя. '
                      'События создания и перемещения отслеживаются рекурсивно; автоматического удаления нет.')
        self.cws_path=QLineEdit(); c.addRow('Сканер .exe',self.pick_row(self.cws_path,True))
        self.cws_db=QLineEdit(); c.addRow('Каталог базы',self.pick_row(self.cws_db,False))
        find=button('Найти установленный Open-CWS / ClamAV',self.discover); c.addRow(find)
        self.trust=QCheckBox('Доверяю выбранному пакету и разрешаю запуск сканера'); c.addRow(self.trust)
        self.pin=QLabel(); self.pin.setObjectName('Code'); self.pin.setWordWrap(True); c.addRow('Доверенный SHA-256',self.pin)
        self.cws_path.textEdited.connect(lambda _:self.trust.setChecked(False))
        self.archives=QCheckBox('Проверять содержимое поддерживаемых архивов'); c.addRow('Архивы',self.archives)
        self.max_file=self.spin(1,2048); self.max_file.setSuffix(' МиБ'); c.addRow('Лимит одного файла',self.max_file)
        self.max_scan=self.spin(1,4096); self.max_scan.setSuffix(' МиБ'); c.addRow('Лимит распаковки',self.max_scan)
        self.add_note(c,'Open-CWS больше не поддерживается. Установите доверенный пакет отдельно: bin/MSScmd.exe и bin/db. '
                      'Поддерживается также clamscan.exe. SHA-256 фиксирует выбранный файл, но НЕ доказывает безопасность пакета и его DLL. '
                      'Старый движок может не работать с современными базами; ошибки не считаются успешной проверкой. '
                      'Базы CWS обновляются отдельно, их возраст и совместимость контролируйте по выводу движка.')
        c.addRow(button('Открыть исходный проект',lambda:QDesktopServices.openUrl(QUrl(CWS_PROJECT))))
        text=QLabel('OSIP-DEFEND 3.0 — бренд интерфейса и собственный локальный сканер.\n\n'
                   'OSIP System использует установленный Microsoft Defender (Microsoft Corporation). '
                   'Перед запуском MpCmdRun проверяется Authenticode. Microsoft Defender не переименовывается, не копируется и не отключается.\n\n'
                   'OSIP Community — независимый адаптер сканера Open-CWS / ClamAV. Open-CWS распространяется под GPL-2.0; '
                   'автор репозитория: mrkaban. Проект больше не поддерживается. Код и бинарники проекта в этом файле не распространяются. '
                   'При самостоятельном распространении стороннего пакета соблюдайте его лицензии.\n\n'
                   'Оба движка работают в режиме отчёта: автоматическое удаление, завершение чужих процессов и запуск BAT-скриптов отсутствуют. '
                   'Фоновая защита Windows остаётся независимой.\n\n'
                   'Проверка GUI и адаптеров выполнена в Linux с безопасными тестовыми CLI. '
                   'Реальные движки Windows, реестр и их совместимость здесь не проверялись.')
        text.setWordWrap(True); a.addRow(text)
        a.addRow(button('Исходный проект Open-CWS',lambda:QDesktopServices.openUrl(QUrl(CWS_PROJECT))))
        a.addRow(button('Документация Microsoft Defender',lambda:QDesktopServices.openUrl(QUrl('https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus'))))
        self.feedback=QLabel('Параметры загружены. Для применения изменений нажмите «Сохранить».'); self.feedback.setObjectName('Muted'); self.feedback.setWordWrap(True); layout.addWidget(self.feedback)
        self.load(window.settings)

    def section(self,title):
        page=QWidget(); page.setObjectName('Page'); form=QFormLayout(page)
        form.setContentsMargins(20,20,20,20); form.setSpacing(14)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.sections.addTab(page,title); return page,form

    @staticmethod
    def spin(low,high):
        result=QSpinBox(); result.setRange(low,high); result.lineEdit().setTextMargins(10,0,8,0); return result

    @staticmethod
    def add_note(form,text):
        label=QLabel(text); label.setWordWrap(True); label.setObjectName('Muted'); form.addRow(label)

    def pick_row(self,edit,executable):
        container=QWidget(); row=QHBoxLayout(container); row.setContentsMargins(0,0,0,0)
        row.addWidget(edit,1)
        def pick():
            if executable: path,_=QFileDialog.getOpenFileName(self,'Сканер MSScmd.exe или clamscan.exe',edit.text(),'Исполняемые файлы (*.exe)')
            else: path=QFileDialog.getExistingDirectory(self,'Выберите папку',edit.text())
            if path:
                edit.setText(path)
                if edit is self.cws_path: self.trust.setChecked(False)
        row.addWidget(button('Обзор',pick)); return container

    def load(self,values):
        self.folder.setText(values['default_folder']); self.default_mode.setCurrentIndex({'both':0,'defender':1,'cws':2}[values['engine_mode']])
        for widget,key in [(self.timeout,'av_timeout_minutes'),(self.font_size,'font_size'),(self.log_limit,'log_limit'),
                           (self.days,'heuristic_days'),(self.delay,'monitor_delay_ms'),(self.max_file,'cws_max_file_mb'),(self.max_scan,'cws_max_scan_mb')]: widget.setValue(values[key])
        for widget,key in [(self.animations,'animations'),(self.recursive,'recursive'),(self.heuristics,'heuristics'),(self.archives,'cws_archives')]: widget.setChecked(values[key])
        self.excludes.setPlainText('\n'.join(values['excludes'])); self.roots.setPlainText('\n'.join(values['monitor_roots']))
        self.extensions.setText(', '.join(values['monitor_extensions']))
        self.cws_path.setText(values['cws_executable']); self.cws_db.setText(values['cws_database'])
        self.trust.setChecked(bool(values['cws_sha256'])); self.pin.setText(values['cws_sha256'] or 'Не задан')

    def discover(self):
        exe=locate_cws()
        if not exe: QMessageBox.information(self,'Open-CWS','Пакет не найден в стандартных папках. Укажите установленный сканер вручную.'); return
        self.cws_path.setText(exe); self.trust.setChecked(False)
        self.cws_db.setText(locate_cws_database(exe) or '')
        self.feedback.setText('Найдены пути. Проверьте источник пакета и подтвердите доверие перед сохранением.')

    def reset(self):
        if QMessageBox.question(self,'Сброс настроек','Загрузить значения по умолчанию в форму? Чтобы применить их, нажмите «Сохранить».',
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)==QMessageBox.StandardButton.Yes:
            self.load(DEFAULT_SETTINGS); self.feedback.setText('Значения по умолчанию загружены в форму, но ещё не сохранены.')

    def save(self):
        try:
            values=copy.deepcopy(self.window.settings)
            values.update(default_folder=self.folder.text().strip(),engine_mode=['both','defender','cws'][self.default_mode.currentIndex()],
                          excludes=self.excludes.toPlainText().splitlines(),monitor_roots=self.roots.toPlainText().splitlines(),
                          monitor_extensions=self.extensions.text().split(','),cws_executable=self.cws_path.text().strip(),cws_database=self.cws_db.text().strip())
            for widget,key in [(self.timeout,'av_timeout_minutes'),(self.font_size,'font_size'),(self.log_limit,'log_limit'),
                               (self.days,'heuristic_days'),(self.delay,'monitor_delay_ms'),(self.max_file,'cws_max_file_mb'),(self.max_scan,'cws_max_scan_mb')]: values[key]=widget.value()
            for widget,key in [(self.animations,'animations'),(self.recursive,'recursive'),(self.heuristics,'heuristics'),(self.archives,'cws_archives')]: values[key]=widget.isChecked()
            values=validate_settings(values)
            if not self.trust.isChecked(): values['cws_sha256']=''
            elif not values['cws_sha256'] or values['cws_executable'] != self.window.settings['cws_executable']:
                exe=locate_cws(values['cws_executable'])
                if not exe or Path(exe).name.lower() not in {'msscmd.exe','clamscan.exe'}: raise ValueError('Выберите MSScmd.exe либо clamscan.exe')
                if regular_info(exe).st_size > 64*1024*1024: raise ValueError('EXE больше 64 МиБ: проверьте, что выбран сканер, а не установщик')
                digest,_=hash_file(exe)
                if QMessageBox.question(self,'Доверие внешней программе',
                    f'Разрешить запуск выбранного сканера и его DLL с правами текущего пользователя?\n{exe}\nSHA-256: {digest}\n'
                    'Хеш фиксирует файл, но не подтверждает безопасность. Старый Open-CWS не поддерживается. '
                    'Продолжайте только после проверки источника пакета.',
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
                values['cws_executable'],values['cws_sha256']=exe,digest
            self.window.update_settings(values); self.load(self.window.settings)
            self.feedback.setText('Сохранено. Оформление применено; параметры задач — со следующего запуска. Активный мониторинг не перезапускался.')
        except (OSError,ValueError) as exc:
            QMessageBox.warning(self,'Настройки не сохранены',str(exc))


def heading(layout, title, subtitle):
    overline = QLabel('OSIP / SECURITY WORKSPACE')
    overline.setObjectName('Eyebrow')
    layout.addWidget(overline)
    label = QLabel(title); label.setObjectName('PageTitle'); layout.addWidget(label)
    label = QLabel(subtitle); label.setObjectName('Muted'); label.setWordWrap(True)
    layout.addWidget(label)


def button(text, slot=None, kind=''):
    item = QPushButton(text)
    item.setMinimumHeight(44)
    if kind:
        item.setObjectName(kind)
    if slot:
        item.clicked.connect(slot)
    return item


def card():
    widget = QFrame()
    widget.setObjectName('Card')
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(20, 20, 20, 20)
    layout.setSpacing(12)
    return widget, layout


def table(headers):
    item = QTableWidget(0, len(headers))
    item.setHorizontalHeaderLabels(headers)
    item.verticalHeader().hide()
    item.setAlternatingRowColors(False)
    item.setShowGrid(False)
    item.verticalHeader().setDefaultSectionSize(40)
    item.setMinimumHeight(170)
    item.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    item.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    item.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    item.horizontalHeader().setSectionResizeMode(len(headers) - 1, QHeaderView.ResizeMode.Stretch)
    item.setWordWrap(False)
    if headers[0] == 'Вердикт':
        item.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        item.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        item.setColumnWidth(0, 175)
        item.setColumnWidth(1, 285)
    return item


def fill_row(widget, values, color=None, data=None):
    row = widget.rowCount()
    widget.insertRow(row)
    for col, value in enumerate(values):
        cell = QTableWidgetItem(str(value))
        cell.setToolTip(str(value))
        if color and col == 0:
            cell.setForeground(QColor(color))
        if col == 0 and data is not None:
            cell.setData(Qt.ItemDataRole.UserRole, data)
        widget.setItem(row, col, cell)
    return row


class ScannerTab(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.worker = self.deleter = None
        self.findings = []
        self.running = False
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        heading(layout, 'Каждый файл под контролем.', 'Локальный сканер · SHA-256 и эвристика. Для полноценной антивирусной проверки откройте «Антивирус».')
        metrics = QHBoxLayout(); metrics.setSpacing(12)
        self.checked_metric = MetricCard('Проверено файлов', accent=True)
        self.threat_metric = MetricCard('Найдено совпадений')
        self.error_metric = MetricCard('Ошибки / пропуски')
        for metric in (self.checked_metric, self.threat_metric, self.error_metric): metrics.addWidget(metric, 1)
        layout.addLayout(metrics)
        box, body = card()
        row = QHBoxLayout()
        self.path = QLineEdit(window.settings['default_folder'])
        self.path.setPlaceholderText('Папка для проверки')
        self.browse = button('Обзор', self.choose)
        self.browse.setIcon(vector_icon('folder'))
        row.addWidget(self.path, 1)
        row.addWidget(self.browse)
        body.addLayout(row)
        row = QHBoxLayout()
        self.start = button('Начать сканирование', self.scan, 'Primary')
        self.start.setIcon(vector_icon('play', '#07140b'))
        self.stop = button('Остановить', self.cancel)
        self.stop.setEnabled(False)
        self.demo = button('Создать тесты', self.create_demo)
        for w in (self.start, self.stop, self.demo):
            row.addWidget(w)
        body.addLayout(row)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        body.addWidget(self.progress)
        self.summary = QLabel('Готов к проверке • 8 безопасных тестовых сигнатур')
        self.summary.setWordWrap(True)
        body.addWidget(self.summary)
        layout.addWidget(box)
        self.results = table(['Вердикт', 'Причина', 'Путь'])
        layout.addWidget(self.results, 2)
        row = QHBoxLayout()
        note = QLabel('Эвристика ≠ вирус. Удаление — только подтверждённых тестовых образцов.')
        note.setWordWrap(True)
        note.setObjectName('Muted')
        row.addWidget(note, 1)
        self.remove = button('Удалить найденное', self.delete, 'Danger')
        self.remove.setEnabled(False)
        row.addWidget(self.remove)
        layout.addLayout(row)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(500)
        self.console.setMaximumHeight(100)
        self.console.setPlaceholderText('Журнал локальной проверки · ожидание запуска…')
        layout.addWidget(self.console, 1)

    def choose(self):
        folder = QFileDialog.getExistingDirectory(self, 'Папка для сканирования', self.path.text())
        if folder:
            self.path.setText(folder)

    def create_demo(self):
        folder = QFileDialog.getExistingDirectory(self, 'Где создать папку OSIP-demo?')
        if not folder:
            return
        try:
            dest = Path(tempfile.mkdtemp(prefix='OSIP-demo-', dir=folder))
            for name, data in TEST_SAMPLES.items():
                (dest / (name + '.txt')).write_bytes(data)
            self.path.setText(str(dest))
            self.window.log(f'Созданы 8 безопасных образцов: {dest}', 'Успех')
        except OSError as exc:
            QMessageBox.warning(self, 'Тесты', str(exc))

    def scan(self):
        folder = os.path.abspath(os.path.expandvars(self.path.text().strip()))
        if not os.path.isdir(folder):
            QMessageBox.warning(self, 'Сканирование', 'Выберите существующую папку.')
            return
        self.findings.clear()
        self.results.setRowCount(0)
        self.console.clear()
        self.window.stats(0, 0)
        self.checked_metric.value.setText('0'); self.threat_metric.value.setText('0'); self.error_metric.value.setText('0')
        self.progress.setRange(0, 0)
        self.running = True
        self.lock(True)
        self.worker = ScanWorker(folder, self.window.settings)
        self.worker.log.connect(self.scan_log)
        self.worker.result.connect(self.found)
        self.worker.progress.connect(self.advance)
        self.worker.completed.connect(self.complete)
        self.worker.finished.connect(self.released)
        self.window.log(f'Проверка начата: {folder}', 'Информация')
        self.worker.start()

    def lock(self, busy):
        for item in (self.start, self.browse, self.demo, self.path):
            item.setEnabled(not busy)
        self.stop.setEnabled(busy and self.running)
        self.remove.setEnabled(not busy and any(f.kind == 'test' for f in self.findings))

    def cancel(self):
        if self.worker and self.worker.isRunning():
            self.worker.requestInterruption()
            self.stop.setEnabled(False)
            self.summary.setText('Остановка после текущего блока чтения…')

    def scan_log(self, text, status):
        self.console.appendPlainText(f'[{datetime.now():%H:%M:%S}] {text}')
        if status != 'Ход проверки':
            self.window.log(text, status)

    def found(self, finding):
        self.findings.append(finding)
        fill_row(self.results,
                 ['Тестовая сигнатура' if finding.kind == 'test' else 'Подозрительный',
                  finding.reason, finding.path], RED if finding.kind == 'test' else '#ffd166', finding)

    def advance(self, processed, total, checked, threats):
        self.progress.setRange(0, 100)
        self.progress.setValue(int(processed * 100 / total) if total else 0)
        self.summary.setText(f'Обработано: {processed} / {total}  •  SHA-256: {checked}  •  Находки: {threats}')
        self.window.stats(checked, threats)
        self.checked_metric.value.setText(f'{checked:,}'.replace(',', ' '))
        self.threat_metric.value.setText(str(threats))
        self.threat_metric.value.setStyleSheet('color: #ff5874;' if threats else 'color: #f2f5fa;')

    def complete(self, checked, threats, errors, cancelled):
        self.error_metric.value.setText(str(errors))
        state = 'Остановлено' if cancelled else 'Завершено'
        self.summary.setText(f'{state} • Проверено: {checked} • Находки: {threats} • Ошибки/пропуски: {errors}')
        self.window.log(self.summary.text(), 'Предупреждение' if cancelled or errors else 'Успех')
        self.window.stats(checked, threats)

    def released(self):
        self.running = False
        self.lock(False)
        self.worker.deleteLater()
        self.worker = None

    def delete(self):
        targets = [f for f in self.findings if f.kind == 'test']
        if not targets:
            return
        answer = QMessageBox.question(self, 'Необратимое удаление',
            f'Удалить {len(targets)} файлов с точным совпадением тестовой сигнатуры?\n'
            'Удаляются все тестовые образцы в списке, не только выделенные строки.\n'
            'SHA-256 будет повторно проверен. Корзина не используется.\n'
            'Эвристические находки останутся без изменений.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.lock(True)
        self.deleter = DeleteWorker(targets)
        self.deleter.outcome.connect(self.deleted)
        self.deleter.finished.connect(self.delete_finished)
        self.deleter.start()

    def deleted(self, finding, ok, text):
        self.window.log(f'{text}: {finding.path}', 'Успех' if ok else 'Ошибка')
        if ok:
            self.findings.remove(finding)
            for row in range(self.results.rowCount()):
                if self.results.item(row, 0).data(Qt.ItemDataRole.UserRole) == finding:
                    self.results.item(row, 0).setText('Удалено')
                    self.results.item(row, 0).setForeground(QColor(GREEN))
                    break

    def delete_finished(self):
        self.lock(False)
        self.deleter.deleteLater()
        self.deleter = None


class Shield(QWidget):
    def __init__(self):
        super().__init__()
        self.enabled = False
        self.phase = 0
        self.setMinimumSize(180, 170)
        self.timer = QTimer(self)
        self.timer.setInterval(40)
        self.timer.timeout.connect(self.tick)

    def tick(self):
        self.phase = (self.phase + 1) % 75
        self.update()

    def set_active(self, enabled):
        self.enabled = enabled
        if enabled and getattr(self, 'animate', True):
            self.timer.start()
        else:
            self.timer.stop()
        self.update()

    def paintEvent(self, event):
        from PySide6.QtGui import QPainterPath
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self.width() / 2, self.height() / 2
        if self.enabled:
            radius = 55 + self.phase / 75 * 22
            p.setPen(QPen(QColor(0, 255, 65, int(70 * (1 - self.phase / 75))), 2))
            p.drawEllipse(QRectF(cx - radius, cy - radius, 2 * radius, 2 * radius))
        path = QPainterPath()
        path.moveTo(cx, cy - 55)
        path.lineTo(cx + 43, cy - 38)
        path.lineTo(cx + 36, cy + 18)
        path.quadTo(cx + 24, cy + 43, cx, cy + 57)
        path.quadTo(cx - 24, cy + 43, cx - 36, cy + 18)
        path.lineTo(cx - 43, cy - 38)
        path.closeSubpath()
        p.setPen(QPen(QColor(GREEN if self.enabled else MUTED), 2.5))
        p.setBrush(QColor(0, 255, 65, 20) if self.enabled else QColor('#1a2530'))
        p.drawPath(path)
        p.setFont(QFont('Segoe UI', 34))
        p.drawText(QRectF(cx - 35, cy - 36, 70, 80), Qt.AlignmentFlag.AlignCenter,
                   '✓' if self.enabled else '—')


class ProtectionTab(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.worker = None
        self.roots = monitor_roots(window.settings)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        heading(layout, 'Защита в реальном времени', 'Настраиваемые папки и расширения · только уведомления, без автоматического удаления.')
        box, body = card()
        hero = QHBoxLayout(); hero.setSpacing(24)
        self.shield = Shield(); self.shield.setFixedSize(190, 190); hero.addWidget(self.shield)
        details = QVBoxLayout(); details.setSpacing(14)
        badge = QLabel('WATCHDOG / REAL-TIME'); badge.setObjectName('Eyebrow'); details.addWidget(badge)
        self.state = QLabel('Щит выключен'); self.state.setObjectName('HeroTitle'); details.addWidget(self.state)
        description = QLabel('Получайте уведомления о новых исполняемых файлах в чувствительных папках. '
                             'Решение о дальнейшей проверке остаётся за вами.')
        description.setWordWrap(True); description.setObjectName('Muted'); details.addWidget(description)
        self.toggle = button('Включить реальную защиту', self.change, 'Primary')
        details.addWidget(self.toggle, 0, Qt.AlignmentFlag.AlignLeft)
        hero.addLayout(details, 1); body.addLayout(hero); layout.addWidget(box)
        box, body = card()
        label = QLabel('ОБЛАСТЬ НАБЛЮДЕНИЯ'); label.setObjectName('Eyebrow'); body.addWidget(label)
        self.coverage = QLabel('Папки:\n' + '\n'.join(self.roots))
        self.coverage.setObjectName('Code'); self.coverage.setWordWrap(True)
        self.coverage.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.addWidget(self.coverage); layout.addWidget(box)
        warning = QLabel('Новый исполняемый файл не обязательно опасен. Мониторинг не блокирует запуск, '
                         'не проверяет содержимое и не заменяет Microsoft Defender. '
                         'Создание и перемещение отслеживаются рекурсивно; существующие файлы проверяйте сканером.')
        warning.setWordWrap(True)
        warning.setObjectName('Muted')
        layout.addWidget(warning)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(500)
        layout.addWidget(self.console, 1)

    def change(self):
        if self.worker:
            self.worker.requestInterruption()
            self.toggle.setEnabled(False)
            self.state.setText('Остановка наблюдателя…')
            return
        self.toggle.setEnabled(False)
        self.state.setText('Запуск наблюдателя…')
        self.roots = monitor_roots(self.window.settings)
        self.worker = MonitorWorker(self.roots, self.window.settings)
        self.worker.log.connect(self.log_event)
        self.worker.active.connect(self.set_active)
        self.worker.finished.connect(self.released)
        self.worker.start()

    def log_event(self, text, status):
        self.console.appendPlainText(f'[{datetime.now():%H:%M:%S}] {text}')
        self.window.log(text, status)

    def set_active(self, active, roots):
        self.shield.set_active(active)
        self.window.monitor_label.setText('● Наблюдение активно' if active else '○ Наблюдение выключено')
        self.state.setText('Щит активен' if active else 'Щит выключен')
        self.state.setStyleSheet('color: #00ff41;' if active else 'color: #f2f5fa;')
        if active:
            self.toggle.setEnabled(True)
            self.toggle.setText('Выключить защиту')
            self.coverage.setText('Фактически наблюдаются:\n' + roots)
            self.log_event('Наблюдение включено: ' + roots.replace('\n', '; '), 'Успех')
        else:
            self.window.log('Наблюдение выключено', 'Информация')

    def released(self):
        self.worker.deleteLater()
        self.worker = None
        self.toggle.setText('Включить реальную защиту')
        self.toggle.setEnabled(True)


class SystemTab(QWidget):
    SYSTEM = r'Software\Microsoft\Windows\CurrentVersion\Policies\System'
    EXPLORER = r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    ADVANCED = r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'

    def __init__(self, window):
        super().__init__()
        self.window = window
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        heading(layout, 'Системные ограничения', 'Точечные изменения реестра с резервной копией исходных значений.')
        grid = QGridLayout(); grid.setSpacing(16)
        operations = [
            ('Диспетчер задач', 'DisableTaskMgr', 'Разблокировать Диспетчер задач', ('delete', self.SYSTEM, 'DisableTaskMgr')),
            ('Редактор реестра', 'DisableRegistryTools', 'Разблокировать Редактор реестра', ('delete', self.SYSTEM, 'DisableRegistryTools')),
            ('Панель управления', 'NoControlPanel', 'Разблокировать Панель управления', ('delete', self.EXPLORER, 'NoControlPanel')),
            ('Скрытые файлы', 'Hidden + ShowSuperHidden', 'Показать скрытые файлы', ('hidden', self.ADVANCED, ''))]
        for index, (title, detail, action_text, operation) in enumerate(operations):
            box, body = card()
            top = QHBoxLayout()
            icon = QLabel(); icon.setPixmap(vector_icon('system' if index < 3 else 'folder', GREEN, 26).pixmap(26, 26))
            top.addWidget(icon); top.addStretch()
            status_label = QLabel('Не запускалось'); status_label.setObjectName('Muted'); top.addWidget(status_label)
            body.addLayout(top)
            title_label = QLabel(title); title_label.setObjectName('SectionTitle'); body.addWidget(title_label)
            label = QLabel(detail); label.setObjectName('Code'); label.setWordWrap(True); body.addWidget(label)
            description = QLabel('Политики пользователя и компьютера' if index < 3 else 'Проводник · текущий пользователь')
            description.setObjectName('Muted'); description.setWordWrap(True); body.addWidget(description)
            action = button(action_text)
            action.clicked.connect(lambda checked=False, op=operation, label=status_label: self.apply(op, label))
            body.addWidget(action)
            grid.addWidget(box, index // 2, index % 2)
        layout.addLayout(grid)
        note = QLabel('HKLM обычно требует запуска от администратора. Политики организации могут '
                      'восстановить ограничения: не обходите правила администратора. Для скрытых файлов '
                      'может потребоваться открыть новое окно Проводника. Системные файлы не изменяются.')
        note.setWordWrap(True)
        note.setObjectName('Muted')
        layout.addWidget(note)
        layout.addStretch()

    def backup(self, hive_name, key, name, view, value, value_type):
        self.window.data_dir.mkdir(parents=True, exist_ok=True)
        record = {'time': datetime.now().isoformat(), 'hive': hive_name, 'key': key,
                  'name': name, 'view': view, 'exists': value_type is not None,
                  'type': value_type, 'value': value.hex() if isinstance(value, bytes) else value,
                  'binary_hex': isinstance(value, bytes)}
        path = self.window.data_dir / 'registry-backup.jsonl'
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        return path

    def apply(self, operation, status_label):
        if not IS_WINDOWS:
            QMessageBox.warning(self, 'Система', 'Реестр доступен только в Windows.')
            return
        if QMessageBox.question(self, 'Подтверждение изменения реестра',
            'Изменить выбранные параметры? Исходные значения будут записаны в registry-backup.jsonl.\n'
            'Продолжайте только на компьютере, которым вам разрешено управлять.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        mode, key_path, value_name = operation
        changed, denied, absent = 0, [], 0
        is_64 = bool(os.environ.get('PROCESSOR_ARCHITEW6432')) or '64' in os.environ.get('PROCESSOR_ARCHITECTURE', '')
        views = [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY] if is_64 else [0]
        hives = [('HKCU', winreg.HKEY_CURRENT_USER)]
        if mode == 'delete':
            hives.append(('HKLM', winreg.HKEY_LOCAL_MACHINE))
        else:
            views = [0]
        for hive_name, hive in hives:
            for view in views:
                names = ['Hidden', 'ShowSuperHidden'] if mode == 'hidden' else [value_name]
                for name in names:
                    target = f'{hive_name}\\{key_path}\\{name} (view {view})'
                    try:
                        try:
                            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_QUERY_VALUE | view) as key:
                                try:
                                    old, value_type = winreg.QueryValueEx(key, name)
                                except FileNotFoundError:
                                    old, value_type = None, None
                        except FileNotFoundError:
                            old, value_type = None, None
                        if mode == 'delete' and value_type is None:
                            absent += 1
                            continue
                        if mode == 'hidden' and old == 1 and value_type == winreg.REG_DWORD:
                            absent += 1
                            continue
                        self.backup(hive_name, key_path, name, view, old, value_type)
                        with winreg.CreateKeyEx(hive, key_path, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | view) as key:
                            try:
                                current, current_type = winreg.QueryValueEx(key, name)
                            except FileNotFoundError:
                                current, current_type = None, None
                            if (current, current_type) != (old, value_type):
                                raise OSError('Параметр изменён другим процессом; повторите действие')
                            if mode == 'delete':
                                winreg.DeleteValue(key, name)
                            else:
                                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 1)
                        changed += 1
                        self.window.log(f'Изменён {target}; исходное значение сохранено', 'Успех')
                    except OSError as exc:
                        denied.append(f'{target}: {exc}')
                        self.window.log(denied[-1], 'Ошибка')
        if mode == 'hidden' and changed:
            try:
                from ctypes import wintypes
                send = ctypes.windll.user32.SendMessageTimeoutW
                send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                 wintypes.LPCWSTR, wintypes.UINT, wintypes.UINT,
                                 ctypes.POINTER(ctypes.c_size_t)]
                send.restype = wintypes.LPARAM
                result = ctypes.c_size_t()
                send(0xffff, 0x001A, 0, 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',
                     2, 1000, ctypes.byref(result))
            except (OSError, AttributeError):
                pass
        status_label.setText('⚠ Частично / ошибка' if denied else '✓ Готово')
        status_label.setStyleSheet('color: #ffd166;' if denied else f'color: {GREEN};')
        self.window.log(f'Реестр: изменено {changed}; уже настроено/отсутствует {absent}; ошибок {len(denied)}',
                        'Предупреждение' if denied else 'Успех')
        if denied:
            QMessageBox.warning(self, 'Не все параметры изменены', '\n'.join(denied) +
                '\n\nHKLM: могут потребоваться права администратора. Автоповышение отключено.')


class Donut(QWidget):
    def __init__(self):
        super().__init__()
        self.checked = self.threats = 0
        self.setMinimumSize(200, 170)
        self.setAccessibleName('Статистика последней проверки')

    def set_values(self, checked, threats):
        self.checked, self.threats = checked, threats
        self.setAccessibleDescription(f'Проверено {checked}; находок {threats}; без находок {checked - threats}. Не проверенные файлы не учитываются.')
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        diameter = min(self.width() - 36, self.height() - 36, 160)
        rect = QRectF((self.width() - diameter) / 2, (self.height() - diameter) / 2, diameter, diameter)
        p.setPen(QPen(QColor('#2b3b46'), 16))
        p.drawEllipse(rect)
        if self.checked:
            p.setPen(QPen(QColor(GREEN), 16))
            p.drawEllipse(rect)
            if self.threats:
                p.setPen(QPen(QColor(RED), 16))
                p.drawArc(rect, 90 * 16, -round(self.threats / self.checked * 360 * 16))
        p.setPen(QColor('#f0f5f7'))
        p.setFont(QFont('Segoe UI', 24, QFont.Weight.DemiBold))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(self.checked))


class LogsTab(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        heading(layout, 'Журнал и статистика', 'Размер локального журнала задаётся в настройках. Диаграмма — последняя локальная проверка в этой сессии.')
        box, body = card()
        row = QHBoxLayout()
        self.chart = Donut()
        row.addWidget(self.chart)
        self.counts = QLabel('Проверено: 0\nБез находок: 0\nНаходки: 0')
        self.counts.setObjectName('SectionTitle')
        row.addWidget(self.counts, 1)
        body.addLayout(row)
        hint = QLabel('Зелёный — без совпадений, красный — тестовая сигнатура или эвристика.\n'
                      '«Без находок» не гарантирует безопасность. Ошибки чтения не включены.')
        hint.setObjectName('Muted')
        hint.setWordWrap(True)
        body.addWidget(hint)
        layout.addWidget(box)
        self.events = table(['Дата', 'Статус', 'Событие'])
        layout.addWidget(self.events, 1)
        layout.addWidget(button('Очистить логи', self.clear))

    def update_stats(self, checked, threats):
        self.chart.set_values(checked, threats)
        self.counts.setText(f'Проверено: {checked}\nБез находок: {checked - threats}\nНаходки: {threats}')

    def add(self, entry):
        color = RED if entry['status'] in ('Ошибка', 'Обнаружено') else MUTED
        fill_row(self.events, [entry['time'], entry['status'], entry['event']], color)
        if self.events.rowCount() > MAX_LOGS:
            self.events.removeRow(0)
        self.events.scrollToBottom()

    def clear(self):
        if QMessageBox.question(self, 'Очистить журнал', 'Удалить сохранённые события? Резервные копии реестра останутся.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.events.setRowCount(0)
            self.window.entries.clear()
            self.window.save_logs()


STYLE = '''
QMainWindow, QScrollArea, QWidget#Canvas, QWidget#Page { background: #0c0f14; }
QWidget { color: #f2f5fa; font-family: "Segoe UI"; font-size: 14px; }
QLabel { background: transparent; }
QFrame#Sidebar { background: #10141b; border-right: 1px solid #29313d; }
QFrame#Card, QFrame#Metric { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #191f29,stop:1 #141a23); border: 1px solid #333e4e; border-radius: 12px; }
QFrame#EngineHero { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #182d23,stop:.65 #18212a,stop:1 #141b24); border: 1px solid #3b6950; border-radius: 12px; }
QFrame#Topbar { background: #0c0f14; border-bottom: 1px solid #29313d; }
QLabel#Eyebrow { color: #a5b3c5; font-size: 11px; font-weight: 600; letter-spacing: 1px; }
QLabel#PageTitle { font-size: 30px; font-weight: 700; letter-spacing: -1px; padding-bottom: 2px; }
QLabel#HeroTitle { font-size: 24px; font-weight: 600; }
QLabel#SectionTitle { font-size: 19px; font-weight: 600; }
QLabel#MetricValue { font-size: 30px; font-weight: 600; }
QLabel#Muted { color: #a7b2c2; font-size: 13px; }
QLabel#Code { color: #b6c5d7; font-family: Consolas; font-size: 12px; }
QLabel#Brand { font-size: 20px; font-weight: 800; letter-spacing: .5px; }
QLabel#Badge { color: #8bffab; background: #183022; border: 1px solid #427451; border-radius: 6px; padding: 7px 10px; font-size: 11px; font-weight: 600; }
QPushButton { background: #212a36; border: 1px solid #526277; border-radius: 8px; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #2b3848; border-color: #8295ad; }
QPushButton:pressed { background: #354558; }
QPushButton:focus, QLineEdit:focus { border: 2px solid #00ff41; }
QPushButton:disabled { background: #1a202a; color: #8c98a9; border-color: #35404e; }
QPushButton#Primary { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5aff84,stop:1 #00e63b); color: #06150b; border: 1px solid #56ff81; }
QPushButton#Primary:hover { background: #8affaa; }
QPushButton#Primary:disabled { background: #203b2c; color: #91b09c; border-color: #3a5948; }
QPushButton#Danger { color: #ff95a8; background: #2b1b25; border-color: #a64c62; }
QPushButton#Danger:disabled { background: #1c1c25; color: #a28e98; border-color: #4b3e49; }
QPushButton#Nav { text-align: left; border: 1px solid transparent; border-left: 3px solid transparent; background: transparent; padding: 13px 14px; font-weight: 500; color: #b2bfd0; }
QPushButton#Nav:checked { color: #adffbf; background: #1a3025; border-left: 3px solid #00ff41; }
QPushButton#Nav:hover { background: #212b38; color: #ffffff; }
QTabWidget::pane { background: #141a23; border: 1px solid #354153; border-radius: 8px; top: -1px; }
QTabBar::tab { background: #151e29; color: #a8b7ca; padding: 12px 18px; border-bottom: 2px solid #354153; }
QTabBar::tab:selected { color: #aaffbd; background: #1c2a24; border-bottom: 2px solid #00ff41; }
QTabBar::tab:hover { background: #263345; }
QComboBox, QSpinBox { background: #101720; border: 1px solid #526277; border-radius: 8px; padding: 9px 12px; min-height: 24px; }
QComboBox::down-arrow { image: url(:/osip/down.png); width: 12px; height: 12px; }
QSpinBox::up-arrow { image: url(:/osip/up.png); width: 10px; height: 10px; }
QSpinBox::down-arrow { image: url(:/osip/down.png); width: 10px; height: 10px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 28px; border: none; border-left: 1px solid #354153; }
QSpinBox QLineEdit { border: none; background: transparent; padding-left: 10px; }
QSpinBox::up-button { subcontrol-origin: border; subcontrol-position: top right; width: 24px; height: 22px; border: 1px solid #526277; border-top-right-radius: 8px; background: #2b3849; }
QSpinBox::down-button { subcontrol-origin: border; subcontrol-position: bottom right; width: 24px; height: 22px; border: 1px solid #526277; border-bottom-right-radius: 8px; background: #2b3849; }
QComboBox QAbstractItemView { background: #192330; selection-background-color: #284336; }
QCheckBox { color: #ccd6e3; spacing: 10px; padding: 6px 0px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #8495ac; border-radius: 3px; background: #152231; }
QCheckBox::indicator:checked { image: url(:/osip/check.png); background: #1a4a2c; border-color: #64ff8e; }
QLineEdit { background: #101720; border: 1px solid #526277; border-radius: 8px; padding: 11px; color: #e1eaf5; selection-background-color: #275b3d; }
QProgressBar { border: none; background: #303d4c; border-radius: 3px; min-height: 6px; max-height: 6px; font-size: 1px; }
QProgressBar::chunk { background: #00ef45; border-radius: 3px; }
QPlainTextEdit, QTableWidget { background: #121923; border: 1px solid #354153; border-radius: 10px; selection-background-color: #284336; selection-color: #ffffff; }
QPlainTextEdit { font-family: Consolas; font-size: 12px; color: #bccbdc; padding: 8px; }
QTableWidget::item { padding: 9px 12px; border-bottom: 1px solid #29323f; }
QTableWidget::item:selected { background: #243e31; }
QHeaderView::section { background: #1b2431; color: #adbdcf; border: none; border-bottom: 1px solid #3a485c; padding: 12px; font-size: 12px; font-weight: 600; }
QTableCornerButton::section { background: #1b2431; border: none; }
QScrollArea { border: none; }
QScrollBar:vertical { background: #121923; width: 8px; margin: 2px; }
QScrollBar::handle:vertical { background: #576a80; min-height: 30px; border-radius: 3px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QToolTip { color: #eef4f8; background: #243344; border: 1px solid #607888; padding: 5px; }
QMessageBox { background: #141c27; }
'''


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('OSIP-DEFEND • локальная защита')
        self.resize(1360, 960)
        self.setMinimumSize(1050, 740)
        self.closing = False
        self.entries = []
        base = os.environ.get('LOCALAPPDATA') or str(Path.home() / '.local' / 'share')
        self.data_dir = Path(base) / 'OSIP-DEFEND'
        self.settings_store = SettingsStore(self.data_dir)
        self.settings = self.settings_store.load()
        global MAX_LOGS
        MAX_LOGS = self.settings['log_limit']
        self.persistence_error = ''
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.persistence_error = str(exc)
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(700)
        self.save_timer.timeout.connect(self.save_logs)
        canvas = QWidget()
        canvas.setObjectName('Canvas')
        self.setCentralWidget(canvas)
        main = QHBoxLayout(canvas)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        sidebar = QFrame()
        self.sidebar = sidebar
        sidebar.setObjectName('Sidebar')
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 28, 16, 24)
        side.setSpacing(12)
        brand = QHBoxLayout()
        brand_icon = QLabel(); brand_icon.setPixmap(vector_icon('shield', GREEN, 30).pixmap(30, 30))
        brand.addWidget(brand_icon)
        logo = QLabel('OSIP<span style="color:#00ff41">·</span>DEFEND')
        logo.setObjectName('Brand'); brand.addWidget(logo); brand.addStretch()
        side.addLayout(brand)
        sub = QLabel('SECURITY WORKSPACE'); sub.setObjectName('Eyebrow'); side.addWidget(sub)
        side.addSpacing(36)
        label = QLabel('ИНСТРУМЕНТЫ'); label.setObjectName('Eyebrow'); side.addWidget(label)
        self.nav = []
        self.nav_icons = ['scan', 'shield', 'system', 'logs', 'engine', 'settings']
        for i, title in enumerate(['Сканер', 'Защита', 'Система', 'Журнал', 'Антивирус OSIP', 'Настройки']):
            item = button(title)
            item.setIcon(vector_icon(self.nav_icons[i])); item.setIconSize(QSize(22, 22))
            item.setObjectName('Nav'); item.setCheckable(True)
            item.clicked.connect(lambda checked=False, index=i: self.switch(index))
            self.nav.append(item); side.addWidget(item)
        side.addStretch()
        self.monitor_label = QLabel('○ Наблюдение выключено')
        self.monitor_label.setWordWrap(True)
        self.monitor_label.setObjectName('Muted')
        side.addWidget(self.monitor_label)
        self.processes = QLabel()
        self.processes.setObjectName('Muted')
        side.addWidget(self.processes)
        info = QLabel('OSIP MULTI-ENGINE\nЛокальная защита\n\nOSIP-DEFEND  3.0')
        info.setWordWrap(True)
        info.setObjectName('Muted')
        side.addWidget(info)
        main.addWidget(sidebar)
        right = QVBoxLayout()
        right.setContentsMargins(28, 18, 28, 16)
        topbar = QFrame(); topbar.setObjectName('Topbar')
        topl = QHBoxLayout(topbar); topl.setContentsMargins(4, 0, 4, 14)
        workspace = QLabel('Центр безопасности'); workspace.setObjectName('Muted'); topl.addWidget(workspace)
        topl.addStretch()
        badge = QLabel('WINDOWS  /  DESKTOP'); badge.setObjectName('Eyebrow'); topl.addWidget(badge)
        right.addWidget(topbar)
        right.addSpacing(8)
        self.stack = QStackedWidget()
        self.logs = LogsTab(self)
        self.scanner = ScannerTab(self)
        self.protection = ProtectionTab(self)
        self.system = SystemTab(self)
        self.defender = AntivirusTab(self)
        self.settings_tab = SettingsTab(self)
        for page in (self.scanner, self.protection, self.system, self.logs, self.defender, self.settings_tab):
            page.setObjectName('Page')
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            self.stack.addWidget(scroll)
        right.addWidget(self.stack, 1)
        self.footer = QLabel('OSIP 3.0    /    MULTI-ENGINE    /    Режим проверки: только отчёт')
        self.footer.setObjectName('Muted')
        right.addWidget(self.footer)
        main.addLayout(right, 1)
        self.nav[0].setChecked(True)
        self.nav[0].setIcon(vector_icon('scan', GREEN))
        self.effect = QGraphicsOpacityEffect(self.stack)
        self.stack.setGraphicsEffect(self.effect)
        self.animation = QPropertyAnimation(self.effect, b'opacity', self)
        self.animation.setDuration(190)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.effect.setOpacity(1)
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.refresh_processes)
        self.process_timer.start(5000)
        self.refresh_processes()
        self.load_logs()
        self.log('OSIP-DEFEND 3.0: локальный движок + Microsoft Defender + адаптер Open-CWS/ClamAV.', 'Информация')
        if self.settings_store.error:
            self.log('Не удалось прочитать настройки; применены безопасные значения: ' + self.settings_store.error, 'Ошибка')
        self.apply_preferences()
        if self.persistence_error:
            self.footer.setText('Ошибка локального хранилища: ' + self.persistence_error)
        self.shutdown_timer = QTimer(self)
        self.shutdown_timer.setInterval(100)
        self.shutdown_timer.timeout.connect(self.check_shutdown)

    def switch(self, index):
        if self.stack.currentIndex() == index:
            return
        self.animation.stop()
        self.stack.setCurrentIndex(index)
        for i, item in enumerate(self.nav):
            item.setChecked(i == index)
            item.setIcon(vector_icon(self.nav_icons[i], GREEN if i == index else '#9aa7b8'))
        if not self.settings['animations']:
            self.effect.setOpacity(1); return
        self.animation.setStartValue(.35)
        self.animation.setEndValue(1.0)
        self.animation.start()

    def apply_preferences(self):
        global MAX_LOGS
        MAX_LOGS = self.settings['log_limit']
        self.sidebar.setFixedWidth(220 + max(0, self.settings['font_size'] - 14) * 8)
        palette = QPalette()
        for role, value in [(QPalette.ColorRole.Window, '#0c0f14'), (QPalette.ColorRole.Base, '#101720'),
                            (QPalette.ColorRole.AlternateBase, '#141b24'), (QPalette.ColorRole.Text, '#f2f5fa'),
                            (QPalette.ColorRole.WindowText, '#f2f5fa'), (QPalette.ColorRole.Button, '#263345'),
                            (QPalette.ColorRole.ButtonText, '#eef4f8'), (QPalette.ColorRole.Highlight, '#208640'),
                            (QPalette.ColorRole.HighlightedText, '#ffffff')]: palette.setColor(role, QColor(value))
        QApplication.instance().setPalette(palette)
        self.defender.console.setMaximumBlockCount(MAX_LOGS)
        self.entries = self.entries[-MAX_LOGS:]
        while self.logs.events.rowCount() > MAX_LOGS: self.logs.events.removeRow(0)
        QApplication.instance().setStyleSheet(STYLE.replace('font-size: 14px;', f"font-size: {self.settings['font_size']}px;", 1))
        self.protection.shield.animate = self.settings['animations']
        self.protection.shield.set_active(self.protection.shield.enabled)
        if not self.settings['animations']:
            self.animation.stop(); self.effect.setOpacity(1)

    def update_settings(self, values):
        old = self.settings
        self.settings = self.settings_store.save(values)
        self.apply_preferences()
        if old['default_folder'] != self.settings['default_folder']:
            if not self.scanner.worker and not self.scanner.deleter:
                self.scanner.path.setText(self.settings['default_folder'])
            if not self.defender.worker: self.defender.path.setText(self.settings['default_folder'])
        if not self.protection.worker:
            self.protection.roots = monitor_roots(self.settings)
            self.protection.coverage.setText('Папки:\n' + '\n'.join(self.protection.roots))
        if not self.defender.worker:
            self.defender.mode.setCurrentIndex({'both':0,'defender':1,'cws':2}[self.settings['engine_mode']])
            self.defender.detect()
        self.log('Настройки сохранены. Новые параметры задач применятся при следующем запуске.', 'Успех')
        self.save_logs()

    def refresh_processes(self):
        try:
            self.processes.setText(f'Процессов: {len(psutil.pids())}')
        except (psutil.Error, OSError):
            self.processes.setText('Процессы: недоступно')

    def stats(self, checked, threats):
        self.logs.update_stats(checked, threats)

    def log(self, text, status='Информация'):
        entry = {'time': datetime.now().astimezone().isoformat(timespec='seconds'),
                 'status': status, 'event': str(text)}
        self.entries.append(entry)
        self.entries = self.entries[-MAX_LOGS:]
        self.logs.add(entry)
        if not self.save_timer.isActive():
            self.save_timer.start()

    def load_logs(self):
        path = self.data_dir / 'events.json'
        try:
            if not path.exists():
                return
            if path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError('Журнал больше 16 МиБ')
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, list):
                raise ValueError('Неверный формат журнала')
            for entry in data[-MAX_LOGS:]:
                if isinstance(entry, dict) and all(isinstance(entry.get(k), str) for k in ('time', 'status', 'event')):
                    self.entries.append(entry)
                    self.logs.add(entry)
        except (OSError, ValueError) as exc:
            self.log(f'Журнал не прочитан: {exc}', 'Ошибка')

    def save_logs(self):
        temporary = None
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=self.data_dir,
                                             prefix='events-', suffix='.tmp', delete=False) as stream:
                temporary = stream.name
                json.dump(self.entries, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.data_dir / 'events.json')
        except OSError as exc:
            self.footer.setText('Журнал не сохранён: ' + str(exc))
        finally:
            if temporary and os.path.exists(temporary):
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def jobs(self):
        return [job for job in (self.scanner.worker, self.scanner.deleter, self.protection.worker, self.defender.worker)
                if job is not None and job.isRunning()]

    def closeEvent(self, event):
        jobs = self.jobs()
        if jobs:
            if not self.closing and QMessageBox.question(self, 'Завершение работы',
                'Завершить задачи и закрыть приложение? При проверке Defender завершается только наш CLI; работа службы может продолжаться.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.closing = True
            for job in jobs:
                job.requestInterruption()
            self.centralWidget().setEnabled(False)
            self.footer.setText('Остановка потоков… Ожидание завершения файлового ввода-вывода.')
            self.shutdown_timer.start()
            event.ignore()
        else:
            self.shutdown_timer.stop()
            self.process_timer.stop()
            self.save_timer.stop()
            self.save_logs()
            event.accept()

    def check_shutdown(self):
        if not self.jobs():
            self.shutdown_timer.stop()
            self.close()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('OSIP-DEFEND')
    app.setOrganizationName('OSIP')
    app.setStyle('Fusion')
    app.setFont(QFont('Segoe UI', 10))
    app.setStyleSheet(STYLE)
    if not IS_WINDOWS:
        QMessageBox.critical(None, 'OSIP-DEFEND', 'Приложение предназначено для Windows 10/11.\n'
                             'Движок можно проверить командой --self-test.')
        return 1
    from PySide6.QtCore import QLockFile, QStandardPaths
    lock_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
    try:
        Path(lock_dir).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        QMessageBox.critical(None, 'OSIP-DEFEND', f'Не удалось создать локальное хранилище: {exc}')
        return 1
    lock = QLockFile(str(Path(lock_dir) / 'instance.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, 'OSIP-DEFEND', 'Приложение уже запущено либо файл блокировки недоступен.')
        return 1
    window = MainWindow()
    window.show()
    result = app.exec()
    lock.unlock()
    return result


if __name__ == '__main__':
    sys.exit(main())
