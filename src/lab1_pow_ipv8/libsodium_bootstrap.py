"""Runtime libsodium bootstrap for IPv8/libnacl."""

from __future__ import annotations

import ctypes.util
import os
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

LIBSODIUM_WINDOWS_URL = (
    "https://download.libsodium.org/libsodium/releases/"
    "libsodium-1.0.22-stable-msvc.zip"
)
VENDOR_DIR = Path(__file__).resolve().parents[2] / "vendor" / "libsodium"
EXTRACT_DIR = VENDOR_DIR / "extract"
CACHE_DIR = VENDOR_DIR / "cache"
CACHE_ARCHIVE = CACHE_DIR / "libsodium-download"
BIN_DIR = VENDOR_DIR / "bin"


def ensure_libsodium() -> None:
    """
    Ensure libsodium is available to libnacl/IPv8.

    On Windows, download the official MSVC bundle into vendor/ and prepend
    its DLL location to PATH if libsodium isn't already available.
    """
    if os.environ.get("LAB1_SKIP_LIBSODIUM_BOOTSTRAP"):
        return

    if os.name == "nt":
        existing_dir = _find_existing_windows_dll_dir()
        if existing_dir is not None:
            _prepend_path(existing_dir)
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(existing_dir))
            return

        dll_dir = _ensure_windows_libsodium()
        _prepend_path(dll_dir)
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(dll_dir))
        return

    if _has_libsodium_available():
        return

    # macOS/Linux: use system libsodium or optional override URL.
    if _find_system_libsodium():
        return

    if _try_download_from_env_url():
        _prepend_shared_library_paths(BIN_DIR)
        if _find_system_libsodium() or _has_shared_lib_in_dir(BIN_DIR):
            return

    raise RuntimeError(
        "libsodium was not found. This project tries a local runtime bootstrap "
        "to keep your system PATH clean, but no system library was detected and "
        "no compatible binary could be downloaded.\n"
        "Fix: install libsodium via your OS package manager (brew/apt/yum/port/conda), "
        "or set LIBSODIUM_DIR to a folder containing the shared library, or set "
        "LIBSODIUM_URL to a direct download of a prebuilt binary archive."
    )


def _has_libsodium_available() -> bool:
    if _find_system_libsodium():
        return True
    if os.name == "nt":
        for path in _candidate_dll_dirs():
            if (Path(path) / "libsodium.dll").exists():
                return True
    else:
        for path in _candidate_dll_dirs():
            if _has_shared_lib_in_dir(Path(path)):
                return True
    return False


_SYSTEM_LIB_SEARCH_DIRS: tuple[str, ...] = (
    "/opt/homebrew/lib",   # Apple Silicon Homebrew
    "/usr/local/lib",      # Intel Homebrew / manual installs
    "/usr/lib",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
)

_SODIUM_DYLIB_NAMES: tuple[str, ...] = (
    "libsodium.dylib",
    "libsodium.so",
    "libsodium.so.26",
    "libsodium.so.23",
)


def _patch_find_library_for_sodium(full_path: str) -> None:
    """
    Monkey-patch ctypes.util.find_library so downstream consumers (libnacl)
    resolve 'sodium' to the full path we already found.  Called once.
    """
    import ctypes.util as _cu

    _orig = _cu.find_library

    def _patched(name: str) -> str | None:
        if name == "sodium":
            return full_path
        return _orig(name)

    _cu.find_library = _patched


def _find_system_libsodium() -> bool:
    if ctypes.util.find_library("sodium"):
        return True
    for directory in _SYSTEM_LIB_SEARCH_DIRS:
        p = Path(directory)
        for name in _SODIUM_DYLIB_NAMES:
            candidate = p / name
            if candidate.exists():
                _patch_find_library_for_sodium(str(candidate))
                return True
    return False


def _candidate_dll_dirs() -> Iterable[Path]:
    env_dir = os.environ.get("LIBSODIUM_DIR")
    if env_dir:
        yield Path(env_dir)
    yield BIN_DIR

    for path in os.environ.get("PATH", "").split(os.pathsep):
        if path:
            yield Path(path)


def _find_existing_windows_dll_dir() -> Path | None:
    for path in _candidate_dll_dirs():
        dll_path = Path(path) / "libsodium.dll"
        if dll_path.exists():
            return Path(path)
    return None


def _ensure_windows_libsodium() -> Path:
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    archive_path = CACHE_ARCHIVE.with_suffix(".zip")
    url = os.environ.get("LIBSODIUM_URL", LIBSODIUM_WINDOWS_URL)

    if not archive_path.exists():
        _download_file(url, archive_path)

    if not any(EXTRACT_DIR.rglob("libsodium.dll")):
        _extract_archive(archive_path, EXTRACT_DIR)

    dll_path = _select_windows_dll(EXTRACT_DIR)
    target_dll = BIN_DIR / "libsodium.dll"
    if not target_dll.exists():
        target_dll.write_bytes(dll_path.read_bytes())

    return BIN_DIR


def _select_windows_dll(search_root: Path) -> Path:
    candidates = list(search_root.rglob("libsodium.dll"))
    if not candidates:
        raise RuntimeError("Downloaded libsodium archive did not contain libsodium.dll")

    def score(path: Path) -> tuple[int, int]:
        parts = {p.lower() for p in path.parts}
        return (int("x64" in parts), int("release" in parts))

    candidates.sort(key=score, reverse=True)
    return candidates[0]


def _try_download_from_env_url() -> bool:
    url = os.environ.get("LIBSODIUM_URL")
    if not url:
        return False

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    suffix = Path(url).suffix
    if suffix == ".gz" and url.endswith(".tar.gz"):
        archive_path = CACHE_ARCHIVE.with_suffix(".tar.gz")
    elif suffix == ".bz2" and url.endswith(".tar.bz2"):
        archive_path = CACHE_ARCHIVE.with_suffix(".tar.bz2")
    elif suffix == ".zip":
        archive_path = CACHE_ARCHIVE.with_suffix(".zip")
    else:
        archive_path = CACHE_ARCHIVE.with_suffix(suffix)

    if not archive_path.exists():
        _download_file(url, archive_path)

    _extract_archive(archive_path, EXTRACT_DIR)
    lib_path = _select_shared_library(EXTRACT_DIR)
    target = BIN_DIR / lib_path.name
    if not target.exists():
        target.write_bytes(lib_path.read_bytes())
    return True


def _download_file(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url) as response:
        data = response.read()
    dest.write_bytes(data)


def _prepend_path(path: Path) -> None:
    os.environ["PATH"] = f"{path}{os.pathsep}{os.environ.get('PATH', '')}"


def _extract_archive(archive_path: Path, dest: Path) -> None:
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as archive:
            archive.extractall(dest)
        return

    if ".tar" in archive_path.name:
        with tarfile.open(archive_path, "r:*") as archive:
            archive.extractall(dest)
        return

    raise RuntimeError(f"Unsupported archive format: {archive_path.name}")


def _select_shared_library(search_root: Path) -> Path:
    names = ["libsodium.dylib", "libsodium.so", "libsodium.so.23", "libsodium.so.26"]
    candidates = []
    for name in names:
        candidates.extend(search_root.rglob(name))
    if not candidates:
        raise RuntimeError("No libsodium shared library found in archive")
    return candidates[0]


def _has_shared_lib_in_dir(path: Path) -> bool:
    for name in (
        "libsodium.dylib",
        "libsodium.so",
        "libsodium.so.23",
        "libsodium.so.26",
    ):
        if (path / name).exists():
            return True
    return False


def _prepend_shared_library_paths(path: Path) -> None:
    _prepend_path(path)
    if sys.platform == "darwin":
        os.environ["DYLD_LIBRARY_PATH"] = (
            f"{path}{os.pathsep}{os.environ.get('DYLD_LIBRARY_PATH', '')}"
        )
    elif os.name == "posix":
        os.environ["LD_LIBRARY_PATH"] = (
            f"{path}{os.pathsep}{os.environ.get('LD_LIBRARY_PATH', '')}"
        )
