"""Bounded reads and single-file publication in a trusted, cooperative directory.

Staging is on the destination volume, file contents are fsynced before publication,
and POSIX directory fsync errors propagate. Windows has no portable directory
fsync here: publication is atomic, but power-loss durability of its directory entry
is not guaranteed. Windows chmod is not an ACL privacy guarantee. These checks are
not an isolation boundary against a hostile process swapping ancestor directories.
"""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import stat
import tempfile


class CrossVolumeError(RuntimeError):
    pass


def _same_volume(a: str, b: str) -> bool:
    """True if paths a and b live on the same device/volume."""
    da = os.path.dirname(os.path.abspath(a)) or "."
    db = os.path.dirname(os.path.abspath(b)) or "."
    # Walk up to an existing ancestor (dest dir may not exist yet in dry tests).
    while not os.path.exists(da) and os.path.dirname(da) != da:
        da = os.path.dirname(da)
    while not os.path.exists(db) and os.path.dirname(db) != db:
        db = os.path.dirname(db)
    try:
        return os.stat(da).st_dev == os.stat(db).st_dev
    except OSError:
        return False


def assert_same_volume(tmp_path: str, dest_path: str) -> None:
    if not _same_volume(tmp_path, dest_path):
        raise CrossVolumeError(
            "refusing non-atomic cross-volume rename: %s -> %s" % (tmp_path, dest_path)
        )



class UnsafePathError(ValueError):
    """A path has unsafe syntax, reparse components or an unexpected file type."""


class FileTooLargeError(ValueError):
    """A read would exceed the caller's byte limit."""


_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", re.I)


def validate_path(path, *, root=None) -> Path:
    """Validate lexical components and existing ancestors without following links.

    If supplied, root is also checked and containment is component-aware. Missing
    components are allowed for writes. Symlinks and Windows reparse points are not.
    """
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw or raw.startswith(("\\\\?\\", "\\\\.\\")):
        raise UnsafePathError("unsafe_path")
    candidate = Path(raw)
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    if any(p == ".." or ":" in p or p.rstrip(". ") != p or _RESERVED.fullmatch(p) for p in parts):
        raise UnsafePathError("unsafe_path")
    candidate = Path(os.path.abspath(candidate))
    if root is not None:
        base = validate_path(root)
        if not candidate.is_relative_to(base):
            raise UnsafePathError("outside_root")
    for part in reversed((candidate, *candidate.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise UnsafePathError("reparse_point")
        if part != candidate and not stat.S_ISDIR(info.st_mode):
            raise UnsafePathError("not_directory")
    return candidate


def _regular_or_missing(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise UnsafePathError("not_regular_file")
    return info


def _sync_directory(parent):
    if os.name == "nt":
        return
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _staged(path, data, mode):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise TypeError("data must be str or bytes")
    if not isinstance(mode, int) or not 0 <= mode <= 0o777:
        raise ValueError("invalid_mode")
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_path(path)
    fd, name = tempfile.mkstemp(prefix=".fleet-guards-", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            # Do not suppress chmod failures; a successful write must satisfy its
            # platform's permission operation before its contents are published.
            os.chmod(temp, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        validate_path(path)
        _regular_or_missing(path)
        yield temp
    finally:
        if os.name == "nt":
            try:
                # A losing create may leave a read-only staged file. Only this
                # unpublished file needs its Windows read-only bit cleared.
                info = temp.lstat()
                if stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400:
                    os.chmod(temp, mode | stat.S_IWRITE)
            except FileNotFoundError:
                pass
        temp.unlink(missing_ok=True)


def atomic_replace(path, data, mode: int = 0o600) -> None:
    """Replace a regular file with complete str/bytes; create missing parents.

    Failures before publication preserve the previous file. An error after rename
    (directory fsync or cleanup) may mean publication occurred; callers must inspect
    their transaction state rather than assume this is an atomic compare-and-swap.
    """
    path = validate_path(path)
    _regular_or_missing(path)
    with _staged(path, data, mode) as temp:
        os.replace(temp, path)
        _sync_directory(path.parent)


def create_no_replace(path, data, mode: int = 0o600) -> bool:
    """Publish complete bytes only if the destination is absent; False on collision.

    Uses the same implementation as create_no_replace_with_identity.
    """
    return create_no_replace_with_identity(path, data, mode) is not None


def create_no_replace_with_identity(path, data, mode: int = 0o600):
    """Return the opened staging object's [device, inode], or None on collision.

    Identity is obtained BEFORE publication, never adopted from the destination.
    Windows pins parents and renames the opened handle with write/delete exclusion.
    POSIX links the staging pathname in a trusted cooperative directory; this does
    not exclude hostile staging swaps or later inode reuse. Callers must compare
    the destination to this evidence and preserve ambiguity after process loss.
    A return or exception after the OS operation does not guarantee the path still
    names the published object. No extra durable hard-link anchor is retained.
    """
    path = validate_path(path)
    if _regular_or_missing(path) is not None:
        return None
    with _staged(path, data, mode) as temp:
        try:
            if os.name == "nt":
                with _pin_parents(temp, path), _file_handle(temp) as handle:
                    with _duplicate_reader(handle) as stream:
                        opened = _stat_identity(os.fstat(stream.fileno()))
                    _rename_handle(handle, path)
            else:
                fd = os.open(temp, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                with os.fdopen(fd, 'rb') as stream:
                    opened = _stat_identity(os.fstat(stream.fileno()))
                    os.link(temp, path)
        except FileExistsError:
            return None
        _sync_directory(path.parent)
        return opened


@contextmanager
def _duplicate_reader(handle):
    """Read a native handle without transferring its caller's ownership."""
    import ctypes
    import msvcrt
    kernel = _kernel()
    duplicate = ctypes.c_void_p()
    current = kernel.GetCurrentProcess()
    if not kernel.DuplicateHandle(current, handle, current, ctypes.byref(duplicate), 0, False, 2):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel.CloseHandle(duplicate.value)
        raise
    with os.fdopen(fd, 'rb') as stream:
        yield stream


def read_bounded(path, limit: int) -> bytes:
    """Read at most limit bytes from a regular file; reject observed changes."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("invalid_limit")
    path = validate_path(path)
    before = _regular_or_missing(path)
    if before is None:
        raise FileNotFoundError(path)
    if before.st_size > limit:
        raise FileTooLargeError("file_too_large")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise UnsafePathError("file_changed")
        # Bound each allocation independently of the caller's acceptance limit.
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(stream.fileno())
    if len(data) > limit:
        raise FileTooLargeError("file_too_large")
    validate_path(path)
    current = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after) or identity(after) != identity(current) or len(data) != after.st_size:
        raise UnsafePathError("file_changed")
    return data


def identity(path):
    return _stat_identity(Path(path).stat(follow_symlinks=False))


def _stat_identity(info):
    if not stat.S_ISREG(info.st_mode):
        raise OSError('nonregular_curation_file')
    if info.st_ino == 0:
        raise OSError('unavailable_curation_file_identity')
    return [info.st_dev, info.st_ino]


# The public name shares the same directory durability implementation.
sync_directory = _sync_directory


def link_no_replace(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with _pin_parents(source, destination):
        try:
            os.link(source, destination)
        except FileExistsError:
            return False
        sync_directory(destination.parent)
        return True


def detach_if_matches(path, expected, expected_identity, retained):
    """Return False on conflict/unavailable exclusion; leave all evidence intact.

    On success the original entry is now at retained (which must be absent).
    The caller must use no-replace to fill the vacancy and journal both steps.
    Ordinary Windows write, rename and delete opens are excluded throughout
    validation and the handle rename, including through other hard links.
    """
    if os.name != 'nt':
        return False
    try:
        with _pin_parents(path, retained), _file_handle(path) as handle:
            with _duplicate_reader(handle) as stream:
                info = os.fstat(stream.fileno())
                if ([info.st_dev, info.st_ino] != expected_identity
                        or not stat.S_ISREG(info.st_mode) or stream.read() != expected):
                    return False
            _rename_handle(handle, retained)
        return True
    except OSError:
        # This fixed result is consumed as a conflict, never as success.
        return False


def _kernel():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    return kernel


@contextmanager
def _file_handle(path, *, directory=False, read_only=False, delete=False):
    import ctypes
    kernel = _kernel()
    # Directory handles deny rename/delete of every ancestor. File handles
    # deny both write and delete sharing; rename uses this same handle.
    access, sharing = (0x80, 3) if directory else (0x80000000 | 0x10000, 1)
    if read_only:
        access &= ~0x10000
    if delete:
        access |= 0x10000
    handle = kernel.CreateFileW(str(Path(path).absolute()), access, sharing, None, 3,
                                0x00200000 | (0x02000000 if directory else 0), None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if Path(path).lstat().st_file_attributes & 0x400:
            raise OSError('linked_curation_file')
        yield handle
    finally:
        kernel.CloseHandle(handle)


@contextmanager
def exclude_file_writes(paths):
    """Hold Windows write/delete exclusion on every member until context exit.

    Read-only access permits normal readback while share flags exclude ordinary
    writes (including through hard links) and deletion/replacement of each held
    pathname. NTFS may unlink an unheld alias without deleting the held member.
    Unsupported platforms fail before the caller may publish anything.
    """
    if os.name != 'nt':
        raise OSError('file_exclusion_unavailable')
    paths = [validate_path(path) for path in paths]
    with ExitStack() as stack:
        stack.enter_context(_pin_parents(*paths))
        opened = {}
        for path in paths:
            handle = stack.enter_context(_file_handle(path, read_only=True))
            with _duplicate_reader(handle) as stream:
                opened[path] = _stat_identity(os.fstat(stream.fileno()))
        yield opened


def delete_if_identity_matches(path, expected_identity, *, directory=False):
    """Delete only the opened owned object; directories must already be empty.

    Content is intentionally not an ownership test: an owned hard link may have
    changed through its now-active target. Foreign replacements are preserved.
    """
    if os.name != 'nt':
        return False
    import ctypes
    try:
        path = validate_path(path)
        with _pin_parents(path), _file_handle(path, directory=directory, delete=True) as handle:
            info = path.lstat()
            correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            if [info.st_dev, info.st_ino] != expected_identity or not correct_type:
                return False
            disposition = ctypes.c_int(1)
            if not _kernel().SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        return True
    except OSError:
        return False


@contextmanager
def _pin_parents(*paths):
    with ExitStack() as stack:
        if os.name == 'nt':
            parents = {p for path in paths for p in Path(path).absolute().parents}
            for parent in sorted(parents, key=lambda p: len(p.parts)):
                stack.enter_context(_file_handle(parent, directory=True))
        yield


def _rename_handle(handle, retained):
    import ctypes
    from ctypes import wintypes
    name = str(Path(retained).absolute())
    size = len(name.encode('utf-16-le'))

    class RenameInfo(ctypes.Structure):
        _fields_ = [('ReplaceIfExists', ctypes.c_ubyte), ('RootDirectory', wintypes.HANDLE),
                    ('FileNameLength', wintypes.DWORD), ('FileName', wintypes.WCHAR * (size // 2 + 1))]

    info = RenameInfo()
    info.FileNameLength, info.FileName = size, name
    if not _kernel().SetFileInformationByHandle(handle, 3, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
