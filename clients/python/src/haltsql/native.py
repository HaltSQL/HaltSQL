"""In-process verification with the compiled HaltSQL engine (no sidecar).

Platform wheels (``pip install haltsql`` on manylinux_2_28 x86_64/aarch64 and
macOS arm64) ship the engine as ``haltsql/_native/libhaltsql.so`` plus the
``haltsql`` CLI. :class:`NativeVerifier` uses one of two backends:

``"library"``
    Loads ``libhaltsql`` with :mod:`ctypes` and verifies in-process (tens of
    microseconds per call). ctypes releases the GIL during a call; the library
    serializes calls internally, so one verifier is safe to share between threads.
``"process"``
    Keeps one long-lived ``haltsql verify --policy FILE --batch`` child and talks
    JSONL over its pipes, one request at a time. Used when the library cannot be
    loaded (or when asked for).

``"auto"`` (the default) picks the library if it loads, else the process backend,
else raises :class:`~haltsql.HaltSQLUnavailable`.

Fail-closed, like every HaltSQL client: a missing engine, a crashed or hung child,
a timeout, a NULL result, unparseable output, a malformed verdict, or a verdict
for a different SQL string raises; nothing is ever treated as allowed. A request
the engine rejects (``{"error": ...}``) raises :class:`~haltsql.HaltSQLRequestError`.

Environment:

``HALTSQL_LIB``
    Explicit path of ``libhaltsql`` (used instead of the bundled one; it is not
    silently replaced by the bundled copy if it fails to load).
``HALTSQL_BIN``
    Explicit path of the ``haltsql`` CLI for the process backend.
``HALTSQL_NATIVE``
    Only consulted when ``backend="auto"``: ``0``/``process`` forces the process
    backend, ``library`` forces the library, ``auto`` (or unset) chooses.

fork(): the OCaml runtime inside ``libhaltsql`` does not survive ``fork()``. Once
the library has been used in a process, a forked child that calls it gets
:class:`~haltsql.HaltSQLUnavailable` instead of a crash. Create verifiers after
forking (e.g. in gunicorn's ``post_fork`` hook), or use ``backend="process"``.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, NoReturn, Optional, Sequence, Tuple

from .errors import HaltSQLUnavailable
from .local import NATIVE_DIR, _check_sql, _request_line, _resolve_binary, _to_verdict
from .models import Context, Verdict, validate_context

__all__ = [
    "NativeVerifier",
    "AsyncNativeVerifier",
    "load_library",
    "bundled_library",
    "ABI_VERSION",
]

#: The C ABI version (``HALTSQL_ABI_VERSION`` in ``native/include/haltsql.h``) this
#: module was written against. A library reporting anything else is refused.
ABI_VERSION = 1

_LIB_NAMES = ("libhaltsql.so", "libhaltsql.dylib")
_BACKENDS = ("auto", "library", "process")
_MAX_STDERR = 500
_MAX_LINE = 64 * 1024 * 1024
#: A SQL string that every policy denies (E_PARSE: NUL byte); the process backend
#: verifies it at start-up to learn the policy's name, version and mode.
_PROBE_SQL = "\x00"

_CLOSED_MSG = "NativeVerifier is closed"


def bundled_library() -> Optional[str]:
    """Path of ``libhaltsql`` shipped inside a platform wheel, or ``None``."""
    for name in _LIB_NAMES:
        path = os.path.join(NATIVE_DIR, name)
        if os.path.isfile(path):
            return path
    return None


# --------------------------------------------------------------------------- library


class _Library:
    """A loaded, ABI-checked ``libhaltsql`` with typed entry points.

    Every entry point that enters the OCaml runtime first checks that the runtime
    was started in this process (see the module docstring on fork()).
    """

    def __init__(self, path: str) -> None:
        try:
            cdll = ctypes.CDLL(path)
        except OSError as e:
            raise HaltSQLUnavailable(f"cannot load libhaltsql from {path}: {e}") from None
        try:
            abi = cdll.haltsql_abi_version
        except AttributeError:
            raise HaltSQLUnavailable(
                f"{path} is not libhaltsql (no haltsql_abi_version symbol)"
            ) from None
        abi.argtypes = []
        abi.restype = ctypes.c_int
        got = abi()
        if got != ABI_VERSION:
            raise HaltSQLUnavailable(
                f"{path} has ABI version {got}; this haltsql package needs ABI version "
                f"{ABI_VERSION} (install matching versions of the package and the library)"
            )
        c_char_pp = ctypes.POINTER(ctypes.c_void_p)
        sigs = {
            # Returned strings are c_void_p so they can be freed with haltsql_string_free.
            "haltsql_version": ([], ctypes.c_void_p),
            "haltsql_policy_load_file": ([ctypes.c_char_p, c_char_pp], ctypes.c_int64),
            "haltsql_policy_load_string": (
                [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, c_char_pp],
                ctypes.c_int64,
            ),
            "haltsql_policy_info": ([ctypes.c_int64], ctypes.c_void_p),
            "haltsql_policy_free": ([ctypes.c_int64], None),
            # sql and context are passed with explicit lengths: a bytes object handed
            # to a c_char_p parameter is passed as a pointer to its whole buffer, so
            # embedded NUL bytes reach the engine (which denies them) rather than
            # truncating the SQL to an innocent-looking prefix.
            "haltsql_verify": (
                [ctypes.c_int64, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t],
                ctypes.c_void_p,
            ),
            "haltsql_string_free": ([ctypes.c_void_p], None),
        }
        for name, (argtypes, restype) in sigs.items():
            try:
                fn = getattr(cdll, name)
            except AttributeError:
                raise HaltSQLUnavailable(f"{path} lacks the {name} entry point") from None
            fn.argtypes = argtypes
            fn.restype = restype
        self.path = path
        self._key = os.path.realpath(path)
        self._c = cdll

    # fork() guard ---------------------------------------------------------------

    def runtime_pid(self) -> Optional[int]:
        """The pid that started this library's OCaml runtime, or ``None`` if unused."""
        with _LIBS_LOCK:
            return _RUNTIME_PIDS.get(self._key)

    def _enter(self) -> None:
        pid = os.getpid()
        owner = _RUNTIME_PIDS.get(self._key)
        if owner is None:
            with _LIBS_LOCK:
                owner = _RUNTIME_PIDS.setdefault(self._key, pid)
        if owner != pid:
            raise HaltSQLUnavailable(
                f"libhaltsql was started in process {owner} and this is process {pid}: the "
                "OCaml runtime does not survive fork(). Create the verifier after forking "
                "(e.g. in gunicorn's post_fork hook) or use backend='process'."
            )

    # entry points ----------------------------------------------------------------

    def _take(self, ptr: Optional[int]) -> Optional[str]:
        """Copy and free a returned string; ``None`` for NULL."""
        if not ptr:
            return None
        try:
            raw = ctypes.string_at(ptr)
        finally:
            self._c.haltsql_string_free(ptr)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HaltSQLUnavailable("libhaltsql returned invalid UTF-8") from None

    def version(self) -> str:
        self._enter()
        out = self._take(self._c.haltsql_version())
        if out is None:
            raise HaltSQLUnavailable("libhaltsql returned no version")
        return out

    def _loaded(self, handle: int, err: ctypes.c_void_p) -> int:
        msg = self._take(err.value)
        if handle > 0:
            return int(handle)
        # The library could not load the policy: a configuration error, as with
        # LocalVerifier's missing-file check.
        raise ValueError(msg or "libhaltsql could not load the policy")

    def load_file(self, path: str) -> int:
        self._enter()
        err = ctypes.c_void_p()
        h = self._c.haltsql_policy_load_file(os.fsencode(path), ctypes.byref(err))
        return self._loaded(h, err)

    def load_string(self, doc: str, fmt: str, base_dir: Optional[str]) -> int:
        self._enter()
        data = doc.encode("utf-8")
        err = ctypes.c_void_p()
        h = self._c.haltsql_policy_load_string(
            data,
            len(data),
            fmt.encode("ascii"),
            os.fsencode(base_dir) if base_dir is not None else None,
            ctypes.byref(err),
        )
        return self._loaded(h, err)

    def policy_info(self, handle: int) -> Optional[Dict[str, Any]]:
        """``{"name", "version", "mode"}`` for a live handle, ``None`` for an unknown one."""
        self._enter()
        out = self._take(self._c.haltsql_policy_info(handle))
        if out is None:
            return None
        try:
            info = json.loads(out)
        except ValueError:
            raise HaltSQLUnavailable("libhaltsql returned malformed policy info") from None
        if not isinstance(info, dict):
            raise HaltSQLUnavailable("libhaltsql returned malformed policy info")
        return info

    def policy_free(self, handle: int) -> None:
        self._enter()
        self._c.haltsql_policy_free(handle)

    def verify(self, handle: int, sql: bytes, context: bytes) -> Optional[str]:
        self._enter()
        return self._take(self._c.haltsql_verify(handle, sql, len(sql), context, len(context)))


_LIBS: Dict[str, _Library] = {}
_RUNTIME_PIDS: Dict[str, int] = {}
_LIBS_LOCK = threading.Lock()


def load_library(path: Optional[str] = None) -> _Library:
    """Load (once per path, thread-safe) and ABI-check ``libhaltsql``.

    Search order: ``path``, then ``$HALTSQL_LIB``, then the copy bundled in the
    wheel. An explicit path is authoritative: if it fails to load, the bundled
    copy is not tried. Raises :class:`HaltSQLUnavailable` if no usable library
    is found.
    """
    if path is None:
        path = os.environ.get("HALTSQL_LIB") or bundled_library()
    if not path:
        raise HaltSQLUnavailable(
            "libhaltsql is not bundled with this haltsql installation (a pure-Python "
            "wheel) and HALTSQL_LIB is not set"
        )
    if not os.path.isfile(path):
        raise HaltSQLUnavailable(f"libhaltsql not found: {path}")
    key = os.path.realpath(path)
    with _LIBS_LOCK:
        lib = _LIBS.get(key)
        if lib is None:
            lib = _Library(path)
            _LIBS[key] = lib
        return lib


# --------------------------------------------------------------------------- backends

# A top-level `catalog: <path>` line: a plain scalar (no '#'), or a quoted scalar
# without escapes, optionally followed by a comment.
_YAML_CATALOG = re.compile(
    r"""^catalog:[ \t]+(?:"(?P<dq>[^"\\]*)"|'(?P<sq>[^']*)'|(?P<plain>[^\s#'"{\[|>&*!%@`][^#]*?))"""
    r"""(?:[ \t]+#.*)?[ \t]*$""",
    re.MULTILINE,
)


def _absolutize_catalog(doc: str, fmt: str, base: str) -> str:
    """Make a relative top-level ``catalog:`` path in a policy document absolute.

    JSON is parsed and re-serialized. YAML is not parsed (no YAML library is
    required and YAML 1.1 parsers disagree with the engine's): exactly one simple
    top-level ``catalog: path`` line is rewritten to a JSON-quoted absolute path
    (a valid YAML double-quoted scalar). Anything else is left untouched, so an
    unusual spelling surfaces as the engine's "cannot load catalog snapshot" error,
    never as a silently different policy.
    """
    if fmt == "json":
        try:
            data = json.loads(doc)
        except ValueError:
            return doc  # let the engine report the syntax error
        cat = data.get("catalog") if isinstance(data, dict) else None
        if isinstance(cat, str) and cat and not os.path.isabs(cat):
            data["catalog"] = os.path.join(base, cat)
            return json.dumps(data, ensure_ascii=False)
        return doc
    matches = list(_YAML_CATALOG.finditer(doc))
    if len(matches) != 1:
        return doc
    m = matches[0]
    cat = m.group("dq") if m.group("dq") is not None else m.group("sq")
    if cat is None:
        cat = m.group("plain")
    if not cat or os.path.isabs(cat):
        return doc
    return doc[: m.start()] + "catalog: " + json.dumps(os.path.join(base, cat)) + doc[m.end():]



class _LibraryBackend:
    name = "library"

    def __init__(
        self,
        lib: _Library,
        policy_file: Optional[str],
        policy: Optional[str],
        policy_format: str,
        base_dir: Optional[str],
        verify_sql_hash: bool,
    ) -> None:
        self.lib = lib
        self.verify_sql_hash = verify_sql_hash
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._handle = 0
        if policy_file is not None:
            self._handle = lib.load_file(policy_file)
        else:
            assert policy is not None
            self._handle = lib.load_string(policy, policy_format, base_dir)

    def verify(self, sql: str, context: Dict[str, Any]) -> Verdict:
        h = self._handle
        if not h:
            raise HaltSQLUnavailable(_CLOSED_MSG)
        ctx = json.dumps(context, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        raw = self.lib.verify(h, sql.encode("utf-8"), ctx)
        if not self._handle:
            # close() raced with this call; the engine may have answered "unknown handle".
            raise HaltSQLUnavailable(_CLOSED_MSG)
        if raw is None:
            raise HaltSQLUnavailable("libhaltsql returned no result (out of memory or unusable)")
        try:
            data = json.loads(raw)
        except ValueError:
            raise HaltSQLUnavailable("libhaltsql returned a non-JSON result") from None
        return _to_verdict(data, sql, verify_sql_hash=self.verify_sql_hash, source="libhaltsql")

    def policy_info(self) -> Dict[str, Any]:
        h = self._handle
        if not h:
            raise HaltSQLUnavailable(_CLOSED_MSG)
        info = self.lib.policy_info(h)
        if info is None:
            raise HaltSQLUnavailable(_CLOSED_MSG if not self._handle else "unknown policy handle")
        return info

    def close(self) -> None:
        with self._lock:
            h, self._handle = self._handle, 0
        # Never call into the runtime from a forked child: the handle belongs to the
        # parent's runtime and the guard would raise anyway.
        if h and os.getpid() == self._pid:
            self.lib.policy_free(h)


class _ProcessBackend:
    """One long-lived ``haltsql verify --batch`` child, driven one request at a time.

    A child found dead *before* a request is sent is replaced transparently. If it
    dies, hangs past ``timeout`` or emits anything but the expected result line
    while a request is in flight, it is killed, the call raises
    :class:`HaltSQLUnavailable`, and the next call starts a fresh child.
    """

    name = "process"

    def __init__(
        self,
        binary: str,
        policy_file: Optional[str],
        policy: Optional[str],
        policy_format: str,
        base_dir: Optional[str],
        timeout: float,
        verify_sql_hash: bool,
    ) -> None:
        self.binary = binary
        self.timeout = timeout
        self.verify_sql_hash = verify_sql_hash
        self._lock = threading.Lock()
        self._proc: Optional["subprocess.Popen[bytes]"] = None
        self._stderr: Any = None
        self._rsel: Optional[selectors.BaseSelector] = None
        self._wsel: Optional[selectors.BaseSelector] = None
        self._buf = bytearray()
        self._next_id = 0
        self._pid = os.getpid()
        # The process that created the temp policy dir; only it may delete it (a forked
        # child closing its copy must not pull the file from under the parent's engine).
        self._owner_pid = os.getpid()
        self._closed = False
        self._tmpdir: Optional[str] = None
        self._last_exit: Optional[Tuple[int, str]] = None
        try:
            if policy_file is not None:
                self.policy_file = policy_file
            else:
                assert policy is not None
                self.policy_file = self._materialize(policy, policy_format, base_dir)
            self._info = self._probe()
        except BaseException:
            self.close()
            raise

    def _materialize(self, policy: str, fmt: str, base_dir: Optional[str]) -> str:
        """Write an in-memory policy to a private temp file (0700 dir, 0600 file) kept
        for the verifier's lifetime.

        The CLI resolves a relative ``catalog:`` path against the policy file's
        directory, which would be the temp directory; it is rewritten to an absolute
        path against ``base_dir`` (default: the current directory), as the library
        backend resolves it. See :func:`_absolutize_catalog`.
        """
        self._tmpdir = tempfile.mkdtemp(prefix="haltsql-policy-")
        base = base_dir if base_dir is not None else os.getcwd()
        path = os.path.join(self._tmpdir, "policy." + fmt)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_absolutize_catalog(policy, fmt, base))
        return path

    # child management -------------------------------------------------------------

    def _argv(self) -> List[str]:
        return [self.binary, "verify", "--policy", self.policy_file, "--batch", "--jobs", "1"]

    def _spawn(self) -> "subprocess.Popen[bytes]":
        self._stderr = tempfile.TemporaryFile()
        try:
            proc = subprocess.Popen(
                self._argv(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                bufsize=0,
                close_fds=True,
            )
        except OSError as e:
            self._stderr.close()
            self._stderr = None
            raise HaltSQLUnavailable(f"could not run haltsql CLI: {type(e).__name__}") from None
        assert proc.stdin is not None and proc.stdout is not None
        os.set_blocking(proc.stdin.fileno(), False)
        os.set_blocking(proc.stdout.fileno(), False)
        self._rsel = selectors.DefaultSelector()
        self._rsel.register(proc.stdout.fileno(), selectors.EVENT_READ)
        self._wsel = selectors.DefaultSelector()
        self._wsel.register(proc.stdin.fileno(), selectors.EVENT_WRITE)
        self._buf = bytearray()
        self._proc = proc
        return proc

    def _stderr_text(self) -> str:
        if self._stderr is None:
            return ""
        try:
            self._stderr.seek(0)
            return self._stderr.read(64 * 1024).decode("utf-8", "replace").strip()
        except (OSError, ValueError):
            return ""

    def _kill(self) -> None:
        """Stop the child (if any) and remember how it ended for error messages."""
        proc, self._proc = self._proc, None
        for sel in (self._rsel, self._wsel):
            if sel is not None:
                sel.close()
        self._rsel = self._wsel = None
        self._buf = bytearray()
        if proc is None:
            return
        rc = proc.poll()
        if rc is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL ignored
                pass
        for f in (proc.stdin, proc.stdout):
            try:
                if f is not None:
                    f.close()
            except OSError:
                pass
        self._last_exit = (rc, self._stderr_text()) if rc is not None else None
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    def _fail(self, what: str, *, exiting: bool = False) -> NoReturn:
        """Kill the child and raise. ``exiting``: it closed a pipe, so give it a moment
        to exit by itself and report its real status (exit 2 = policy not loadable)."""
        proc = self._proc
        if exiting and proc is not None:
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                pass
        self._kill()
        msg = f"haltsql CLI {what}"
        if self._last_exit is not None:
            rc, err = self._last_exit
            msg += f" (exit status {rc}" + (f": {err[:_MAX_STDERR]}" if err else "") + ")"
        raise HaltSQLUnavailable(msg)

    def _live_child(self) -> "subprocess.Popen[bytes]":
        if self._closed:
            raise HaltSQLUnavailable(_CLOSED_MSG)
        if self._pid != os.getpid():
            # Forked: the pipes belong to the parent's child. Drop our copies without
            # killing it, and start our own.
            self._proc = None
            self._stderr = None
            self._rsel = self._wsel = None
            self._buf = bytearray()
            self._pid = os.getpid()
        proc = self._proc
        if proc is not None and proc.poll() is not None:
            self._kill()  # died between requests: nothing was in flight, replace it
            proc = None
        if proc is None:
            proc = self._spawn()
        return proc

    # protocol -----------------------------------------------------------------------

    def _write(self, proc: "subprocess.Popen[bytes]", data: bytes, deadline: float) -> None:
        assert proc.stdin is not None and self._wsel is not None
        fd = proc.stdin.fileno()
        view = memoryview(data)
        while view:
            try:
                n = os.write(fd, view)
            except BlockingIOError:
                n = 0
            except OSError:
                self._fail("exited", exiting=True)
            view = view[n:]
            if view:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail(f"timed out after {self.timeout}s")
                self._wsel.select(remaining)

    def _readline(self, proc: "subprocess.Popen[bytes]", deadline: float) -> bytes:
        assert proc.stdout is not None and self._rsel is not None
        fd = proc.stdout.fileno()
        while True:
            i = self._buf.find(b"\n")
            if i >= 0:
                line = bytes(self._buf[:i])
                del self._buf[: i + 1]
                return line
            if len(self._buf) > _MAX_LINE:
                self._fail("returned an oversized line")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(f"timed out after {self.timeout}s")
            if not self._rsel.select(remaining):
                continue
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                self._fail("exited", exiting=True)
            if not chunk:
                self._fail("exited", exiting=True)
            self._buf += chunk

    def _roundtrip(self, sql: str, context: Dict[str, Any]) -> Any:
        if not self._lock.acquire(timeout=self.timeout):
            raise HaltSQLUnavailable(f"haltsql CLI busy for more than {self.timeout}s")
        try:
            proc = self._live_child()
            rid = self._next_id
            self._next_id += 1
            deadline = time.monotonic() + self.timeout
            self._write(proc, (_request_line(rid, sql, context) + "\n").encode("utf-8"), deadline)
            line = self._readline(proc, deadline)
            if self._buf:
                self._fail("returned more than one line for one request")
            try:
                data = json.loads(line)
            except ValueError:
                self._fail("returned a non-JSON line")
            if not isinstance(data, dict) or data.get("id") != rid:
                self._fail("returned a result for a different request")
            return data
        finally:
            self._lock.release()

    def _probe(self) -> Dict[str, Any]:
        try:
            data = self._roundtrip(_PROBE_SQL, {})
        except HaltSQLUnavailable:
            if self._last_exit is not None and self._last_exit[0] == 2:
                # Exit status 2: the CLI could not load the policy (a configuration
                # error; the library backend raises ValueError for the same thing).
                err = self._last_exit[1]
                if err.startswith("haltsql: "):
                    err = err[len("haltsql: "):]
                raise ValueError(err or "haltsql could not load the policy") from None
            raise
        v = _to_verdict(data, _PROBE_SQL, verify_sql_hash=True, source="haltsql CLI")
        # Every policy denies the probe; a shadow-mode policy reports the denial in
        # shadow_reasons and allows.
        if v.allowed and not v.shadow_reasons:
            raise HaltSQLUnavailable("haltsql CLI allowed a SQL string containing a NUL byte")
        return {
            "name": v.policy.name,
            "version": v.policy.version,
            "mode": "shadow" if v.allowed else "enforce",
        }

    def verify(self, sql: str, context: Dict[str, Any]) -> Verdict:
        data = self._roundtrip(sql, context)
        return _to_verdict(data, sql, verify_sql_hash=self.verify_sql_hash, source="haltsql CLI")

    def policy_info(self) -> Dict[str, Any]:
        if self._closed:
            raise HaltSQLUnavailable(_CLOSED_MSG)
        return dict(self._info)

    def child_pid(self) -> Optional[int]:
        """The current child's pid (``None`` if none is running). For tests and ops."""
        proc = self._proc
        return proc.pid if proc is not None else None

    def close(self) -> None:
        self._closed = True
        with self._lock:
            proc = self._proc
            if proc is not None and self._pid == os.getpid():
                # Ask politely (EOF on stdin), then kill.
                try:
                    if proc.stdin is not None:
                        proc.stdin.close()
                    proc.wait(1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                self._kill()
            else:
                self._proc = None
            if self._tmpdir is not None:
                if self._owner_pid == os.getpid():
                    shutil.rmtree(self._tmpdir, ignore_errors=True)
                self._tmpdir = None


# --------------------------------------------------------------------------- selection


def _env_backend() -> str:
    raw = os.environ.get("HALTSQL_NATIVE", "").strip().lower()
    if raw in ("", "auto"):
        return "auto"
    if raw in ("0", "process", "false", "no", "off"):
        return "process"
    if raw in ("library", "lib", "1"):
        return "library"
    raise ValueError(f"HALTSQL_NATIVE must be 0, process, library or auto (got {raw!r})")


_HOWTO = (
    "install a platform wheel of haltsql (manylinux_2_28 x86_64/aarch64 or macOS arm64), "
    "set HALTSQL_LIB to libhaltsql or HALTSQL_BIN to the haltsql CLI, or run "
    "haltsql-server and use HaltSQLClient"
)


class NativeVerifier:
    """Verify SQL in-process with the bundled HaltSQL engine.

    Args:
        policy_file: Policy document on disk (YAML or JSON, by extension).
        policy: The policy document itself, as a string (instead of ``policy_file``).
        policy_format: ``"yaml"`` or ``"json"``: the format of ``policy``.
        base_dir: Directory that resolves a relative ``catalog:`` path in an
            in-memory ``policy`` (default: the current directory).
        backend: ``"auto"`` (library if loadable, else process), ``"library"``
            or ``"process"``. ``HALTSQL_NATIVE`` overrides ``"auto"`` only.
        binary: ``haltsql`` CLI for the process backend; defaults to
            ``$HALTSQL_BIN``, the bundled CLI, then ``haltsql`` on ``PATH``.
        timeout: Seconds per request before the process backend's child is killed
            and :class:`HaltSQLUnavailable` is raised. (A library call cannot be
            interrupted; it takes microseconds.)
        verify_sql_hash: Check every verdict's ``sql_sha256``. Leave it on.

    Raises :class:`ValueError` if the policy cannot be loaded (with the engine's
    message) and :class:`HaltSQLUnavailable` if no engine is usable. After
    :meth:`close`, every method raises :class:`HaltSQLUnavailable`.
    """

    backend: str
    """The backend in use: ``"library"`` or ``"process"``."""

    def __init__(
        self,
        policy_file: "Optional[os.PathLike[str] | str]" = None,
        *,
        policy: Optional[str] = None,
        policy_format: str = "yaml",
        base_dir: "Optional[os.PathLike[str] | str]" = None,
        backend: str = "auto",
        binary: Optional[str] = None,
        timeout: float = 30.0,
        verify_sql_hash: bool = True,
    ) -> None:
        self._impl: Any = None  # first, so __del__ is safe whatever fails below
        if (policy_file is None) == (policy is None):
            raise ValueError("pass exactly one of policy_file or policy")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if backend not in _BACKENDS:
            raise ValueError(f"backend must be one of {', '.join(_BACKENDS)}")
        fmt = policy_format.lower() if isinstance(policy_format, str) else ""
        fmt = "yaml" if fmt == "yml" else fmt
        if fmt not in ("yaml", "json"):
            raise ValueError('policy_format must be "yaml" or "json"')
        path: Optional[str] = None
        if policy_file is not None:
            path = os.fspath(policy_file)
            if not os.path.isfile(path):
                raise ValueError(f"policy file not found: {path}")
        elif not isinstance(policy, str):
            raise TypeError("policy must be a str (the policy document)")
        bdir = os.fspath(base_dir) if base_dir is not None else None

        self.policy_file = path
        self.policy_format = fmt
        self.timeout = timeout
        self.verify_sql_hash = verify_sql_hash

        if backend == "auto":
            backend = _env_backend()

        lib_error: Optional[str] = None
        if backend in ("auto", "library"):
            try:
                lib = load_library()
                owner = lib.runtime_pid()
                if backend == "auto" and owner is not None and owner != os.getpid():
                    raise HaltSQLUnavailable(
                        f"libhaltsql was started in process {owner} before fork()"
                    )
                self._impl = _LibraryBackend(lib, path, policy, fmt, bdir, verify_sql_hash)
            except HaltSQLUnavailable as e:
                if backend == "library":
                    raise
                lib_error = str(e)
        if self._impl is None:
            try:
                exe = _resolve_binary(binary)
            except HaltSQLUnavailable as e:
                if lib_error is None:
                    raise
                raise HaltSQLUnavailable(
                    f"no HaltSQL engine available: {lib_error}; {e}. To fix: {_HOWTO}"
                ) from None
            self._impl = _ProcessBackend(exe, path, policy, fmt, bdir, timeout, verify_sql_hash)
        self.backend = self._impl.name
        self.fallback_reason = lib_error
        """Why ``"auto"`` did not pick the library (``None`` if it did)."""

    # properties --------------------------------------------------------------------

    @property
    def binary(self) -> Optional[str]:
        """The CLI used by the process backend (``None`` for the library backend)."""
        return getattr(self._impl, "binary", None)

    @property
    def library_path(self) -> Optional[str]:
        """The ``libhaltsql`` used by the library backend (``None`` otherwise)."""
        lib = getattr(self._impl, "lib", None)
        return lib.path if lib is not None else None

    @property
    def closed(self) -> bool:
        return self._impl is None

    def __repr__(self) -> str:
        src = (
            f"policy_file={self.policy_file!r}"
            if self.policy_file is not None
            else f"policy=<in-memory {self.policy_format}>"
        )
        state = ", closed" if self._impl is None else ""
        return f"{type(self).__name__}({src}, backend={getattr(self, 'backend', None)!r}{state})"

    # API -----------------------------------------------------------------------------

    def _live(self) -> Any:
        impl = self._impl
        if impl is None:
            raise HaltSQLUnavailable(_CLOSED_MSG)
        return impl

    def verify(self, sql: str, context: Optional[Context] = None) -> Verdict:
        """Verify one SQL string; returns the verdict (allowed or denied)."""
        _check_sql(sql)
        ctx = validate_context(context)
        return self._live().verify(sql, ctx)

    def check(self, sql: str, context: Optional[Context] = None) -> Verdict:
        """Like :meth:`verify`, but raises :class:`~haltsql.QueryDenied` on a denial."""
        return self.verify(sql, context).raise_for_denied()

    def verify_many(self, items: Sequence[Tuple[str, Optional[Context]]]) -> List[Verdict]:
        """Verify several ``(sql, context)`` pairs (all inputs are validated first)."""
        prepared = []
        for sql, ctx in items:
            _check_sql(sql)
            prepared.append((sql, validate_context(ctx)))
        impl = self._live()
        return [impl.verify(sql, ctx) for sql, ctx in prepared]

    def policy_info(self) -> Dict[str, Any]:
        """``{"name": ..., "version": "sha256:...", "mode": "enforce" | "shadow"}``."""
        return self._live().policy_info()

    def close(self) -> None:
        """Free the policy (library) or stop the child (process). Idempotent."""
        impl, self._impl = self._impl, None
        if impl is not None:
            impl.close()

    def __enter__(self) -> "NativeVerifier":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - interpreter shutdown, forked child, ...
            pass


class AsyncNativeVerifier:
    """``asyncio`` twin of :class:`NativeVerifier` (same arguments).

    Calls run in a worker thread (:func:`asyncio.to_thread`), so the event loop is
    never blocked, and a shared verifier is safe across tasks.
    """

    def __init__(self, policy_file: "Optional[os.PathLike[str] | str]" = None, **kwargs: Any) -> None:
        self._sync = NativeVerifier(policy_file, **kwargs)

    @property
    def backend(self) -> str:
        return self._sync.backend

    @property
    def policy_file(self) -> Optional[str]:
        return self._sync.policy_file

    @property
    def closed(self) -> bool:
        return self._sync.closed

    def __repr__(self) -> str:
        return "Async" + repr(self._sync)

    async def verify(self, sql: str, context: Optional[Context] = None) -> Verdict:
        return await asyncio.to_thread(self._sync.verify, sql, context)

    async def check(self, sql: str, context: Optional[Context] = None) -> Verdict:
        return (await self.verify(sql, context)).raise_for_denied()

    async def verify_many(
        self, items: Sequence[Tuple[str, Optional[Context]]]
    ) -> List[Verdict]:
        return await asyncio.to_thread(self._sync.verify_many, list(items))

    async def policy_info(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._sync.policy_info)

    def close(self) -> None:
        self._sync.close()

    async def aclose(self) -> None:
        await asyncio.to_thread(self._sync.close)

    async def __aenter__(self) -> "AsyncNativeVerifier":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()
