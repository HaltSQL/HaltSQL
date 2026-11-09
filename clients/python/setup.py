"""Wheel tagging for the bundled engine. All metadata lives in pyproject.toml.

If ``src/haltsql/_native/libhaltsql.so`` exists (staged by
``scripts/build_wheel.sh``), the wheel is platform-specific: tagged
``py3-none-<plat>`` (no CPython ABI is involved: the engine is loaded with
ctypes and the CLI is a plain executable) and it gets the ``haltsql`` console
script. ``<plat>`` is ``$HALTSQL_WHEEL_PLAT`` or the build interpreter's
platform. Otherwise this builds the usual pure ``py3-none-any`` wheel (HTTP
client and LocalVerifier only).
"""

import os
import sysconfig

from setuptools import Distribution, setup

try:  # setuptools >= 70.1 ships bdist_wheel itself
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # pragma: no cover
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel

HERE = os.path.dirname(os.path.abspath(__file__))
NATIVE = os.path.join(HERE, "src", "haltsql", "_native")


def has_native() -> bool:
    return os.path.isfile(os.path.join(NATIVE, "libhaltsql.so"))


def wheel_plat() -> str:
    plat = os.environ.get("HALTSQL_WHEEL_PLAT") or sysconfig.get_platform()
    return plat.replace("-", "_").replace(".", "_")


class BinaryDistribution(Distribution):
    """Non-pure when the engine is staged, so every file lands in the wheel root
    (platlib) instead of ``*.data/purelib``; that keeps the paths delocate and
    auditwheel write into the binaries valid after installation."""

    def has_ext_modules(self):
        return has_native()


class bdist_wheel(_bdist_wheel):
    def get_tag(self):
        if has_native():
            return ("py3", "none", wheel_plat())
        return super().get_tag()


entry_points = {}
if has_native() and os.path.isfile(os.path.join(NATIVE, "haltsql")):
    entry_points["console_scripts"] = ["haltsql = haltsql._native_cli:main"]

setup(
    distclass=BinaryDistribution,
    cmdclass={"bdist_wheel": bdist_wheel},
    entry_points=entry_points,
)
