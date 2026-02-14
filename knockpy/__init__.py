"""Public package surface for knockpy.

Importing `knockpy` exposes the high-level API function (`KNOCKPY`) and package
version, keeping internals hidden by default.
"""

from .core import KNOCKPY
from .version import __version__

__all__ = ["KNOCKPY", "__version__"]
