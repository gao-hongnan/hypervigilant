"""The I/O layer: the only place in the package that holds a socket."""

from hypervigilant.db.runtime.asyncio import Database

__all__ = ["Database"]
