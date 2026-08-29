"""Column types and schema conventions that storage-row modules import.

This is the module a ``table=True`` SQLModel class reaches for. It holds no
connection state and no engine; it is safe to import from anywhere inside the
package.

Why a ``TypeDecorator`` and not a plain ``JSON`` column
------------------------------------------------------
Writing a Pydantic model into ``Column(JSON)`` raises ``TypeError: Object of
type X is not JSON serializable``. The obvious repair -- dumping to a dict on
the way in -- is worse than the error, because it *succeeds*: the value returns
as an untyped mapping, silently replacing a discriminated union with a dict
that has the right keys and none of the guarantees. Every validator on the
model stops running, and nothing fails until something far away reads
``locus.kind`` off a plain dict. :class:`PydanticJSON` closes that by validating
through a :class:`~pydantic.TypeAdapter` on load, so a union round-trips as its
concrete variant or raises where the bad bytes are.

Four defects fixed relative to the prior implementation
-------------------------------------------------------
All four were verified against SQLAlchemy 2.0.52.

**The adapter was invisible to the compiled-statement cache.** ``cache_ok =
True`` asserts to SQLAlchemy that two instances of the type compile and convert
identically. SQLAlchemy builds the key by intersecting ``__init__`` parameter
*names* with instance ``__dict__``, and additionally discards any key starting
with an underscore (``sqlalchemy/sql/type_api.py:1000-1017``). Storing the
adapter as ``self._adapter`` while naming the parameter ``adapter`` therefore
produced the key ``(PydanticJSON,)`` for *every* instance. Two statements
differing only in their Pydantic type collapsed to one cache entry, and the
second was decoded with the first's adapter -- reproduced end to end: a
statement declaring ``TypeAdapter(B)`` returned an ``A``. Storing it as the
public :attr:`adapter` restores a key that distinguishes types.

**The adapter was lost by ``TypeEngine.adapt()``.** ``util.constructor_copy``
reads the same ``{'adapter'}`` name set off ``__dict__``, missed ``_adapter``,
and rebuilt the column with no adapter at all -- DDL-correct and
conversion-dead. Same one-word fix.

**``None`` did not round-trip.** ``sqlalchemy.JSON`` defaults
``none_as_null=False``, so a ``None`` model was persisted as the JSON literal
``'null'`` rather than SQL ``NULL``. ``WHERE col IS NULL`` matched nothing,
``NOT NULL`` never tripped, and partial indexes on ``IS NULL`` were dead.
:data:`_IMPL` sets ``none_as_null=True``.

**PostgreSQL got ``JSON``, not ``JSONB``.** ``impl = types.JSON`` compiles to
the text-backed ``JSON`` type on PostgreSQL: no containment operators, no GIN
index. :meth:`PydanticJSON.load_dialect_impl` returns ``JSONB`` there.

The adapter is required
-----------------------
The prior implementation made it optional to satisfy Alembic, whose autogenerate
renders a column type by ``repr()``-ing it -- so a required parameter appeared
to make every generated revision fail at ``TypeError``. The premise is true and
the conclusion does not follow: the supported mechanism is the ``render_item``
hook in ``env.py`` (``alembic/runtime/environment.py:754-778``), and it is
needed regardless, because ``TypeDecorator.__repr__`` renders
``PydanticJSON()`` either way -- never valid migration source. Four lines in
``env.py`` buy back a required constructor argument, which deletes an entire
runtime failure mode::

    def render_item(type_, obj, autogen_context):
        if type_ == "type" and isinstance(obj, PydanticJSON):
            return "sa.JSON()"
        return False

Two model families, one conversion boundary
-------------------------------------------
A ``table=True`` SQLModel class is a *storage row*, never a domain object, and
two of its properties make that a constraint rather than a preference. It does
not validate its own fields -- constructing one with nonsense succeeds silently,
because SQLModel disables validation on table classes so SQLAlchemy can populate
attributes when hydrating a query. And it cannot be frozen:
``ConfigDict(frozen=True)`` on a table class fails at *construction*, because
the instrumentation must set attributes. So nothing reaches the domain without
passing through a validated Pydantic class, and nothing reaches the database
except through a row built from one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, override

from pydantic import JsonValue, TypeAdapter
from sqlalchemy import MetaData, types
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from sqlalchemy import Dialect
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlmodel.ext.asyncio.session import AsyncSession

__all__ = ["NAMING_CONVENTION", "PydanticJSON", "SessionFactory", "build_metadata"]

type SessionFactory = async_sessionmaker[AsyncSession]
"""The callable a session is opened from. Named so consumers can spell it."""

_POSTGRESQL_DIALECT: Final = "postgresql"
"""SQLAlchemy's name for the PostgreSQL dialect, as ``Dialect.name`` reports it.

The one value :meth:`PydanticJSON.load_dialect_impl` branches on. Spelled once, so a
typo degrades to portable ``JSON`` everywhere rather than in whichever module got it
wrong -- a failure that is invisible until somebody needs a GIN index.
"""

_IMPL: Final = types.JSON(none_as_null=True)
"""The cross-dialect storage type.

``none_as_null=True`` is the whole reason this is an instance rather than the
bare ``types.JSON`` class -- see the module docstring.
"""

NAMING_CONVENTION: Final[dict[str, str]] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
"""Deterministic constraint names, resolved at Python construction time.

SQLAlchemy's own default covers indexes only
(``DEFAULT_NAMING_CONVENTION`` at ``sqlalchemy/sql/schema.py:5384``), so without
this an autogenerated migration emits unnamed ``CHECK`` / ``UNIQUE`` /
``FOREIGN KEY`` constraints -- and the corresponding ``downgrade()`` cannot drop
them, because the name it would need was invented by the server and is not
knowable from the model.
"""


def build_metadata() -> MetaData:
    """Return a fresh :class:`~sqlalchemy.MetaData` carrying :data:`NAMING_CONVENTION`.

    Pair it with an explicit registry rather than mutating ``SQLModel.metadata``.
    That singleton is created at import (``sqlmodel/main.py:799``) and the
    convention is consulted when a constraint is *attached*, so mutating it works
    only if it happens before the first ``table=True`` class is defined --
    import-order fragility that fails silently and late. SQLModel's metaclass
    honours a ``registry=`` class keyword (``sqlmodel/main.py:616-623``), which
    has no such ordering hazard::

        from sqlalchemy.orm import registry

        REGISTRY = registry(metadata=build_metadata())

        class Base(SQLModel, registry=REGISTRY):
            pass

        class Order(Base, table=True):
            ...

    Returns
    -------
        A new instance each call, because a :class:`~sqlalchemy.MetaData` is
        mutable and shared collections of tables are how test suites leak into
        one another.

    Examples
    --------
    >>> build_metadata().naming_convention["pk"]
    'pk_%(table_name)s'
    >>> build_metadata() is build_metadata()
    False
    """
    return MetaData(naming_convention=NAMING_CONVENTION)


class PydanticJSON[ModelT](types.TypeDecorator[ModelT]):
    """A JSON column that round-trips one Pydantic type as itself.

    Dumps through a :class:`~pydantic.TypeAdapter` on bind and validates through
    the same adapter on load, so a discriminated union comes back as the variant
    it went in as. The adapter is supplied rather than inferred, because the
    interesting cases are unions and aliases with no single class to introspect.

    Parameters
    ----------
    adapter
        The adapter for the stored type. Required, and stored under the public
        name :attr:`adapter` -- SQLAlchemy reads ``__init__`` parameter names
        back off the instance to build both the compiled-cache key and
        ``constructor_copy``, and an underscore-prefixed attribute is invisible
        to both.

    Notes
    -----
    Prefer module-level adapters shared across columns::

        LOCUS_ADAPTER: Final = TypeAdapter(Locus)
        locus: Locus = Field(sa_column=Column(PydanticJSON(LOCUS_ADAPTER)))

    :class:`~pydantic.TypeAdapter` compares by identity, so the cache key is
    per-adapter-instance. Sharing one adapter keeps a single compiled-cache
    entry per statement shape; constructing a fresh adapter per column merely
    costs entries in a bounded LRU, but there is no reason to pay it.

    Examples
    --------
    >>> from pydantic import BaseModel, TypeAdapter
    >>> from sqlalchemy.dialects import postgresql
    >>> class Point(BaseModel):
    ...     x: int
    >>> column = PydanticJSON(TypeAdapter(Point))
    >>> wire = column.process_bind_param(Point(x=1), postgresql.dialect())
    >>> wire
    {'x': 1}
    >>> column.process_result_value(wire, postgresql.dialect())
    Point(x=1)

    Columns for different types are distinguishable by the statement cache --
    the regression that made a ``B`` column decode as an ``A``:

    >>> class Other(BaseModel):
    ...     y: int
    >>> a, b = PydanticJSON(TypeAdapter(Point)), PydanticJSON(TypeAdapter(Other))
    >>> a._static_cache_key == b._static_cache_key
    False

    PostgreSQL gets ``JSONB``; every other dialect keeps portable ``JSON``:

    >>> isinstance(column.load_dialect_impl(postgresql.dialect()), postgresql.JSONB)
    True
    """

    impl = _IMPL
    cache_ok = True

    adapter: TypeAdapter[ModelT]

    def __init__(self, adapter: TypeAdapter[ModelT]) -> None:
        super().__init__()
        self.adapter = adapter

    @override
    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        """Use ``JSONB`` on PostgreSQL, portable ``JSON`` elsewhere.

        ``JSONB`` is binary, indexable with GIN, and supports the containment
        operators; ``JSON`` on PostgreSQL is text with a validity check and none
        of that. Keeping a single type object -- rather than ``with_variant`` --
        keeps a single cache key.
        """
        if dialect.name == _POSTGRESQL_DIALECT:
            return dialect.type_descriptor(postgresql.JSONB(none_as_null=True))
        return dialect.type_descriptor(_IMPL)

    @override
    def process_bind_param(self, value: ModelT | None, dialect: Dialect) -> JsonValue:
        """Dump the model to JSON-compatible primitives on the way to the database.

        ``mode="json"`` rather than ``mode="python"``: the latter leaves
        :class:`~datetime.datetime` and :class:`~enum.Enum` values as objects,
        which the JSON serialiser then refuses -- the same ``TypeError`` this
        class exists to prevent, one level down.

        ``None`` is returned unchanged and reaches SQL ``NULL`` rather than the
        JSON literal ``'null'`, because :data:`_IMPL` sets ``none_as_null``.
        """
        if value is None:
            return None
        dumped: JsonValue = self.adapter.dump_python(value, mode="json")
        return dumped

    @override
    def process_result_value(self, value: JsonValue, dialect: Dialect) -> ModelT | None:
        """Validate the stored JSON back into the declared type.

        The half that makes the round trip lossless. Without it a caller
        receives a ``dict`` that happens to have the right keys, and every
        invariant the model declares stops being enforced from here outward.
        """
        return None if value is None else self.adapter.validate_python(value)
