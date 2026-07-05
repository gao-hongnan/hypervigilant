"""Redis-backed :class:`BreakerStore` implementation (PR 3B / task 3B).

This is the multi-process / multi-worker storage backend. State is
persisted in a Redis hash at ``cb:{name}``; the half-open probe lease
lives at ``cb:{name}:probe``. Both keys are hash-tagged so they share a
Cluster slot and Lua scripts can operate on them atomically.

State transitions are dispatched via three Lua scripts loaded at
:meth:`initialize` (``acquire.lua``, ``record_failure.lua``,
``record_success.lua``); EVALSHA is used for every call with a single
``NOSCRIPT`` reload-and-retry. ``redis.call('TIME')`` provides the wall
clock inside Lua, eliminating cross-worker clock skew.

Storage failures (``redis.RedisError``) route through a
``cachetools.TTLCache`` of the most recent :class:`Snapshot` for each
circuit (default 30 s TTL). Cache hits are projected through the sansio
core to the Decision ADT (FAIL_STATIC); cache misses fall through to a
configured secondary policy (default :attr:`StorageFailurePolicy.FAIL_OPEN`,
matching refinement R2).

References
----------
- FR-006 (Lua atomicity, EVALSHA + NOSCRIPT retry).
- FR-007 (Lua scripts as separate ``.lua`` files).
- FR-009 (FAIL_STATIC default + secondary policy).
- FR-016 (StoreObserver telemetry).
- AC-002, AC-005, AC-009, EC-001, EC-002, EC-006, EC-007.
- Decisions 5, 6, 10, 11.
"""

import asyncio
import contextlib
import time
from collections.abc import Awaitable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cachetools import TTLCache

from hypervigilant.circuit_breaker.breaker import project_decision
from hypervigilant.circuit_breaker.clock import Clock, SystemClock
from hypervigilant.circuit_breaker.config import (
    BreakerConfig,
    CountingPolicy,
    StorageFailurePolicy,
)
from hypervigilant.circuit_breaker.errors import CircuitStorageError
from hypervigilant.circuit_breaker.hooks import NoOpObserver, StoreObserver
from hypervigilant.circuit_breaker.policy import (
    AllowCall,
    Decision,
    ProbeCall,
    RejectCall,
)
from hypervigilant.circuit_breaker.state import Snapshot, WindowSummary

if TYPE_CHECKING:
    from redis.asyncio import Redis


__all__ = ["RedisStore"]


_LUA_DIR = Path(__file__).parent / "lua"
_LUA_FILES: tuple[tuple[str, str], ...] = (
    ("acquire", "acquire.lua"),
    ("record_failure", "record_failure.lua"),
    ("record_success", "record_success.lua"),
    ("record_failure_windowed", "record_failure_windowed.lua"),
    ("record_success_windowed", "record_success_windowed.lua"),
)


def _hash_tagged(name: str) -> tuple[str, str]:
    """Return the ``(state_key, probe_key)`` pair for a circuit name.

    Both keys are hash-tagged with ``{name}`` so Redis Cluster routes them
    to the same slot, allowing the multi-key Lua scripts to operate on them
    atomically.

    Examples
    --------
    >>> _hash_tagged("payment")
    ('cb:{payment}', 'cb:{payment}:probe')
    """
    return (f"cb:{{{name}}}", f"cb:{{{name}}}:probe")


def _decode(value: str | bytes) -> str:
    """Decode a Redis-returned bytes-or-str value to ``str``."""
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _snapshot_from_lua_payload(
    name: str,
    payload: list[Any],
    *,
    sliding: bool = False,
    size: int = 0,
) -> Snapshot:
    """Materialise a :class:`Snapshot` from a Lua-script return payload.

    The Lua scripts return a flat array ``[state, fc, oa, gen]`` (a five-element
    variant for ``acquire`` appends the decision tag); the windowed ``record_*``
    scripts append ``win_failures, win_total``. Every element arrives as a Redis
    bulk string, decoded to ``bytes`` or ``str``; we normalise via
    :func:`_decode` and narrow the state string to the ``BreakerState`` literal
    via explicit branching.

    When ``sliding`` is true and the post-mutation state is ``closed`` with a
    non-empty window, a :class:`WindowSummary` is attached; otherwise ``window``
    is ``None`` (matching the sans-io core, which carries no active window
    outside a closed epoch).
    """
    try:
        state_str = _decode(payload[0])
        failure_count = int(_decode(payload[1]))
        opened_at = float(_decode(payload[2]))
        generation = int(_decode(payload[3]))
    except (ValueError, IndexError, TypeError) as exc:
        msg = f"RedisStore received malformed Lua payload for {name!r}: {payload!r}."
        raise CircuitStorageError(msg) from exc
    window: WindowSummary | None = None
    if sliding and state_str == "closed" and len(payload) >= 6:
        win_failures = int(_decode(payload[4]))
        win_total = int(_decode(payload[5]))
        if win_total > 0:
            window = WindowSummary(
                size=size,
                failures=win_failures,
                total=win_total,
                rate=win_failures / win_total,
            )
    if state_str == "closed":
        return Snapshot(
            name=name,
            state="closed",
            failure_count=failure_count,
            opened_at=opened_at,
            generation=generation,
            window=window,
        )
    if state_str == "opened":
        return Snapshot(
            name=name,
            state="opened",
            failure_count=failure_count,
            opened_at=opened_at,
            generation=generation,
        )
    if state_str == "half_opened":
        return Snapshot(
            name=name,
            state="half_opened",
            failure_count=failure_count,
            opened_at=opened_at,
            generation=generation,
        )
    msg = f"RedisStore received invalid state {state_str!r} for {name!r}."
    raise CircuitStorageError(msg)


class RedisStore:
    """Asymmetric :class:`BreakerStore` implementation backed by Redis + Lua.

    Parameters
    ----------
    client
        Async ``redis-py`` client. Use :meth:`from_url` for the common case
        or :meth:`from_client` to share an existing pool.
    clock
        Time source for retry-after computation in the FAIL_STATIC cache
        path. Defaults to :class:`SystemClock` because the cached
        ``opened_at`` values were produced by Redis-side ``redis.call('TIME')``
        and need wall-clock comparison.
    observer
        Telemetry hook. Defaults to :class:`NoOpObserver`.
    failure_policy
        Behaviour when Redis is unreachable. Default
        :attr:`StorageFailurePolicy.FAIL_STATIC`.
    secondary_policy
        Fallback when ``FAIL_STATIC`` is configured but the local cache
        has no entry for the circuit (cold-start or post-eviction).
        Default :attr:`StorageFailurePolicy.FAIL_OPEN`. Setting this to
        ``FAIL_STATIC`` raises :exc:`ValueError` (would loop).
    cache_ttl
        TTL for the FAIL_STATIC local cache. Default ``30.0`` seconds.
    cache_size
        Maximum number of cached circuit snapshots. Default ``1024``.
    """

    __slots__ = (
        "_cache",
        "_client",
        "_clock",
        "_failure_policy",
        "_initialized",
        "_init_lock",
        "_key_ttl_seconds",
        "_lua_source",
        "_observer",
        "_owns_client",
        "_request_timeout_seconds",
        "_secondary_policy",
        "_shas",
    )

    def __init__(
        self,
        *,
        client: "Redis",
        clock: Clock | None = None,
        observer: StoreObserver | None = None,
        failure_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_STATIC,
        secondary_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_OPEN,
        cache_ttl: float = 30.0,
        cache_size: int = 1024,
        owns_client: bool = False,
        request_timeout_seconds: float = 1.0,
        key_ttl_seconds: int = 86400,
    ) -> None:
        if secondary_policy is StorageFailurePolicy.FAIL_STATIC:
            msg = "secondary_policy MUST NOT be FAIL_STATIC (would recurse on cold cache)."
            raise ValueError(msg)
        if cache_ttl <= 0.0:
            msg = f"cache_ttl must be > 0; got {cache_ttl}."
            raise ValueError(msg)
        if cache_size < 1:
            msg = f"cache_size must be >= 1; got {cache_size}."
            raise ValueError(msg)
        if request_timeout_seconds <= 0.0:
            msg = f"request_timeout_seconds must be > 0; got {request_timeout_seconds}."
            raise ValueError(msg)
        if key_ttl_seconds <= 0:
            msg = f"key_ttl_seconds must be > 0; got {key_ttl_seconds}."
            raise ValueError(msg)
        # ``Redis[bytes]`` would be the precise type, but redis-py 7.1's
        # bundled stubs are partial -- ``aclose``, ``script_load``, and
        # ``evalsha`` all surface as untyped. Until upstream stubs catch
        # up, we tag the client as ``Any`` and rely on the integration
        # tests for behavioural verification (NFR-002 acceptable escape).
        self._client: Any = client
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._observer: StoreObserver = observer if observer is not None else NoOpObserver()
        self._failure_policy = failure_policy
        self._secondary_policy = secondary_policy
        self._cache: TTLCache[str, Snapshot] = cast(
            "TTLCache[str, Snapshot]", TTLCache(maxsize=cache_size, ttl=cache_ttl)
        )
        self._lua_source: dict[str, str] = {}
        self._shas: dict[str, str] = {}
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._owns_client = owns_client
        self._request_timeout_seconds = request_timeout_seconds
        self._key_ttl_seconds = key_ttl_seconds

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        pool_max: int = 50,
        clock: Clock | None = None,
        observer: StoreObserver | None = None,
        failure_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_STATIC,
        secondary_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_OPEN,
        cache_ttl: float = 30.0,
        cache_size: int = 1024,
        request_timeout_seconds: float = 1.0,
        key_ttl_seconds: int = 86400,
    ) -> "RedisStore":
        """Construct a :class:`RedisStore` owning its own connection pool.

        The pool is closed when :meth:`aclose` is called.
        """
        from redis.asyncio import BlockingConnectionPool, Redis  # noqa: PLC0415 -- lazy import for optional dep

        pool = BlockingConnectionPool.from_url(url, max_connections=pool_max)
        client = Redis(connection_pool=pool)
        return cls(
            client=client,
            clock=clock,
            observer=observer,
            failure_policy=failure_policy,
            secondary_policy=secondary_policy,
            cache_ttl=cache_ttl,
            cache_size=cache_size,
            owns_client=True,
            request_timeout_seconds=request_timeout_seconds,
            key_ttl_seconds=key_ttl_seconds,
        )

    @classmethod
    def from_client(
        cls,
        client: "Redis",
        *,
        clock: Clock | None = None,
        observer: StoreObserver | None = None,
        failure_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_STATIC,
        secondary_policy: StorageFailurePolicy = StorageFailurePolicy.FAIL_OPEN,
        cache_ttl: float = 30.0,
        cache_size: int = 1024,
        owns_client: bool = False,
        request_timeout_seconds: float = 1.0,
        key_ttl_seconds: int = 86400,
    ) -> "RedisStore":
        """Construct a :class:`RedisStore` using a caller-supplied client.

        ``owns_client`` defaults to ``False`` --- :meth:`aclose` will NOT
        close the supplied client. This is the safe default when sharing a
        Redis pool with other application components (cache, rate-limiter,
        etc.). Pass ``owns_client=True`` if the store should own and close
        the supplied client.
        """
        return cls(
            client=client,
            clock=clock,
            observer=observer,
            failure_policy=failure_policy,
            secondary_policy=secondary_policy,
            cache_ttl=cache_ttl,
            cache_size=cache_size,
            owns_client=owns_client,
            request_timeout_seconds=request_timeout_seconds,
            key_ttl_seconds=key_ttl_seconds,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Load every Lua script via ``SCRIPT LOAD`` and cache its SHA.

        Idempotent — the second call is a no-op. Concurrent first-time
        callers serialise through an internal lock.
        """
        async with self._init_lock:
            if self._initialized:
                return
            self._lua_source = {tag: (_LUA_DIR / filename).read_text(encoding="utf-8") for tag, filename in _LUA_FILES}
            await self._load_scripts()
            self._initialized = True

    async def _load_scripts(self) -> None:
        """Issue ``SCRIPT LOAD`` for every script and remember the SHAs.

        Wraps ``TimeoutError`` and ``RedisError`` into
        :exc:`CircuitStorageError` so the caller can route through the
        configured failure policy instead of seeing a bare timeout.
        """
        from redis.exceptions import RedisError  # noqa: PLC0415

        for tag, source in self._lua_source.items():
            try:
                async with asyncio.timeout(self._request_timeout_seconds):
                    sha = await self._client.script_load(source)
            except (RedisError, TimeoutError) as exc:
                wrapped = CircuitStorageError(f"SCRIPT LOAD for {tag!r} failed.")
                wrapped.__cause__ = exc
                self._observer.on_error(op="script_load", name=tag, exc=wrapped)
                raise wrapped from exc
            self._shas[tag] = _decode(sha) if isinstance(sha, bytes | str) else str(sha)

    async def aclose(self) -> None:
        """Release the underlying client when the store owns it.

        ``from_url`` sets ``owns_client=True`` (the store created the pool
        and is responsible for closing it); ``from_client`` defaults to
        ``owns_client=False`` (the caller owns the pool and may share it
        across components, so the store MUST NOT close it).

        Best-effort: any exception raised by the client's close path is
        swallowed (catch ``Exception`` per NFR-003). The redis-py 7.x API
        renamed ``close`` to ``aclose``; we prefer ``aclose`` and fall back
        to ``close`` for older clients.
        """
        if not self._owns_client:
            return
        closer = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
        if closer is None:
            return
        with contextlib.suppress(Exception):
            await closer()

    def clock_now(self) -> float:
        """Return ``self._clock.now()`` for the runtime's ``retry_after`` math.

        The default ``SystemClock`` matches the Redis-side ``redis.call('TIME')``
        wall-clock domain that ``Snapshot.opened_at`` is stamped with.
        """
        return self._clock.now()

    # ------------------------------------------------------------------
    # Public interface (asymmetric BreakerStore Protocol)
    # ------------------------------------------------------------------

    async def acquire(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        lease_seconds: float,
    ) -> tuple[Decision, Snapshot]:
        """Project a Decision and (atomically) transition OPEN → HALF_OPEN if TTL elapsed."""
        await self.initialize()
        state_key, probe_key = _hash_tagged(name)
        config = BreakerConfig(
            threshold=threshold,
            ttl=ttl_seconds,
            half_open_lease_seconds=lease_seconds,
        )
        start = time.perf_counter()
        try:
            payload = await self._evalsha(
                "acquire",
                keys=[state_key, probe_key],
                args=[
                    str(threshold),
                    str(ttl_seconds),
                    str(lease_seconds),
                    str(self._key_ttl_seconds),
                ],
            )
        except CircuitStorageError as exc:
            return self._resolve_acquire_failure(
                op="acquire",
                name=name,
                exc=exc,
                config=config,
            )
        snapshot = _snapshot_from_lua_payload(name, payload[:4])
        decision_tag = _decode(payload[4]) if len(payload) >= 5 else "reject"
        decision = self._decision_from_tag(snapshot, decision_tag, config)
        self._cache[name] = snapshot
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="acquire", name=name, duration_ms=duration_ms)
        self._observer.on_decision(name=name, snapshot=snapshot, decision=decision)
        return decision, snapshot

    async def record_failure(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically increment the failure counter (or trip the breaker)."""
        await self.initialize()
        state_key, probe_key = _hash_tagged(name)
        sliding = counting is not None and counting.strategy == "sliding_window"
        config = BreakerConfig(threshold=threshold, ttl=ttl_seconds)
        start = time.perf_counter()
        try:
            if counting is not None and counting.strategy == "sliding_window":
                win_key = f"{state_key}:win"
                payload = await self._evalsha(
                    "record_failure_windowed",
                    keys=[state_key, win_key, probe_key],
                    args=[
                        str(counting.sliding_window_size),
                        str(counting.failure_rate_threshold),
                        str(counting.minimum_number_of_calls),
                        str(self._key_ttl_seconds),
                    ],
                )
            else:
                payload = await self._evalsha(
                    "record_failure",
                    keys=[state_key, probe_key],
                    args=[str(threshold), str(ttl_seconds), str(self._key_ttl_seconds)],
                )
        except CircuitStorageError as exc:
            return self._resolve_record_failure(
                op="record_failure",
                name=name,
                exc=exc,
                config=config,
            )
        snapshot = _snapshot_from_lua_payload(
            name,
            payload,
            sliding=sliding,
            size=counting.sliding_window_size if counting is not None else 0,
        )
        self._cache[name] = snapshot
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="record_failure", name=name, duration_ms=duration_ms)
        return snapshot

    async def record_success(
        self,
        name: str,
        *,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically reset the failure counter (or close the breaker after a probe)."""
        await self.initialize()
        state_key, probe_key = _hash_tagged(name)
        sliding = counting is not None and counting.strategy == "sliding_window"
        config = BreakerConfig()
        start = time.perf_counter()
        try:
            if counting is not None and counting.strategy == "sliding_window":
                win_key = f"{state_key}:win"
                payload = await self._evalsha(
                    "record_success_windowed",
                    keys=[state_key, win_key, probe_key],
                    args=[
                        str(counting.sliding_window_size),
                        str(self._key_ttl_seconds),
                    ],
                )
            else:
                payload = await self._evalsha(
                    "record_success",
                    keys=[state_key, probe_key],
                    args=[str(self._key_ttl_seconds)],
                )
        except CircuitStorageError as exc:
            return self._resolve_record_failure(
                op="record_success",
                name=name,
                exc=exc,
                config=config,
            )
        snapshot = _snapshot_from_lua_payload(
            name,
            payload,
            sliding=sliding,
            size=counting.sliding_window_size if counting is not None else 0,
        )
        self._cache[name] = snapshot
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="record_success", name=name, duration_ms=duration_ms)
        return snapshot

    async def peek(self, name: str) -> Snapshot | None:
        """Read the current snapshot without mutating state.

        Returns ``None`` only when Redis is reachable AND the key does not
        exist. A storage failure (Redis unreachable, timeout, malformed
        response) raises :exc:`CircuitStorageError` unless a cached
        snapshot is available; the cached snapshot is returned in that
        case so callers can fall back gracefully.
        """
        from redis.exceptions import RedisError  # noqa: PLC0415

        state_key, _ = _hash_tagged(name)
        try:
            async with asyncio.timeout(self._request_timeout_seconds):
                raw = await self._client.hgetall(state_key)
        except (RedisError, TimeoutError) as exc:
            wrapped = CircuitStorageError(f"peek for {name!r} failed.")
            wrapped.__cause__ = exc
            self._observer.on_error(op="peek", name=name, exc=wrapped)
            cached = self._cache.get(name)
            if isinstance(cached, Snapshot):
                return cached
            raise wrapped from exc
        if not raw:
            return None
        decoded = {_decode(k): _decode(v) for k, v in raw.items()}
        state_str = decoded.get("state")
        if state_str not in {"closed", "opened", "half_opened"}:
            return None
        required = ("failure_count", "opened_at", "generation")
        if any(field_name not in decoded for field_name in required):
            msg = f"RedisStore detected corrupt state hash for {name!r}: {decoded!r}."
            raise CircuitStorageError(msg)
        snapshot = _snapshot_from_lua_payload(
            name,
            [
                state_str,
                decoded["failure_count"],
                decoded["opened_at"],
                decoded["generation"],
            ],
        )
        self._cache[name] = snapshot
        return snapshot

    async def reset(self, name: str | None = None) -> None:
        """Discard breaker state for ``name`` (or every circuit in the cache when None)."""
        if name is None:
            self._cache.clear()
            return
        state_key, probe_key = _hash_tagged(name)
        try:
            async with asyncio.timeout(self._request_timeout_seconds):
                await self._client.delete(state_key, probe_key)
        except Exception as exc:  # noqa: BLE001 -- redis errors caught broadly
            wrapped = CircuitStorageError(f"reset for {name!r} failed.")
            wrapped.__cause__ = exc
            self._observer.on_error(op="reset", name=name, exc=wrapped)
        self._cache.pop(name, None)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _evalsha(
        self,
        tag: str,
        *,
        keys: list[str],
        args: list[str],
    ) -> list[Any]:
        """Dispatch a Lua script via EVALSHA, with a single NOSCRIPT retry.

        Wraps every Redis exception (other than ``NoScriptError``) in
        :exc:`CircuitStorageError` for the caller to route through the
        FAIL_STATIC path.
        """
        from redis.exceptions import NoScriptError, RedisError  # noqa: PLC0415

        sha = self._shas.get(tag)
        if sha is None:
            async with self._init_lock:
                if self._shas.get(tag) is None:
                    await self._load_scripts()
            sha = self._shas[tag]
        try:
            return await self._dispatch(sha, keys=keys, args=args)
        except NoScriptError:
            # Serialise concurrent reload bursts so a Redis primary fail-over
            # does not produce N SCRIPT LOAD calls per concurrent EVALSHA.
            async with self._init_lock:
                await self._load_scripts()
                sha = self._shas[tag]
            try:
                return await self._dispatch(sha, keys=keys, args=args)
            except (RedisError, TimeoutError) as exc:
                wrapped = CircuitStorageError(f"EVALSHA retry for {tag!r} failed.")
                wrapped.__cause__ = exc
                self._observer.on_error(op=tag, name=keys[0], exc=wrapped)
                raise wrapped from exc
        except (RedisError, TimeoutError) as exc:
            wrapped = CircuitStorageError(f"EVALSHA dispatch for {tag!r} failed.")
            wrapped.__cause__ = exc
            self._observer.on_error(op=tag, name=keys[0], exc=wrapped)
            raise wrapped from exc

    async def _dispatch(self, sha: str, *, keys: list[str], args: list[str]) -> list[Any]:
        """Issue a raw EVALSHA and normalise the result to ``list[Any]``."""
        async with asyncio.timeout(self._request_timeout_seconds):
            result_or_awaitable = self._client.evalsha(sha, len(keys), *keys, *args)
            if isinstance(result_or_awaitable, Awaitable):
                result: Any = await result_or_awaitable
            else:
                result = result_or_awaitable
        if not isinstance(result, list):
            msg = f"EVALSHA returned non-list payload: {type(result).__name__}."
            raise CircuitStorageError(msg)
        return result

    def _decision_from_tag(
        self,
        snapshot: Snapshot,
        tag: str,
        config: BreakerConfig,
    ) -> Decision:
        """Map the Lua decision_tag to a :class:`Decision` ADT."""
        if tag == "allow":
            return AllowCall()
        if tag == "probe":
            now = self._clock.now()
            return ProbeCall(lease_until=now + config.half_open_lease_seconds)
        # tag == "reject" → compute retry_after from snapshot + clock.
        now = self._clock.now()
        elapsed = now - snapshot.opened_at if snapshot.opened_at > 0 else 0.0
        retry_after = max(config.ttl - elapsed, 0.0)
        return RejectCall(opened_at=snapshot.opened_at, retry_after=retry_after)

    def _resolve_acquire_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        config: BreakerConfig,
    ) -> tuple[Decision, Snapshot]:
        """Map an acquire-time storage failure to ``(Decision, Snapshot)`` per ``failure_policy``.

        ``FAIL_OPEN`` returns :class:`AllowCall` plus a default closed snapshot
        without consulting the cache. ``FAIL_CLOSED`` returns
        :class:`RejectCall` plus a synthesised opened snapshot. ``FAIL_STATIC``
        delegates to :meth:`_fail_static` (cache lookup with
        ``secondary_policy`` fallback on cold cache).
        """
        if self._failure_policy is StorageFailurePolicy.FAIL_OPEN:
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=StorageFailurePolicy.FAIL_OPEN,
            )
            return AllowCall(), Snapshot(
                name=name,
                state="closed",
                failure_count=0,
                opened_at=0.0,
                generation=0,
            )
        if self._failure_policy is StorageFailurePolicy.FAIL_CLOSED:
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=StorageFailurePolicy.FAIL_CLOSED,
            )
            return RejectCall(opened_at=0.0, retry_after=config.ttl), Snapshot(
                name=name,
                state="opened",
                failure_count=config.threshold,
                opened_at=0.0,
                generation=0,
            )
        return self._fail_static(op=op, name=name, exc=exc, config=config)

    def _resolve_record_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        config: BreakerConfig,
    ) -> Snapshot:
        """Map a record_*-time storage failure to a ``Snapshot`` per ``failure_policy``.

        ``FAIL_OPEN`` returns the cached snapshot if present, otherwise a
        default closed snapshot (lenient: pretend the failure didn't happen).
        ``FAIL_CLOSED`` returns the cached snapshot if present, otherwise a
        synthesised opened snapshot (cautious: pretend the breaker tripped).
        ``FAIL_STATIC`` delegates to :meth:`_fail_static_snapshot` (cache
        lookup; raises :exc:`CircuitStorageError` on cold cache).
        """
        if self._failure_policy is StorageFailurePolicy.FAIL_OPEN:
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=StorageFailurePolicy.FAIL_OPEN,
            )
            cached = self._cache.get(name)
            if isinstance(cached, Snapshot):
                return Snapshot(
                    name=cached.name,
                    state=cached.state,
                    failure_count=cached.failure_count,
                    opened_at=cached.opened_at,
                    generation=cached.generation,
                    is_authoritative=False,
                )
            return Snapshot(
                name=name,
                state="closed",
                failure_count=0,
                opened_at=0.0,
                generation=0,
                is_authoritative=False,
            )
        if self._failure_policy is StorageFailurePolicy.FAIL_CLOSED:
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=StorageFailurePolicy.FAIL_CLOSED,
            )
            cached = self._cache.get(name)
            if isinstance(cached, Snapshot):
                return Snapshot(
                    name=cached.name,
                    state=cached.state,
                    failure_count=cached.failure_count,
                    opened_at=cached.opened_at,
                    generation=cached.generation,
                    is_authoritative=False,
                )
            return Snapshot(
                name=name,
                state="opened",
                failure_count=config.threshold,
                opened_at=0.0,
                generation=0,
                is_authoritative=False,
            )
        cached_snap = self._fail_static_snapshot(op=op, name=name, exc=exc)
        return Snapshot(
            name=cached_snap.name,
            state=cached_snap.state,
            failure_count=cached_snap.failure_count,
            opened_at=cached_snap.opened_at,
            generation=cached_snap.generation,
            is_authoritative=False,
        )

    def _fail_static(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        config: BreakerConfig,
    ) -> tuple[Decision, Snapshot]:
        """Resolve an acquire-time storage failure via the FAIL_STATIC cache.

        Returns the projected :class:`Decision` plus a :class:`Snapshot` that
        the runtime layer can use as pre-state for state-change emission. On
        cache miss the snapshot is a default ``closed`` snapshot --- mirroring
        what the runtime previously synthesised when ``peek`` returned
        ``None`` during an outage.
        """
        cached = self._cache.get(name)
        if cached is None:
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=self._secondary_policy,
            )
            decision = self._decision_from_secondary(
                self._secondary_policy,
                cached=None,
                config=config,
            )
            synthesized = Snapshot(
                name=name,
                state="closed",
                failure_count=0,
                opened_at=0.0,
                generation=0,
            )
            return decision, synthesized
        self._observer.on_storage_failure(
            op=op,
            name=name,
            exc=exc,
            fell_back_to=StorageFailurePolicy.FAIL_STATIC,
        )
        return project_decision(cached, config, self._clock), cached

    def _fail_static_snapshot(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
    ) -> Snapshot:
        """Resolve a record_*-time storage failure by returning the cached snapshot.

        On cache miss, raises :exc:`CircuitStorageError` (record_failure /
        record_success have no Decision to fall back to without a snapshot).
        """
        cached = self._cache.get(name)
        if not isinstance(cached, Snapshot):
            self._observer.on_storage_failure(
                op=op,
                name=name,
                exc=exc,
                fell_back_to=self._secondary_policy,
            )
            wrapped = CircuitStorageError(f"{op} for {name!r} failed and cache is cold.")
            wrapped.__cause__ = exc
            raise wrapped
        self._observer.on_storage_failure(
            op=op,
            name=name,
            exc=exc,
            fell_back_to=StorageFailurePolicy.FAIL_STATIC,
        )
        return cached

    def _decision_from_secondary(
        self,
        policy: StorageFailurePolicy,
        *,
        cached: Snapshot | None,
        config: BreakerConfig,
    ) -> Decision:
        """Map a secondary :class:`StorageFailurePolicy` to a Decision."""
        del cached  # unused by FAIL_OPEN / FAIL_CLOSED
        if policy is StorageFailurePolicy.FAIL_OPEN:
            return AllowCall()
        if policy is StorageFailurePolicy.FAIL_CLOSED:
            return RejectCall(opened_at=0.0, retry_after=config.ttl)
        # Defensive: FAIL_STATIC was rejected at construction; should not occur.
        msg = f"Unhandled secondary policy {policy!r}."
        raise CircuitStorageError(msg)
