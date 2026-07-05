-- acquire.lua — atomic acquire-and-maybe-transition for the circuit breaker.
--
-- Reads the current state hash for ``cb:{name}``; if the breaker is open and
-- the TTL has elapsed, transitions to ``half_opened`` with a fresh probe
-- lease (``cb:{name}:probe`` SET NX PX lease_ms). Returns the post-mutation
-- snapshot plus a decision_tag the Python wrapper maps to a Decision ADT.
--
-- Server-side ``redis.call('TIME')`` provides the wall clock — the script
-- never accepts ``now`` as ARGV. This eliminates cross-worker clock skew
-- (FR-008) and keeps Lua independent of the Python clock.
--
-- KEYS[1] = cb:{name}            -- state hash
-- KEYS[2] = cb:{name}:probe      -- probe lease key (SET NX PX)
-- ARGV[1] = threshold            -- failure threshold (reserved for symmetry)
-- ARGV[2] = ttl_seconds          -- opened-window duration in seconds
-- ARGV[3] = lease_seconds        -- probe lease duration in seconds
-- ARGV[4] = key_ttl_seconds      -- EXPIRE on the state hash
--
-- Returns: {state, failure_count, opened_at, generation, decision_tag}
--   decision_tag in {"allow", "reject", "probe"}.

local key, probe = KEYS[1], KEYS[2]
local ttl = tonumber(ARGV[2])
local lease = tonumber(ARGV[3])
local key_ttl = tonumber(ARGV[4])

local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1e6

local h = redis.call('HMGET', key, 'state', 'failure_count', 'opened_at', 'generation')
local state = h[1] or 'closed'
local fc = tonumber(h[2]) or 0
local oa = tonumber(h[3]) or 0
local gen = tonumber(h[4]) or 0

local decision_tag = 'reject'

if state == 'closed' then
    decision_tag = 'allow'
elseif state == 'opened' and (now - oa) >= ttl then
    state = 'half_opened'
    fc = 0
    gen = gen + 1
    local lease_ms = math.floor(lease * 1000)
    if lease_ms < 1 then lease_ms = 1 end
    redis.call('SET', probe, '1', 'NX', 'PX', lease_ms)
    decision_tag = 'probe'
elseif state == 'half_opened' and redis.call('EXISTS', probe) == 0 then
    -- Stale half-open lease: the previous probe coroutine crashed before
    -- record_failure / record_success ran, but the lease key has expired.
    -- Re-issue the probe so the breaker is not wedged shut for the rest
    -- of key_ttl_seconds.
    fc = 0
    gen = gen + 1
    local lease_ms = math.floor(lease * 1000)
    if lease_ms < 1 then lease_ms = 1 end
    redis.call('SET', probe, '1', 'NX', 'PX', lease_ms)
    decision_tag = 'probe'
end

redis.call('HSET', key,
    'state', state,
    'failure_count', tostring(fc),
    'opened_at', tostring(oa),
    'generation', tostring(gen))
redis.call('EXPIRE', key, key_ttl)

return {state, tostring(fc), tostring(oa), tostring(gen), decision_tag}
