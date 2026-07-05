-- record_failure.lua — atomic failure-record for the circuit breaker.
--
-- Increments the failure counter and, on threshold crossing, transitions
-- ``closed`` → ``opened`` in a single atomic Lua call. If the prior state
-- was ``half_opened`` (a probe in flight), this represents a failed probe
-- and re-opens the breaker (``half_opened`` → ``opened`` with generation +
-- 1). When state is already ``opened`` (within TTL) the snapshot is returned
-- unchanged — the caller has already been counted at the original threshold
-- crossing.
--
-- The atomicity guarantee here is the load-bearing property the rewrite
-- delivers: 1,000 concurrent ``record_failure`` calls on a fresh breaker
-- with ``threshold=10`` produce exactly one ``closed`` → ``opened`` transition,
-- observable as a single ``generation`` increment (AC-002, SC-003). Lua
-- single-threadedness inside Redis makes this deterministic.
--
-- KEYS[1] = cb:{name}            -- state hash
-- KEYS[2] = cb:{name}:probe      -- probe lease key (DEL'd on probe failure)
-- ARGV[1] = threshold
-- ARGV[2] = ttl_seconds          -- (unused; reserved for symmetry)
-- ARGV[3] = key_ttl_seconds      -- EXPIRE on the state hash
--
-- Returns: {state, failure_count, opened_at, generation}.

local key, probe = KEYS[1], KEYS[2]
local threshold = tonumber(ARGV[1])
local key_ttl = tonumber(ARGV[3])

local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1e6

local h = redis.call('HMGET', key, 'state', 'failure_count', 'opened_at', 'generation')
local state = h[1] or 'closed'
local fc = tonumber(h[2]) or 0
local oa = tonumber(h[3]) or 0
local gen = tonumber(h[4]) or 0

if state == 'half_opened' then
    state = 'opened'
    if fc < 1 then fc = 1 end
    oa = now
    gen = gen + 1
    redis.call('DEL', probe)
elseif state == 'closed' then
    fc = fc + 1
    if fc >= threshold then
        state = 'opened'
        fc = threshold
        oa = now
        gen = gen + 1
    end
end
-- state == 'opened' (within TTL): no change.

redis.call('HSET', key,
    'state', state,
    'failure_count', tostring(fc),
    'opened_at', tostring(oa),
    'generation', tostring(gen))
redis.call('EXPIRE', key, key_ttl)

return {state, tostring(fc), tostring(oa), tostring(gen)}
