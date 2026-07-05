-- record_success.lua — atomic success-record for the circuit breaker.
--
-- A successful probe call (state was ``half_opened``) closes the breaker
-- with ``generation += 1`` and ``failure_count = 0``; the probe lease key
-- is DEL'd. A success arriving in ``closed`` state simply resets the
-- failure counter to zero (no generation change). A success arriving in
-- ``opened`` state never normally happens (acquire would have raised
-- ``BreakerOpenError`` first) but is treated as a no-op for safety.
--
-- KEYS[1] = cb:{name}            -- state hash
-- KEYS[2] = cb:{name}:probe      -- probe lease key (DEL'd on probe success)
-- ARGV[1] = key_ttl_seconds      -- EXPIRE on the state hash
--
-- Returns: {state, failure_count, opened_at, generation}.

local key, probe = KEYS[1], KEYS[2]
local key_ttl = tonumber(ARGV[1])

local h = redis.call('HMGET', key, 'state', 'failure_count', 'opened_at', 'generation')
local state = h[1] or 'closed'
local fc = tonumber(h[2]) or 0
local oa = tonumber(h[3]) or 0
local gen = tonumber(h[4]) or 0

if state == 'half_opened' then
    state = 'closed'
    fc = 0
    gen = gen + 1
    redis.call('DEL', probe)
elseif state == 'closed' then
    fc = 0
end
-- state == 'opened': no change (acquire would have rejected the call).

redis.call('HSET', key,
    'state', state,
    'failure_count', tostring(fc),
    'opened_at', tostring(oa),
    'generation', tostring(gen))
redis.call('EXPIRE', key, key_ttl)

return {state, tostring(fc), tostring(oa), tostring(gen)}
