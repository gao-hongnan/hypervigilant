-- record_failure_windowed.lua — atomic sliding-window failure record (DRAFT-0002).
--
-- Maintains a count-based sliding window of the last ``sliding_window_size``
-- outcomes as a Redis bitmap (``cb:{name}:win``) plus cached counters on the
-- circuit hash. Trips ``closed`` -> ``opened`` when
-- ``win_total >= minimum_number_of_calls`` AND
-- ``win_failures / win_total >= failure_rate_threshold``. The bitmap ring
-- update, the cached-counter reconciliation, the rate comparison, and the
-- conditional trip all occur inside one single-threaded EVALSHA, so 1,000
-- concurrent record_failure calls produce at most one trip (single
-- ``generation`` increment).
--
-- KEYS[1] = cb:{name}            -- circuit hash (state, failure_count, opened_at, generation, win_index, win_failures, win_total)
-- KEYS[2] = cb:{name}:win        -- ring bitmap string
-- KEYS[3] = cb:{name}:probe      -- half-open probe lease key
-- ARGV[1] = sliding_window_size
-- ARGV[2] = failure_rate_threshold
-- ARGV[3] = minimum_number_of_calls
-- ARGV[4] = key_ttl_seconds
--
-- Returns: {state, failure_count, opened_at, generation, win_failures, win_total}

local key, win, probe = KEYS[1], KEYS[2], KEYS[3]
local size   = tonumber(ARGV[1])
local rate   = tonumber(ARGV[2])
local min_c  = tonumber(ARGV[3])
local key_tl = tonumber(ARGV[4])

local t   = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1e6

local h = redis.call('HMGET', key, 'state', 'failure_count', 'opened_at', 'generation',
                           'win_index', 'win_failures', 'win_total')
local state = h[1] or 'closed'
local fc    = tonumber(h[2]) or 0
local oa    = tonumber(h[3]) or 0
local gen   = tonumber(h[4]) or 0
local wix   = tonumber(h[5]) or 0
local wf    = tonumber(h[6]) or 0
local wt    = tonumber(h[7]) or 0

if state == 'half_opened' then
    -- probe failed: reopen, reset window
    state, oa, gen = 'opened', now, gen + 1
    fc = math.max(fc, 1)
    redis.call('DEL', probe, win)
    wix, wf, wt = 0, 0, 0
elseif state == 'closed' then
    -- ring update at write_index (evicts the oldest slot when full)
    local pos = wix % size
    local old = redis.call('GETBIT', win, pos)
    redis.call('SETBIT', win, pos, 1)
    wf = wf - old + 1
    wt = math.min(wt + 1, size)
    wix = (wix + 1) % size
    fc = wf
    -- trip predicate (atomic with the update above)
    if wt >= min_c and (wf / wt) >= rate then
        local tripping = wf
        state, oa, gen = 'opened', now, gen + 1
        redis.call('DEL', win)
        wix, wf, wt = 0, 0, 0
        fc = tripping           -- report the count that caused the trip
    end
end
-- state == 'opened' (within TTL): unchanged; fc retains its stored value.

redis.call('HSET', key,
    'state', state,
    'failure_count', tostring(fc),
    'opened_at', tostring(oa),
    'generation', tostring(gen),
    'win_index', tostring(wix),
    'win_failures', tostring(wf),
    'win_total', tostring(wt))
redis.call('EXPIRE', key, key_tl)
if state == 'closed' then redis.call('EXPIRE', win, key_tl) end

return {state, tostring(fc), tostring(oa), tostring(gen), tostring(wf), tostring(wt)}
