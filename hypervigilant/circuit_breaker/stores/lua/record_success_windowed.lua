-- record_success_windowed.lua — atomic sliding-window success record (DRAFT-0002).
--
-- A success in ``closed`` state is recorded into the window (it does NOT wipe
-- it — successes dilute the failure rate so a healing dependency stops
-- tripping). A success in ``half_opened`` state closes the breaker and resets
-- the window for a fresh epoch. Atomic in one EVALSHA.
--
-- KEYS[1] = cb:{name}
-- KEYS[2] = cb:{name}:win
-- KEYS[3] = cb:{name}:probe
-- ARGV[1] = sliding_window_size
-- ARGV[2] = key_ttl_seconds
--
-- Returns: {state, failure_count, opened_at, generation, win_failures, win_total}

local key, win, probe = KEYS[1], KEYS[2], KEYS[3]
local size   = tonumber(ARGV[1])
local key_tl = tonumber(ARGV[2])

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
    -- probe succeeded: close, reset window
    state, gen = 'closed', gen + 1
    redis.call('DEL', probe, win)
    wix, wf, wt, fc = 0, 0, 0, 0
elseif state == 'closed' then
    -- record the success into the window (evict oldest if full)
    local pos = wix % size
    local old = redis.call('GETBIT', win, pos)
    redis.call('SETBIT', win, pos, 0)
    wf = wf - old               -- evicted bit removed; new bit is 0 so nothing added
    wt = math.min(wt + 1, size)
    wix = (wix + 1) % size
    fc = wf
end
-- state == 'opened': unchanged (unreachable via runtime; acquire would reject).

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
