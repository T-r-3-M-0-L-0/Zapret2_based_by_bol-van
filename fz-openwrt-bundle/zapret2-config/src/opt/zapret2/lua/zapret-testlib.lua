--[[

ZAPRET2 TEST LIBRARY - template for custom desync functions
Pure ASCII on purpose (PowerShell 5.1 / cp1251 safety rule of this project).

Load:
  --lua-init=@"<root>\lua\zapret-lib.lua" --lua-init=@"<root>\lua\zapret-antidpi.lua" --lua-init=@"<root>\lua\zapret-testlib.lua"

Call from a profile (.conf) or .bat:
  --lua-desync=myinfo
  --lua-desync=myfake:blob=tls_google:pad=32:ip_ttl=3:repeats=4
  --lua-desync=mysplit:pos=host:seqovl=64:seqovl_pattern=tls_4pda
  --lua-desync=mycount:n=3
  --lua-desync=mydelayed:delay=50:blob=quic_google

FUNCTION CONTRACT (same as zapret-antidpi.lua):
  function name(ctx, desync)   -- called for EVERY packet matching the profile filters
    ctx    - profile instance context (passed to cutoff helpers, never modified)
    desync - state table:
      desync.arg.<name>   - your :arg=val parameters, ALL VALUES ARE STRINGS (use tonumber())
      desync.dis          - dissected packet: dis.ip / dis.ip6 / dis.tcp / dis.udp / dis.payload
                            dis.tcp.th_seq, th_ack, th_flags, th_win, th_urp are numbers
      desync.l7payload    - detected payload type: "tls_client_hello", "http_req",
                            "quic_initial", "unknown", "all" ...
      desync.reasm_data   - full reassembled stream bytes (when reasm is active)
      desync.outgoing     - true = outbound packet, false = inbound
      desync.track        - conntrack state (nil for stateless); desync.track.lua_state
                            is YOUR persistent per-connection table
      desync.func_instance- unique id string of this lua-desync instance (for state keys)
      desync.replay       - true for reassembled replay pieces
    return VERDICT_PASS (or nil) - let the original packet through unchanged
           VERDICT_MODIFY        - send modified desync.dis
           VERDICT_DROP          - drop the original (you sent your own parts)

STANDARD ARG GROUPS (free if you call the helpers - see myfake):
  dir=in|out|any           - direction_check / direction_cutoff_opposite
  payload=<list>           - payload_check
  fooling: ip_ttl=N, ip_autottl=d,min-max, tcp_seq=N, tcp_ack=N, tcp_ts=N,
           tcp_md5, tcp_flags_set/unset, fool=<func>  - apply_fooling(desync, dis)
  reconstruct: badsum      - reconstruct_opts(desync)
  rawsend: repeats=N, ifout, fwmark                     - rawsend_opts(desync)
  ip_id=seq|rnd|zero|none                               - apply_ip_id(desync, dis)
  ipfrag, ipfrag_pos_tcp, ipfrag_disorder               - desync_opts(desync)

REPLAY RULE: TCP payload may arrive twice (original + reassembled replay).
  replay_first(desync)  - true only for the first copy; act only then
  replay_drop_set(desync) + replay_drop(desync) - drop replay pieces afterwards
CUTOFF RULE: when the instance finished its job for this connection call
  instance_cutoff_shim(ctx, desync) - saves CPU for the rest of the connection
]]

-- ============================================================================
-- 1. myinfo - read-only diagnostics. Use it first when writing anything new:
--    it shows what data your function actually receives.
-- args: none
-- ============================================================================
function myinfo(ctx, desync)
	local dir = desync.outgoing and "out" or "in"
	local l4 = dis_l4_name(desync.dis) or "?"
	-- dis_l4_ports returns a ready "sport:dport" string (or "?")
	DLOG("myinfo: "..dir.." "..l4.." "..dis_l4_ports(desync.dis).." l7="..tostring(desync.l7payload)..
	     " payload="..#desync.dis.payload..
	     (desync.reasm_data and (" reasm="..#desync.reasm_data) or "")..
	     (desync.replay and " REPLAY" or ""))
	if #desync.dis.payload > 0 then
		DLOG("myinfo: head: "..hexdump_dlog(desync.dis.payload))
	end
	-- no return = VERDICT_PASS, packet untouched
end

-- ============================================================================
-- 2. myfake - send a fake payload before the original, with an optional
--    random padding appended. Teaches: blobs, fooling, repeats, replay rule.
-- args:
--   blob=<blob>  - fake payload (name from --blob, 0xHEX or built-in). REQUIRED
--   pad=N        - append N random bytes to the fake (default 0)
--   optional     - silently skip if the blob is absent
-- standard args: direction, payload, fooling, ip_id, rawsend, reconstruct, ipfrag
-- ============================================================================
function myfake(ctx, desync)
	direction_cutoff_opposite(ctx, desync)
	if not (desync.dis.tcp or desync.dis.udp) then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	if direction_check(desync) and payload_check(desync) then
		if not replay_first(desync) then
			DLOG("myfake: skipping replay piece")
			return
		end
		if not desync.arg.blob then
			error("myfake: 'blob' arg required")  -- hard config error, visible in --debug
		end
		if desync.arg.optional and not blob_exist(desync, desync.arg.blob) then
			DLOG("myfake: blob '"..desync.arg.blob.."' not found. skipped")
			return
		end
		local fake_payload = blob(desync, desync.arg.blob)
		local pad = tonumber(desync.arg.pad or "0")
		if pad > 0 then
			-- brandom_az09(N) - engine built-in: N random [a-z0-9] bytes
			fake_payload = fake_payload .. brandom_az09(pad)
			DLOG("myfake: padded +"..pad.." => "..#fake_payload.." bytes")
		end
		if b_debug then DLOG("myfake: "..hexdump_dlog(fake_payload)) end
		-- sends the fake with all standard fooling/repeats/badsum applied,
		-- original packet passes after it (we return nothing)
		rawsend_payload_segmented(desync, fake_payload)
	end
end

-- ============================================================================
-- 3. mysplit - split the payload at ONE marker and send the second part FIRST
--    (disorder). Teaches: position markers, rawsend parts, replay drop.
-- args:
--   pos=<marker>       - split position: number, "host", "sni", "midsld",
--                        "sniext+1", "-10" (from the end)... default 2
--   seqovl=N           - overlap: prepend N pattern bytes to part 1 and shift
--                        its seq back by N (default 0)
--   seqovl_pattern=<blob> - pattern for the overlap (default zero bytes)
-- standard args: direction, payload, fooling, ip_id, rawsend, reconstruct, ipfrag
-- ============================================================================
function mysplit(ctx, desync)
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	direction_cutoff_opposite(ctx, desync)
	local data = desync.reasm_data or desync.dis.payload
	if #data > 0 and direction_check(desync) and payload_check(desync) then
		if not replay_first(desync) then
			if replay_drop(desync) then return VERDICT_DROP end
			return
		end
		local spos = desync.arg.pos or "2"
		-- markers are 1-based, resolve_pos returns 1-based absolute position
		local pos = resolve_pos(data, desync.l7payload, spos)
		if not pos or pos < 2 then
			DLOG("mysplit: cannot resolve pos '"..spos.."'")
			return
		end
		local part1 = string.sub(data, 1, pos-1)
		local part2 = string.sub(data, pos)
		local seqovl = tonumber(desync.arg.seqovl or "0")
		local shift1 = 0
		if seqovl > 0 then
			local pat = desync.arg.seqovl_pattern and blob(desync, desync.arg.seqovl_pattern) or "\x00"
			part1 = pattern(pat, 1, seqovl) .. part1
			shift1 = seqovl
		end
		DLOG("mysplit: pos="..(pos-1).." part1="..#part1.." part2="..#part2.." seqovl="..seqovl)
		-- disorder: second part first, then the first part (shifted back by seqovl)
		if not rawsend_payload_segmented(desync, part2, pos-1) then return VERDICT_PASS end
		if not rawsend_payload_segmented(desync, part1, -shift1) then return VERDICT_PASS end
		replay_drop_set(desync)
		return VERDICT_DROP -- original is dropped, our two parts replace it
	end
end

-- ============================================================================
-- 4. mycount - per-connection state. Counts outgoing data packets and drops
--    the Nth one. Teaches: desync.track.lua_state, func_instance keys, cutoff.
-- args:
--   n=N - drop packet number N (default 2)
-- ============================================================================
function mycount(ctx, desync)
	if not desync.track then
		DLOG("mycount: no conntrack (stateless packet)")
		return
	end
	direction_cutoff_opposite(ctx, desync)
	if not direction_check(desync) then return end
	-- per-connection storage, key MUST be unique per instance
	local key = desync.func_instance.."_cnt"
	local cnt = (desync.track.lua_state[key] or 0)
	if #desync.dis.payload > 0 then
		cnt = cnt + 1
		desync.track.lua_state[key] = cnt
		DLOG("mycount: packet #"..cnt)
	end
	local n = tonumber(desync.arg.n or "2")
	if cnt == n then
		DLOG("mycount: dropping packet #"..n)
		instance_cutoff_shim(ctx, desync) -- job done: do not call us again on this conn
		return VERDICT_DROP
	end
end

-- ============================================================================
-- 5. mydelayed - send a blob with a delay (timer). Teaches: timer_set,
--    deepcopy of the dissect, named global timer callbacks.
-- args:
--   blob=<blob>  - what to send. REQUIRED
--   delay=<ms>   - delay in milliseconds (default 50)
-- standard args: direction, payload, fooling, rawsend, reconstruct, ipfrag
-- ============================================================================
function mydelayed(ctx, desync)
	direction_cutoff_opposite(ctx, desync)
	if not (desync.dis.tcp or desync.dis.udp) then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	if direction_check(desync) and payload_check(desync) and replay_first(desync) then
		if not desync.arg.blob then
			error("mydelayed: 'blob' arg required")
		end
		local dis = deepcopy(desync.dis)
		dis.payload = blob(desync, desync.arg.blob)
		apply_fooling(desync, dis)
		local tname = desync_timer_name(desync)
		local ms = tonumber(desync.arg.delay or "50")
		DLOG("mydelayed: armed "..ms.." ms")
		-- oneshot=true : timer auto-deletes after firing
		timer_set(tname, "mydelayed_fire", ms, true, {dis = dis, opts = desync_opts(desync)})
	end
end
function mydelayed_fire(name, data)
	-- global callback, name must match the 2nd timer_set argument
	rawsend_dissect_ipfrag(data.dis, data.opts)
end
