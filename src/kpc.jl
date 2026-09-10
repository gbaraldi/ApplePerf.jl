"""
    ApplePerf.KPC

Exact, per-thread hardware counter deltas around a Julia call, read in-process
through the private `kperf` framework (same mechanism as `lauka`, `mperf` and
ibireme's demo). **Requires root** (`sudo julia ...`) or the private
`com.apple.private.kernel.kpc` entitlement.

```julia
using ApplePerf
KPC.measure(["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC"]) do
    sum(A)
end
```
"""
module KPC

using Libdl
using ..KPEP
using ..KPEP: Event, sym, kperf_sym, KPC_CLASS_FIXED_MASK, KPC_CLASS_CONFIGURABLE_MASK

const KPC_MAX_COUNTERS = 32

"""Whether this process can program the PMU (root, or the kpc entitlement)."""
function has_access()
    KPEP.available() || return false
    r = Ref{Cint}(0)
    return ccall(kperf_sym(:kpc_force_all_ctrs_get), Cint, (Ref{Cint},), r) == 0
end

"""
    Session

A programmed set of counters. Create with [`Session(events)`](@ref), then
`start!`, `read`/`measure`, `stop!`. Counting is per-thread: the kernel saves
and restores the counters across context switches, so deltas belong to the
calling thread only.
"""
mutable struct Session
    names::Vector{String}
    classes::UInt32
    regs::Vector{UInt64}
    map::Vector{Int}          # event i lives in counter slot map[i] (0-based)
    active::Bool
    before::Vector{UInt64}
    after::Vector{UInt64}
end

function Session(names)
    names = String[KPEP.event(n).name for n in names]
    isempty(names) && throw(ArgumentError("need at least one event"))
    db = KPEP.db()
    cfg = Ref{Ptr{Cvoid}}(C_NULL)
    ccall(sym(:kpep_config_create), Cint, (Ptr{Cvoid}, Ref{Ptr{Cvoid}}), db, cfg) == 0 || error("kpep_config_create failed")
    try
        ccall(sym(:kpep_config_force_counters), Cint, (Ptr{Cvoid},), cfg[]) == 0 || error("kpep_config_force_counters failed")
        for nm in KPEP.greedy_order(names)
            ev = Ref{Ptr{KPEP.KpepEventRaw}}(C_NULL)
            ccall(sym(:kpep_db_event), Cint, (Ptr{Cvoid}, Cstring, Ref{Ptr{KPEP.KpepEventRaw}}), db, nm, ev) == 0 || error("kpep_db_event($nm) failed")
            rc = ccall(sym(:kpep_config_add_event), Cint, (Ptr{Cvoid}, Ref{Ptr{KPEP.KpepEventRaw}}, UInt32, Ptr{UInt32}), cfg[], ev, 0, C_NULL)
            rc == 0 || error("kpep_config_add_event($nm) failed with $rc: counter slot conflict. Groups that work: $(KPEP.plan_groups(names))")
        end
        classes = Ref{UInt32}(0)
        ccall(sym(:kpep_config_kpc_classes), Cint, (Ptr{Cvoid}, Ref{UInt32}), cfg[], classes)
        cnt = Ref{Csize_t}(0)
        ccall(sym(:kpep_config_kpc_count), Cint, (Ptr{Cvoid}, Ref{Csize_t}), cfg[], cnt)
        # kpep maps events in the order they were added.
        order = KPEP.greedy_order(names)
        map_ = Vector{Csize_t}(undef, length(order))
        ccall(sym(:kpep_config_kpc_map), Cint, (Ptr{Cvoid}, Ptr{Csize_t}, Csize_t), cfg[], map_, sizeof(map_))
        regs = zeros(UInt64, cnt[])
        ccall(sym(:kpep_config_kpc), Cint, (Ptr{Cvoid}, Ptr{UInt64}, Csize_t), cfg[], regs, sizeof(regs))
        slot = Dict(order[i] => Int(map_[i]) for i in eachindex(order))
        return Session(names, classes[], regs, [slot[n] for n in names], false,
                       zeros(UInt64, KPC_MAX_COUNTERS), zeros(UInt64, KPC_MAX_COUNTERS))
    finally
        ccall(sym(:kpep_config_free), Cvoid, (Ptr{Cvoid},), cfg[])
    end
end

"""Program the PMU and start per-thread counting. Needs root."""
function start!(s::Session)
    s.active && return s
    has_access() || error("ApplePerf.KPC needs root: run Julia with sudo (the PMU sysctls are gated on uid 0 or the private kpc entitlement). Without root use `ApplePerf.profile`, which drives xctrace instead.")
    ccall(kperf_sym(:kpc_force_all_ctrs_set), Cint, (Cint,), 1) == 0 || error("kpc_force_all_ctrs_set failed")
    ccall(kperf_sym(:kpc_set_config), Cint, (UInt32, Ptr{UInt64}), s.classes, s.regs) == 0 || error("kpc_set_config failed (another profiler, e.g. Instruments, may own the PMU)")
    ccall(kperf_sym(:kpc_set_counting), Cint, (UInt32,), s.classes) == 0 || error("kpc_set_counting failed")
    ccall(kperf_sym(:kpc_set_thread_counting), Cint, (UInt32,), s.classes) == 0 || error("kpc_set_thread_counting failed")
    s.active = true
    return s
end

"""Stop counting and release the PMU."""
function stop!(s::Session)
    s.active || return s
    ccall(kperf_sym(:kpc_set_thread_counting), Cint, (UInt32,), 0)
    ccall(kperf_sym(:kpc_set_counting), Cint, (UInt32,), 0)
    ccall(kperf_sym(:kpc_force_all_ctrs_set), Cint, (Cint,), 0)
    s.active = false
    return s
end

@inline function _read!(buf::Vector{UInt64})
    ccall(kperf_sym(:kpc_get_thread_counters), Cint, (UInt32, UInt32, Ptr{UInt64}), 0, KPC_MAX_COUNTERS, buf)
    return buf
end

"""Current raw per-thread counter values for the session's events."""
function Base.read(s::Session)
    _read!(s.before)
    return Dict(s.names[i] => s.before[s.map[i] + 1] for i in eachindex(s.names))
end

"""
    measure(f, session) -> Dict{String,Int}

Run `f()` on the current thread and return the counter deltas.
"""
function measure(f, s::Session)
    s.active || start!(s)
    _read!(s.before)
    f()
    _read!(s.after)
    return Dict(s.names[i] => Int(s.after[s.map[i] + 1] - s.before[s.map[i] + 1]) for i in eachindex(s.names))
end

"""
    measure(f, events; repeat = 1) -> Dict{String,Int}

One-shot: program `events`, run `f()`, release the PMU. If the events cannot
share the PMU, they are split with `KPEP.plan_groups` and `f` is run once per
group (software multiplexing across identical runs). With `repeat > 1` the
minimum delta over the repeats is reported per event.
"""
function measure(f, names; repeat::Integer = 1)
    groups = KPEP.plan_groups(names)
    out = Dict{String,Int}()
    for g in groups
        s = Session(g)
        try
            start!(s)
            best = nothing
            for _ in 1:repeat
                d = measure(f, s)
                best = best === nothing ? d : Dict(k => min(best[k], v) for (k, v) in d)
            end
            merge!(out, best)
        finally
            stop!(s)
        end
    end
    return out
end

"""
    @measure events expr

Evaluate `expr` while counting `events` (a vector of names). Returns the deltas.
"""
macro measure(events, ex)
    return :(measure(() -> $(esc(ex)), $(esc(events))))
end

"""
    overhead(session; n = 1000) -> Dict{String,Float64}

Average counter deltas of an empty `measure`, i.e. the cost of the two
`kpc_get_thread_counters` sysctls themselves. Subtract from short regions.
"""
function overhead(s::Session; n::Integer = 1000)
    acc = Dict(k => 0.0 for k in s.names)
    for _ in 1:n
        d = measure(() -> nothing, s)
        for (k, v) in d; acc[k] += v; end
    end
    return Dict(k => v / n for (k, v) in acc)
end

end # module KPC
