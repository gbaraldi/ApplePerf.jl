"""
    ApplePerf.KPEP

Read-only access to the kpep performance-event database that ships with macOS
(`/usr/share/kpep/*.plist`, loaded through the private `kperfdata` framework).
No privileges are needed. Provides the event list for the current CPU, their
counter-slot masks, and a conflict planner that predicts which events can be
counted simultaneously (the "slot booking" rules Instruments enforces).
"""
module KPEP

using Libdl

const KPERFDATA = "/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"
const KPERF = "/System/Library/PrivateFrameworks/kperf.framework/kperf"

const _kpep = Ref{Ptr{Cvoid}}(C_NULL)
const _kperf = Ref{Ptr{Cvoid}}(C_NULL)

# struct kpep_event from the reverse-engineered headers (ibireme / lauka).
struct KpepEventRaw
    name::Cstring
    description::Cstring
    errata::Cstring
    alias::Cstring
    fallback::Cstring
    mask::UInt32
    number::UInt8
    umask::UInt8
    reserved::UInt8
    is_fixed::UInt8
end

"""
    Event

One performance event from the kpep database.

* `name`: mnemonic, e.g. `"L1D_CACHE_MISS_LD_NONSPEC"`
* `alias`: Instruments' friendly alias, or `""`
* `description`: human description, or `""`
* `mask`: bitmask of counter slots this event may be scheduled on
* `fixed`: `true` for the two fixed counters (cycles, instructions)
"""
struct Event
    name::String
    alias::String
    description::String
    errata::String
    fallback::String
    mask::UInt32
    number::UInt8
    fixed::Bool
end

Base.show(io::IO, e::Event) = print(io, "Event(", e.name, e.fixed ? ", fixed" : "", ", mask=0b", string(e.mask; base=2, pad=10), ")")

_cstr(p::Cstring) = p == C_NULL ? "" : unsafe_string(p)

frameworks_present() = Sys.isapple() && Sys.ARCH === :aarch64 && isdir(dirname(KPERFDATA))

"""Whether the private frameworks exist and a kpep database exists for this CPU (false on most VMs)."""
function available()
    frameworks_present() || return false
    return try
        _db_handle().ptr != C_NULL
    catch
        false
    end
end

function _load()
    _kpep[] == C_NULL || return
    frameworks_present() || error("ApplePerf.KPEP needs macOS on Apple Silicon with the private kperfdata framework")
    _kpep[] = dlopen(KPERFDATA)
    _kperf[] = dlopen(KPERF)
    return
end
sym(s::Symbol) = (_load(); dlsym(_kpep[], s))
kperf_sym(s::Symbol) = (_load(); dlsym(_kperf[], s))

@static if isdefined(Base, :OncePerProcess)
    _once(f) = Base.OncePerProcess(f)
else
    function _once(f)
        r = Ref{Any}(nothing)
        return () -> (r[] === nothing && (r[] = f()); r[])
    end
end

# kpep_db_create fails (code 7) when macOS has no event database for the CPU it
# runs on, e.g. inside virtual machines such as CI runners. Remember the outcome
# instead of letting a OncePerProcess initializer fail permanently.
const _db_handle = _once() do
    r = Ref{Ptr{Cvoid}}(C_NULL)
    rc = ccall(sym(:kpep_db_create), Cint, (Cstring, Ref{Ptr{Cvoid}}), C_NULL, r)
    (ptr = rc == 0 ? r[] : C_NULL, rc = Int(rc))
end
"""Handle to the kpep database for the current CPU (created once per process)."""
function db()
    h = _db_handle()
    h.ptr == C_NULL && error("no kpep performance-event database for this CPU (kpep_db_create failed with code $(h.rc)). " *
                             "Hardware counters are unavailable here; this is expected inside virtual machines.")
    return h.ptr
end

"""Name of the kpep database for this CPU, e.g. `"as12"`."""
function db_name()
    r = Ref{Cstring}(C_NULL)
    ccall(sym(:kpep_db_name), Cint, (Ptr{Cvoid}, Ref{Cstring}), db(), r)
    return _cstr(r[])
end

const KPC_CLASS_FIXED_MASK = UInt32(1)
const KPC_CLASS_CONFIGURABLE_MASK = UInt32(2)

const _counter_slots = _once() do
    f = ccall(kperf_sym(:kpc_get_counter_count), UInt32, (UInt32,), KPC_CLASS_FIXED_MASK)
    c = ccall(kperf_sym(:kpc_get_counter_count), UInt32, (UInt32,), KPC_CLASS_CONFIGURABLE_MASK)
    (fixed = Int(f), configurable = Int(c))
end
"""
    counter_slots() -> (fixed = n, configurable = m)

Number of fixed and configurable hardware counters on this CPU (2 + 8 on M1–M5).
"""
counter_slots() = _counter_slots()

"""
    events() -> Vector{Event}

All performance events the kpep database defines for this CPU (read once per process).
"""
events() = _events()
const _events = _once() do
    n = Ref{Csize_t}(0)
    ccall(sym(:kpep_db_events_count), Cint, (Ptr{Cvoid}, Ref{Csize_t}), db(), n)
    buf = Vector{Ptr{KpepEventRaw}}(undef, n[])
    ccall(sym(:kpep_db_events), Cint, (Ptr{Cvoid}, Ptr{Ptr{KpepEventRaw}}, Csize_t), db(), buf, sizeof(buf))
    evs = Event[]
    for p in buf
        r = unsafe_load(p)
        # the is_fixed byte is not reliably set in every database; the fixed counters are
        # the only events confined to slots 0/1.
        fixed = r.is_fixed != 0 || (r.mask != 0 && (r.mask & ~UInt32(3)) == 0)
        push!(evs, Event(_cstr(r.name), _cstr(r.alias), _cstr(r.description), _cstr(r.errata), _cstr(r.fallback), r.mask, r.number, fixed))
    end
    evs
end

"""Mnemonics of all events, sorted."""
event_names() = sort!([e.name for e in events()])

"""
    event(name) -> Event

Look up an event by mnemonic or alias (case-insensitive). Errors if unknown.
"""
function event(name::AbstractString)
    for e in events()
        (e.name == name || e.alias == name) && return e
    end
    lname = lowercase(name)
    for e in events()
        (lowercase(e.name) == lname || lowercase(e.alias) == lname) && return e
    end
    close = filter(n -> occursin(lowercase(replace(name, r"[^A-Za-z0-9]" => "")), lowercase(replace(n, "_" => ""))), event_names())
    hint = isempty(close) ? "" : " Did you mean one of: " * join(first(close, 5), ", ") * "?"
    error("unknown PMU event '$name' on this CPU ($(db_name()))." * hint)
end
event(e::Event) = e

"""
    describe([pattern])

Print every event (or those whose name/description matches `pattern`) with its
slot mask and description.
"""
function describe(pattern = ""; io::IO = stdout)
    re = pattern isa Regex ? pattern : Regex(string(pattern), "i")
    println(io, "kpep database: ", db_name(), "  counters: ", counter_slots())
    for e in sort(events(); by = x -> (!x.fixed, x.mask, x.name))
        (occursin(re, e.name) || occursin(re, e.description) || occursin(re, e.alias)) || continue
        print(io, rpad(e.name, 42), " mask=", string(e.mask; base = 2, pad = 10), e.fixed ? " fixed " : "       ")
        isempty(e.alias) || print(io, " [", e.alias, "]")
        isempty(e.description) || print(io, "  ", e.description)
        println(io)
    end
end

# ---------------------------------------------------------------------------
# Conflict planning.
#
# Every event has a mask of counter slots it may live on. Instruments (and the
# kernel) book slots greedily, first free slot from the low bit, in insertion
# order — which is why order matters there. We solve the assignment exactly
# (bipartite matching), so `can_coexist` is order independent, and `schedule`
# also returns an insertion order that the greedy booker accepts.
# ---------------------------------------------------------------------------

function _match!(evs::Vector{Event}, i::Int, used::Vector{Int}, seen::AbstractVector{Bool})
    m = evs[i].mask
    for slot in 0:31
        (m >> slot) & 1 == 1 || continue
        seen[slot + 1] && continue
        seen[slot + 1] = true
        if used[slot + 1] == 0 || _match!(evs, used[slot + 1], used, seen)
            used[slot + 1] = i
            return true
        end
    end
    return false
end

"""
    schedule(events) -> Dict{String,Int} or nothing

Assign each event to a distinct counter slot honoring its mask. Returns the
slot index per event, or `nothing` if no assignment exists.
"""
function schedule(names)
    evs = Event[event(n) for n in names]
    used = zeros(Int, 32)
    for i in eachindex(evs)
        _match!(evs, i, used, falses(32)) || return nothing
    end
    return Dict(evs[i].name => slot - 1 for slot in eachindex(used) if used[slot] != 0 for i in (used[slot],))
end

"""
    can_coexist(events...) -> Bool

Whether all the given events can be counted at the same time on this CPU.
"""
can_coexist(names...) = schedule(collect(Iterators.flatten(map(n -> n isa AbstractString || n isa Event ? (n,) : n, names)))) !== nothing

"""
    greedy_order(events) -> Vector{String}

An insertion order that Instruments' first-free-slot booker accepts (narrowest
masks first). Errors if the set cannot coexist at all.
"""
function greedy_order(names)
    evs = Event[event(n) for n in names]
    s = schedule([e.name for e in evs])
    s === nothing && error("events cannot be scheduled together: " * join([e.name for e in evs], ", ") * ". Try `plan_groups`.")
    return [e.name for e in sort(evs; by = e -> (count_ones(e.mask), e.mask))]
end

"""
    plan_groups(events) -> Vector{Vector{String}}

Split a list of events into the fewest groups that can each be counted
simultaneously (greedy first-fit). Use with `KPC.measure(f, groups)` to
multiplex across repeated runs, or run one `profile` per group.
"""
function plan_groups(names)
    evs = [event(n).name for n in names]
    groups = Vector{String}[]
    for e in evs
        placed = false
        for g in groups
            if schedule(vcat(g, e)) !== nothing
                push!(g, e); placed = true; break
            end
        end
        placed || push!(groups, [e])
    end
    return groups
end

end # module KPEP
