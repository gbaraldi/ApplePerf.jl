"""
    ApplePerf.Analysis

Turn an xctrace trace into per-region counter summaries and symbolized,
attributed samples. Works on traces recorded by [`profile`](@ref) (in which
case JIT frames are symbolized against the live process) or on any trace file
(`analyze(path)`; JIT frames then stay as addresses unless a symbol map is
supplied).
"""
module Analysis

using Printf, Statistics
using ..XCTrace
using ..KPEP
using ..XCTrace: XNode, Table, fmt, raw, rawint, child, colindex

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

struct Frame
    addr::UInt64
    func::String
    file::String
    line::Int
    binary::String
    inlined::Bool
end
Base.show(io::IO, f::Frame) = print(io, f.func, isempty(f.file) ? "" : " at $(basename(f.file)):$(f.line)", f.inlined ? " [inlined]" : "")

"""
    Sample

One profiler sample. `weight` is in nanoseconds for timer sampling, or in
occurrences of the trigger event for event-based (PMI) sampling. `stack` is
leaf-first. `values` holds counter values attached to the sample, if any.
"""
struct Sample
    time::Int
    duration::Int
    tid::String
    weight::Int
    stack::Vector{Frame}
    values::Vector{Int}
end

struct Region
    name::String
    id::String
    tid::String
    start::Int
    stop::Int
end
duration(r::Region) = r.stop - r.start
Base.show(io::IO, r::Region) = @printf(io, "Region(%s, %.3f ms, tid %s)", r.name, duration(r) / 1e6, r.tid)

"""
    ProfileResult

Everything `profile`/`analyze` extracted from a trace. Query it with
[`regions`](@ref), [`by_function`](@ref), [`by_line`](@ref), [`counters`](@ref),
export it with [`collapsed`](@ref) or [`pprof`](@ref), or
`open_in_instruments(result.trace)`.
"""
mutable struct ProfileResult
    trace::String
    template::String
    weight_unit::String                  # "ns" or an event mnemonic
    weight_label::String                 # "time" or "L1D_CACHE_MISS_LD_NONSPEC"
    regions::Vector{Region}
    samples::Vector{Sample}
    counter_names::Vector{String}        # names for Sample.values / counter rows
    counter_rows::Vector{Sample}         # per-thread counter intervals (no stacks)
    pt_points::Vector{Tuple{Int,String,Int,Int}}  # (time, tid, instructions, cycles) from Processor Trace
    pt_gaps::Vector{Tuple{Int,String}}
    julia_pid::Int
end

# ---------------------------------------------------------------------------
# Symbolization
# ---------------------------------------------------------------------------

const _lookup_cache = Dict{UInt64,Vector{Frame}}()

_is_address_name(s) = isempty(s) || startswith(s, "0x")

"""
    symbolize(addr; leaf) -> Vector{Frame}

Resolve an address in *this* process (JIT code included) to frames, innermost
inlined frame first. Non-leaf addresses are return addresses and are looked
up one byte back.
"""
function symbolize(addr::UInt64; leaf::Bool = true)
    key = leaf ? addr : addr - 1
    get!(_lookup_cache, key) do
        frames = Frame[]
        try
            for sf in Base.StackTraces.lookup(Ptr{Cvoid}(key))
                sf.func === Symbol("") && continue
                fn = String(sf.func)
                if sf.linfo isa Core.MethodInstance
                    fn = string(sf.linfo.def isa Method ? sf.linfo.def.name : sf.func)
                    # keep the signature for disambiguation
                    fn = sprint(show, sf.linfo; context = :compact => true)
                    fn = replace(fn, r"^MethodInstance for " => "")
                end
                push!(frames, Frame(addr, fn, String(sf.file), Int(sf.line), sf.from_c ? "native" : "julia", sf.inlined))
            end
        catch
        end
        isempty(frames) && push!(frames, Frame(addr, "0x" * string(addr; base = 16), "", 0, "?", false))
        frames
    end
end

function _frame_from_export(n::XNode, leaf::Bool, symbolize_jit::Bool)
    addr = haskey(n, "addr") ? parse(UInt64, n["addr"]) : UInt64(0)
    name = get(n, "name", "")
    bin = child(n, "binary")
    binname = bin === nothing ? "" : get(bin, "name", "")
    src = child(n, "source")
    file = ""; line = 0
    if src !== nothing
        line = parse(Int, get(src, "line", "0"))
        p = child(src, "path"); file = p === nothing ? "" : fmt(p)
    end
    if _is_address_name(name) && addr != 0 && symbolize_jit
        return symbolize(addr; leaf)
    end
    return [Frame(addr, isempty(name) ? "0x" * string(addr; base = 16) : name, file, line, isempty(binname) ? "?" : binname, get(n, "inlined", "") == "true")]
end

function _stack(bt::XNode, symbolize_jit::Bool)
    stack = Frame[]
    for (i, fr) in enumerate(bt.children)
        fr.tag == "frame" || continue
        append!(stack, _frame_from_export(fr, i == 1, symbolize_jit))
    end
    return stack
end

# kperf-bt (time-sample table): text-addresses child holds space separated decimal addresses
function _stack_kperf(bt::XNode, symbolize_jit::Bool)
    ta = child(bt, "text-addresses")
    ta === nothing && return Frame[]
    stack = Frame[]
    for (i, s) in enumerate(split(raw(ta)))
        a = parse(UInt64, s); a == 0 && continue
        append!(stack, symbolize_jit ? symbolize(a; leaf = i == 1) : [Frame(a, "0x" * string(a; base = 16), "", 0, "?", false)])
    end
    return stack
end

_tid(n::XNode) = (t = child(n, "tid"); t === nothing ? fmt(n) : fmt(t))
_pid(n::XNode) = (p = child(n, "pid"); p === nothing ? 0 : rawint(p))

# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

function _regions(trace)
    t = XCTrace.export_table(trace, "os-signpost")
    isempty(t.rows) && return Region[]
    it = colindex(t, "Timestamp"); ity = colindex(t, "Event Type"); iid = colindex(t, "Signpost identifier")
    ith = colindex(t, "Thread"); imsg = colindex(t, "Message"); inm = colindex(t, "Name")
    isub = findfirst(==("Subsystem"), t.columns)
    open_ = Dict{Tuple{String,String},Tuple{Int,String}}()
    regs = Region[]
    for r in sort(t.rows; by = r -> rawint(r[it]))
        isub !== nothing && fmt(r[isub]) != "org.julialang.ApplePerf" && !occursin("julia", fmt(r[isub])) && continue
        tid = _tid(r[ith]); id = fmt(r[iid]); ty = fmt(r[ity])
        name = fmt(r[imsg]); isempty(name) && (name = fmt(r[inm]))
        if ty == "Begin"
            open_[(tid, id)] = (rawint(r[it]), name)
        elseif ty == "End" && haskey(open_, (tid, id))
            s, nm = pop!(open_, (tid, id))
            push!(regs, Region(nm, id, tid, s, rawint(r[it])))
        end
    end
    return regs
end

function _samples_time_profile(trace, symbolize_jit)
    t = XCTrace.export_table(trace, "time-profile")
    out = Sample[]
    isempty(t.rows) && return out
    it = colindex(t, "Sample Time"); ith = colindex(t, "Thread"); iw = colindex(t, "Weight"); ib = colindex(t, "Backtrace")
    for r in t.rows
        bt = r[ib]; bt.tag == "sentinel" && continue
        push!(out, Sample(rawint(r[it]), 0, _tid(r[ith]), rawint(r[iw]), _stack(bt, symbolize_jit), Int[]))
    end
    return out
end

# counters-profile: PMI (event) samples or timer samples with counter arrays
function _samples_counters_profile(trace, symbolize_jit)
    t = XCTrace.export_table(trace, "counters-profile")
    out = Sample[]
    isempty(t.rows) && return out
    it = colindex(t, "Sample Time"); ith = colindex(t, "Thread"); iw = colindex(t, "Weight"); ib = colindex(t, "Backtrace")
    iv = findfirst(==("Counter Value Array"), t.columns)
    for r in t.rows
        bt = r[ib]
        vals = Int[]
        if iv !== nothing && r[iv].tag != "sentinel"
            vals = [parse(Int, s) for s in split(raw(r[iv]))]
        end
        bt.tag == "sentinel" && isempty(vals) && continue
        w = r[iw].tag == "sentinel" ? 0 : rawint(r[iw])
        push!(out, Sample(rawint(r[it]), 0, _tid(r[ith]), w, bt.tag == "sentinel" ? Frame[] : _stack(bt, symbolize_jit), vals))
    end
    return out
end

function _counter_rows(trace)
    t = XCTrace.export_table(trace, "CounterMetricByThread")
    out = Sample[]
    isempty(t.rows) && return out
    it = colindex(t, "Timestamp"); id = colindex(t, "Duration"); ith = colindex(t, "Thread"); iv = colindex(t, "Value")
    for r in t.rows
        r[iv].tag == "sentinel" && continue
        push!(out, Sample(rawint(r[it]), rawint(r[id]), _tid(r[ith]), 0, Frame[], [parse(Int, s) for s in split(raw(r[iv]))]))
    end
    return out
end

function _metric_names(trace)
    toc = XCTrace.toc(trace)
    m = match(r"metricLegend: \\?&quot;(.*?)\\?&quot;", toc)
    names = String[]
    if m !== nothing
        for x in eachmatch(r"index (\d+): ([^\\\n]+?) *(?:\\n|$)", m[1])
            push!(names, String(strip(x[2])))
        end
    end
    return names
end

function _pt(trace)
    pts = Tuple{Int,String,Int,Int}[]
    gaps = Tuple{Int,String}[]
    tables = XCTrace.list_tables(trace)
    if "processor-trace-points" in tables
        t = XCTrace.export_table(trace, "processor-trace-points")
        if !isempty(t.rows)
            it = colindex(t, "Timestamp"); ith = colindex(t, "Thread"); ii = colindex(t, "Instructions"); ic = colindex(t, "Cycles")
            for r in t.rows
                push!(pts, (rawint(r[it]), _tid(r[ith]), rawint(r[ii]), rawint(r[ic])))
            end
        end
    end
    if "processor-trace-gaps" in tables
        XCTrace.export_table(trace, "processor-trace-gaps") do cols, r
            push!(gaps, (rawint(r[1]), _tid(r[3])))
        end
    end
    return pts, gaps
end

function _mnemonic(name)
    name = String(name)
    try
        for e in KPEP.events()
            (e.name == name || e.alias == name) && return e.name
        end
    catch
    end
    return name
end

"""
    analyze(trace; symbolize_jit = true, template = "") -> ProfileResult

Extract regions, samples and counters from a trace. `symbolize_jit` resolves
unnamed frames against the *current* process, which is only meaningful for a
trace of this very process (as `profile` does).
"""
function analyze(trace::AbstractString; symbolize_jit::Bool = true, template::AbstractString = "", pid::Integer = getpid())
    tables = XCTrace.list_tables(trace)
    regions = "os-signpost" in tables ? _regions(trace) : Region[]
    samples = Sample[]
    unit = "ns"; label = "time"
    counter_names = String[]
    if "counters-profile" in tables
        samples = _samples_counters_profile(trace, symbolize_jit)
        attrs = XCTrace.table_attributes(trace, "counters-profile")
        if get(attrs, "trigger", "") == "pmi"
            unit = replace(get(attrs, "pmi-event", "event"), "\"" => "", "&quot;" => "")
            label = unit
        end
        pmc = replace(get(attrs, "pmc-events", ""), "&quot;" => "", "\"" => "")
        # Instruments reports events by alias where one exists ("Cycles"); normalise to mnemonics
        isempty(strip(pmc)) || (counter_names = [_mnemonic(n) for n in split(strip(pmc), r"[ ,]+")])
    end
    if isempty(samples) && "time-profile" in tables
        samples = _samples_time_profile(trace, symbolize_jit)
    end
    crows = "CounterMetricByThread" in tables ? _counter_rows(trace) : Sample[]
    if !isempty(crows)
        counter_names = _metric_names(trace)
        n = length(crows[1].values)
        length(counter_names) >= n || (counter_names = ["metric$(i-1)" for i in 1:n])
        counter_names = counter_names[1:n]
    end
    pts, gaps = _pt(trace)
    return ProfileResult(String(trace), String(template), unit, label, regions, samples, counter_names, crows, pts, gaps, pid)
end

# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

_overlap(a0, a1, b0, b1) = max(0, min(a1, b1) - max(a0, b0))
_inside(r::Region, s::Sample) = s.tid == r.tid && r.start <= s.time <= r.stop

"""Samples (with stacks) that fell inside any region named `name` (or all samples if `nothing`)."""
function samples(res::ProfileResult, name = nothing)
    name === nothing && return res.samples
    regs = filter(r -> r.name == name, res.regions)
    return filter(s -> any(r -> _inside(r, s), regs), res.samples)
end

"""
    RegionSummary

Per region name: number of intervals, total wall time (ns), number of stack
samples inside, summed sample weight, per-counter totals (pro-rated for
interval counters), and Processor Trace instructions/cycles if recorded.
"""
struct RegionSummary
    name::String
    count::Int
    total_ns::Int
    nsamples::Int
    weight::Int
    counters::Dict{String,Float64}
    pt_instructions::Int
    pt_cycles::Int
    pt_gaps::Int
end

"""
    regions(result) -> Vector{RegionSummary}

Summaries for every distinct region name, in order of first appearance.
"""
function regions(res::ProfileResult)
    names = unique([r.name for r in res.regions])
    out = RegionSummary[]
    for nm in names
        regs = filter(r -> r.name == nm, res.regions)
        ns = 0; w = 0; cnt = Dict{String,Float64}(); ins = 0; cyc = 0; gaps = 0
        for s in res.samples
            any(r -> _inside(r, s), regs) || continue
            ns += 1; w += s.weight
            for (i, v) in enumerate(s.values)
                i <= length(res.counter_names) || break
                cnt[res.counter_names[i]] = get(cnt, res.counter_names[i], 0.0) + v
            end
        end
        for c in res.counter_rows, r in regs
            c.tid == r.tid || continue
            ov = _overlap(r.start, r.stop, c.time, c.time + c.duration)
            ov > 0 || continue
            f = ov / c.duration
            for (i, v) in enumerate(c.values)
                i <= length(res.counter_names) || break
                cnt[res.counter_names[i]] = get(cnt, res.counter_names[i], 0.0) + v * f
            end
        end
        for (t, tid, i, c) in res.pt_points, r in regs
            (tid == r.tid && r.start <= t <= r.stop) && (ins += i; cyc += c)
        end
        for (t, tid) in res.pt_gaps, r in regs
            (tid == r.tid && r.start <= t <= r.stop) && (gaps += 1)
        end
        push!(out, RegionSummary(nm, length(regs), sum(duration, regs), ns, w, cnt, ins, cyc, gaps))
    end
    return out
end

"""Per-counter totals for a region name (or the whole trace)."""
function counters(res::ProfileResult, name = nothing)
    if name === nothing
        d = Dict{String,Float64}()
        for c in res.counter_rows, (i, v) in enumerate(c.values)
            i <= length(res.counter_names) || break
            d[res.counter_names[i]] = get(d, res.counter_names[i], 0.0) + v
        end
        for s in res.samples, (i, v) in enumerate(s.values)
            i <= length(res.counter_names) || break
            d[res.counter_names[i]] = get(d, res.counter_names[i], 0.0) + v
        end
        return d
    end
    for r in regions(res)
        r.name == name && return r.counters
    end
    error("no region named $name")
end

"""Names of every region interval enclosing the sample (outermost first)."""
function enclosing(res::ProfileResult, s::Sample)
    names = String[]
    for r in res.regions
        _inside(r, s) && push!(names, r.name)
    end
    return unique!(sort!(names; by = n -> -sum(duration(r) for r in res.regions if r.name == n)))
end

"""
    weight(result, sample, by = nothing)

The sample's weight: `nothing` selects the sampling weight (time or trigger
event), a counter name selects that counter's per-sample delta.
"""
function weight(res::ProfileResult, s::Sample, by = nothing)
    by === nothing && return s.weight
    i = findfirst(==(_mnemonic(by)), res.counter_names)
    i === nothing && error("no counter $by in this profile; have $(res.counter_names)")
    return i <= length(s.values) ? s.values[i] : 0
end

_leaf(s::Sample) = isempty(s.stack) ? nothing : s.stack[1]
_outer_leaf(s::Sample) = (i = findfirst(f -> !f.inlined, s.stack); i === nothing ? _leaf(s) : s.stack[i])

"""
    by_function(result; region = nothing, top = 25, inlined = false, by = nothing) -> Vector{Pair{String,Int}}

Self weight per function (leaf frame). With `inlined = true` the innermost
inlined callee is charged instead of the function it was inlined into. `by`
selects a counter column instead of the sampling weight (see [`weight`](@ref)).
"""
function by_function(res::ProfileResult; region = nothing, top::Integer = 25, inlined::Bool = false, by = nothing)
    acc = Dict{String,Int}()
    for s in samples(res, region)
        f = inlined ? _leaf(s) : _outer_leaf(s)
        f === nothing && continue
        acc[f.func] = get(acc, f.func, 0) + weight(res, s, by)
    end
    return first(sort!(collect(acc); by = last, rev = true), top)
end

"""
    by_line(result; region = nothing, top = 25) -> Vector{Pair{String,Int}}

Self weight per source line (`file:line  function`), innermost inlined frame.
"""
function by_line(res::ProfileResult; region = nothing, top::Integer = 25, by = nothing)
    acc = Dict{String,Int}()
    for s in samples(res, region)
        f = _leaf(s); f === nothing && continue
        key = isempty(f.file) ? f.func : "$(f.file):$(f.line)  $(f.func)"
        acc[key] = get(acc, key, 0) + weight(res, s, by)
    end
    return first(sort!(collect(acc); by = last, rev = true), top)
end

"""
    inclusive(result; region = nothing, top = 25) -> Vector{Pair{String,Int}}

Total (inclusive) weight per function: a sample counts once for every distinct
function on its stack.
"""
function inclusive(res::ProfileResult; region = nothing, top::Integer = 25, by = nothing)
    acc = Dict{String,Int}()
    for s in samples(res, region)
        for fn in unique([f.func for f in s.stack])
            acc[fn] = get(acc, fn, 0) + weight(res, s, by)
        end
    end
    return first(sort!(collect(acc); by = last, rev = true), top)
end

# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

_fmtw(res, w) = res.weight_unit == "ns" ? @sprintf("%10.3f ms", w / 1e6) : @sprintf("%13s", _commas(w))
_commas(n::Integer) = replace(string(n), r"(?<=\d)(?=(\d{3})+$)" => ",")

function Base.show(io::IO, ::MIME"text/plain", res::ProfileResult)
    println(io, "ApplePerf.ProfileResult  (", res.template, ")  trace: ", res.trace)
    println(io, "  ", length(res.samples), " samples weighted by ", res.weight_label, ", ", length(res.regions), " region intervals, ",
            length(res.counter_rows), " counter rows", isempty(res.pt_points) ? "" : ", $(length(res.pt_points)) processor-trace points")
    regs = regions(res)
    if !isempty(regs)
        println(io)
        @printf(io, "  %-28s %6s %12s %8s %14s\n", "region", "runs", "wall", "samples", res.weight_label == "time" ? "sampled time" : res.weight_label)
        for r in regs
            @printf(io, "  %-28s %6d %9.3f ms %8d %14s\n", first(r.name, 28), r.count, r.total_ns / 1e6, r.nsamples,
                    res.weight_unit == "ns" ? @sprintf("%.3f ms", r.weight / 1e6) : _commas(r.weight))
            if !isempty(r.counters)
                for (k, v) in sort(collect(r.counters))
                    @printf(io, "      %-40s %18s\n", k, _commas(round(Int, v)))
                end
            end
            if r.pt_cycles > 0
                @printf(io, "      processor trace: %s instructions, %s cycles, IPC %.2f, %d gaps\n", _commas(r.pt_instructions), _commas(r.pt_cycles), r.pt_instructions / r.pt_cycles, r.pt_gaps)
            end
        end
    end
    if !isempty(res.samples)
        println(io)
        println(io, "  top functions by self ", res.weight_label, ":")
        tot = sum(s.weight for s in res.samples)
        for (fn, w) in by_function(res; top = 12)
            @printf(io, "  %5.1f%% %s  %s\n", 100w / max(tot, 1), _fmtw(res, w), first(fn, 90))
        end
    end
end

"""Print a per-line table for a region (or everything)."""
function report(res::ProfileResult; region = nothing, top::Integer = 30, io::IO = stdout, by = nothing)
    ss = samples(res, region)
    tot = sum(weight(res, s, by) for s in ss; init = 0)
    label = by === nothing ? res.weight_label : by
    println(io, "self ", label, " by source line", region === nothing ? "" : " in region $region", " (", length(ss), " samples):")
    for (k, w) in by_line(res; region, top, by)
        @printf(io, "  %5.1f%% %s  %s\n", 100w / max(tot, 1), by === nothing ? _fmtw(res, w) : @sprintf("%13s", _commas(w)), k)
    end
end

# ---------------------------------------------------------------------------
# Exports: collapsed stacks (speedscope, flamegraph.pl, inferno) and pprof
# ---------------------------------------------------------------------------

_fname(f::Frame) = isempty(f.file) ? f.func : "$(f.func) ($(basename(f.file)):$(f.line))"

"""
    collapsed(result, path; region = nothing, inlined = true)

Write Brendan Gregg "folded" stacks (`root;...;leaf weight`). Load in
speedscope.app, `flamegraph.pl`, or `inferno-flamegraph`.
"""
function collapsed(res::ProfileResult, path::AbstractString; region = nothing, inlined::Bool = true, by = nothing)
    acc = Dict{String,Int}()
    for s in samples(res, region)
        frames = inlined ? s.stack : filter(f -> !f.inlined, s.stack)
        isempty(frames) && continue
        key = join(map(_fname, reverse(frames)), ";")
        acc[key] = get(acc, key, 0) + weight(res, s, by)
    end
    open(path, "w") do io
        for (k, v) in acc
            println(io, replace(k, ' ' => '_'), " ", v)
        end
    end
    return path
end

# --- minimal protobuf writer for pprof's profile.proto -----------------------

function _varint!(io::IO, v::Integer)
    v = UInt64(v)
    while v >= 0x80
        write(io, UInt8(v & 0x7f) | 0x80); v >>= 7
    end
    write(io, UInt8(v))
end
_key!(io, field, wt) = _varint!(io, (field << 3) | wt)
_field_varint!(io, field, v) = (_key!(io, field, 0); _varint!(io, v))
_field_bytes!(io, field, b::Vector{UInt8}) = (_key!(io, field, 2); _varint!(io, length(b)); write(io, b))
_field_str!(io, field, s::AbstractString) = _field_bytes!(io, field, Vector{UInt8}(codeunits(s)))
_field_msg!(io, field, f::Function) = (b = IOBuffer(); f(b); _field_bytes!(io, field, take!(b)))
function _field_packed!(io, field, vs)
    b = IOBuffer(); for v in vs; _varint!(b, v); end
    _field_bytes!(io, field, take!(b))
end

"""
    pprof(result, path; region = nothing)

Write a pprof profile (`profile.proto`, uncompressed). View with
`pprof -http=: file.pb` or `go tool pprof`. JIT frames are symbolized, inlined
frames become multi-line locations. Sample values are `[samples, weight]`
where weight is time in nanoseconds or the trigger event count.

When the recording had a manual event list, every counter becomes an extra
sample type (`<EVENT>/count`), so `-sample_index=L1D_CACHE_MISS_LD_NONSPEC`
switches the whole view to that event; the first counter is the default view.

Every sample carries a `thread` label and one `region` label per enclosing
region, so a single export can be sliced inside pprof:
`pprof -tagfocus=region=gather file.pb`, `-tagignore=region=profile`,
`-tagroot=region` or `-tagroot=thread` to group the graph.
"""
function pprof(res::ProfileResult, path::AbstractString; region = nothing)
    strings = String[""]; sidx = Dict{String,Int}("" => 0)
    str(s) = get!(sidx, s) do; push!(strings, s); length(strings) - 1; end
    funcs = Dict{Tuple{String,String},Int}()            # (name, file) -> id
    locs = Dict{Vector{Tuple{Int,Int}},Int}()           # [(func_id, line)...] -> id
    locaddr = Dict{Int,UInt64}()
    samples_out = Vector{Tuple{Vector{Int},Vector{Int},Vector{Tuple{Int,Int}}}}()   # (locations, values, labels as (key idx, str idx))
    for s in samples(res, region)
        isempty(s.stack) && continue
        ids = Int[]
        # group inlined frames with their caller into one Location
        i = 1
        while i <= length(s.stack)
            j = i
            while j < length(s.stack) && s.stack[j].inlined; j += 1; end
            lines = Tuple{Int,Int}[]
            for f in s.stack[i:j]
                fid = get!(funcs, (f.func, f.file)) do; length(funcs) + 1; end
                push!(lines, (fid, f.line))
            end
            lid = get!(locs, lines) do; length(locs) + 1; end
            locaddr[lid] = s.stack[i].addr
            push!(ids, lid)
            i = j + 1
        end
        labels = Tuple{Int,Int}[(str("thread"), str(s.tid))]
        for nm in enclosing(res, s)
            push!(labels, (str("region"), str(nm)))
        end
        vals = Int[1, s.weight]
        for i in eachindex(res.counter_names)
            push!(vals, i <= length(s.values) ? s.values[i] : 0)
        end
        push!(samples_out, (ids, vals, labels))
    end
    unit = res.weight_unit == "ns" ? "nanoseconds" : "count"
    # intern every string before the string table is written
    s_samples = str("samples"); s_count = str("count"); s_label = str(res.weight_label); s_unit = str(unit); s_julia = str("julia")
    s_comment = str("ApplePerf.jl: " * res.template * " trace " * res.trace)
    s_counters = [str(c) for c in res.counter_names]; s_cnt = str("count")
    s_default = isempty(s_counters) ? s_label : s_counters[1]
    fnames = Dict(fid => (str(name), str(file)) for ((name, file), fid) in funcs)
    open(path, "w") do io
        _field_msg!(io, 1, b -> (_field_varint!(b, 1, s_samples); _field_varint!(b, 2, s_count)))
        _field_msg!(io, 1, b -> (_field_varint!(b, 1, s_label); _field_varint!(b, 2, s_unit)))
        for sc in s_counters
            _field_msg!(io, 1, b -> (_field_varint!(b, 1, sc); _field_varint!(b, 2, s_cnt)))
        end
        for (ids, vals, labels) in samples_out
            _field_msg!(io, 2, b -> begin
                _field_packed!(b, 1, ids); _field_packed!(b, 2, vals)
                for (k, v) in labels
                    _field_msg!(b, 3, bb -> (_field_varint!(bb, 1, k); _field_varint!(bb, 2, v)))
                end
            end)
        end
        _field_msg!(io, 3, b -> (_field_varint!(b, 1, 1); _field_varint!(b, 2, 0); _field_varint!(b, 3, typemax(UInt64) >> 1); _field_varint!(b, 5, s_julia);
                                 # has_functions / has_filenames / has_line_numbers: already symbolized, pprof must not try
                                 _field_varint!(b, 7, 1); _field_varint!(b, 8, 1); _field_varint!(b, 9, 1)))
        for (lines, lid) in sort(collect(locs); by = last)
            _field_msg!(io, 4, b -> begin
                _field_varint!(b, 1, lid); _field_varint!(b, 2, 1); _field_varint!(b, 3, locaddr[lid])
                for (fid, line) in lines
                    _field_msg!(b, 4, bb -> (_field_varint!(bb, 1, fid); _field_varint!(bb, 2, line)))
                end
            end)
        end
        for fid in sort(collect(keys(fnames)))
            sn, sf = fnames[fid]
            _field_msg!(io, 5, b -> (_field_varint!(b, 1, fid); _field_varint!(b, 2, sn); _field_varint!(b, 3, sn); _field_varint!(b, 4, sf)))
        end
        for s in strings
            _field_str!(io, 6, s)
        end
        _field_varint!(io, 9, round(Int, time() * 1e9))
        _field_msg!(io, 11, b -> (_field_varint!(b, 1, s_label); _field_varint!(b, 2, s_unit)))
        _field_varint!(io, 13, s_comment)
        _field_varint!(io, 14, s_default)   # default_sample_type
    end
    return path
end

end # module Analysis
