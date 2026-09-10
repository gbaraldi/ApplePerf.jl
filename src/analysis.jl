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
using PProf, ProtoBuf, CodecZlib
using ..XCTrace
using ..KPEP
using ..XCTrace: XNode, Table, TraceInfo, fmt, raw, rawint, child, colindex

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
    remarks::Vector{Tuple{Int,String,String}}   # (time, tid, remark) from Instruments' guided modes
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

function _regions(t::Table)
    isempty(t.rows) && return Region[]
    it = colindex(t, "Timestamp"); ity = colindex(t, "Event Type"); iid = colindex(t, "Signpost identifier")
    ith = colindex(t, "Thread"); imsg = colindex(t, "Message"); inm = colindex(t, "Name")
    isub = findfirst(==("Subsystem"), t.columns)
    open_ = Dict{Tuple{String,String},Tuple{Int,String}}()
    regs = Region[]
    seen = Set{Tuple{Int,String,String,String}}()     # the same event appears once per table instance
    for r in sort(t.rows; by = r -> rawint(r[it]))
        isub !== nothing && fmt(r[isub]) != "org.julialang.ApplePerf" && !occursin("julia", fmt(r[isub])) && continue
        tid = _tid(r[ith]); id = fmt(r[iid]); ty = fmt(r[ity]); time = rawint(r[it])
        (time, tid, id, ty) in seen && continue
        push!(seen, (time, tid, id, ty))
        name = fmt(r[imsg]); isempty(name) && (name = fmt(r[inm]))
        if ty == "Begin"
            open_[(tid, id)] = (time, name)
        elseif ty == "End" && haskey(open_, (tid, id))
            s, nm = pop!(open_, (tid, id))
            push!(regs, Region(nm, id, tid, s, time))
        end
    end
    return regs
end

function _samples_time_profile(t::Table, symbolize_jit)
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
function _samples_counters_profile(t::Table, symbolize_jit)
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

function _counter_rows(t::Table)
    out = Sample[]
    isempty(t.rows) && return out
    it = colindex(t, "Timestamp"); id = colindex(t, "Duration"); ith = colindex(t, "Thread"); iv = colindex(t, "Value")
    for r in t.rows
        r[iv].tag == "sentinel" && continue
        push!(out, Sample(rawint(r[it]), rawint(r[id]), _tid(r[ith]), 0, Frame[], [parse(Int, s) for s in split(raw(r[iv]))]))
    end
    return out
end

function _metric_names(ti::TraceInfo)
    toc = ti.toc
    m = match(r"metricLegend: \\?&quot;(.*?)\\?&quot;", toc)
    names = String[]
    if m !== nothing
        for x in eachmatch(r"index (\d+): ([^\\\n]+?) *(?:\\n|$)", m[1])
            push!(names, String(strip(x[2])))
        end
    end
    return names
end

function _pt(tabs::Dict{String,Table})
    pts = Tuple{Int,String,Int,Int}[]
    gaps = Tuple{Int,String}[]
    if haskey(tabs, "processor-trace-points")
        t = tabs["processor-trace-points"]
        if !isempty(t.rows)
            it = colindex(t, "Timestamp"); ith = colindex(t, "Thread"); ii = colindex(t, "Instructions"); ic = colindex(t, "Cycles")
            for r in t.rows
                push!(pts, (rawint(r[it]), _tid(r[ith]), rawint(r[ii]), rawint(r[ic])))
            end
        end
    end
    if haskey(tabs, "processor-trace-gaps")
        for r in tabs["processor-trace-gaps"].rows
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
    ti = XCTrace.info(trace)                       # one xctrace call for the toc
    tables = XCTrace.list_tables(ti)
    wanted = filter(in(tables), ["os-signpost", "counters-profile", "time-profile", "CounterMetricByThread", "CountingModeSamples", "processor-trace-points", "processor-trace-gaps"])
    "counters-profile" in wanted && filter!(!=("time-profile"), wanted)   # counters-profile supersedes it
    tabs = XCTrace.export_tables(ti, wanted)       # one xctrace call for every table we need
    regions = haskey(tabs, "os-signpost") ? _regions(tabs["os-signpost"]) : Region[]
    samples = Sample[]
    unit = "ns"; label = "time"
    counter_names = String[]
    if haskey(tabs, "counters-profile")
        samples = _samples_counters_profile(tabs["counters-profile"], symbolize_jit)
        attrs = XCTrace.table_attributes(ti, "counters-profile")
        if get(attrs, "trigger", "") == "pmi"
            unit = replace(get(attrs, "pmi-event", "event"), "\"" => "", "&quot;" => "")
            label = unit
        end
        pmc = replace(get(attrs, "pmc-events", ""), "&quot;" => "", "\"" => "")
        # Instruments reports events by alias where one exists ("Cycles"); normalise to mnemonics
        isempty(strip(pmc)) || (counter_names = [_mnemonic(n) for n in split(strip(pmc), r"[ ,]+")])
    end
    if isempty(samples) && haskey(tabs, "time-profile")
        samples = _samples_time_profile(tabs["time-profile"], symbolize_jit)
    end
    crows = haskey(tabs, "CounterMetricByThread") ? _counter_rows(tabs["CounterMetricByThread"]) : Sample[]
    if !isempty(crows)
        counter_names = _metric_names(ti)
        n = length(crows[1].values)
        length(counter_names) >= n || (counter_names = ["metric$(i-1)" for i in 1:n])
        counter_names = counter_names[1:n]
    end
    pts, gaps = _pt(tabs)
    remarks = Tuple{Int,String,String}[]
    if haskey(tabs, "CountingModeSamples") && !isempty(tabs["CountingModeSamples"].rows)
        t = tabs["CountingModeSamples"]
        it = colindex(t, "Timestamp"); ith = colindex(t, "Thread"); ir = colindex(t, "Remark")
        for r in t.rows
            r[ir].tag == "sentinel" && continue
            push!(remarks, (rawint(r[it]), _tid(r[ith]), fmt(r[ir])))
        end
    end
    return ProfileResult(String(trace), String(template), unit, label, regions, samples, counter_names, crows, pts, gaps, pid, remarks)
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
    remarks::Dict{String,Int}     # Instruments' bottleneck remarks (guided modes), sample counts
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
        rem = Dict{String,Int}()
        for (t, tid, name) in res.remarks, r in regs
            (tid == r.tid && r.start <= t <= r.stop) && (rem[name] = get(rem, name, 0) + 1)
        end
        push!(out, RegionSummary(nm, length(regs), sum(duration, regs), ns, w, cnt, ins, cyc, gaps, rem))
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
    isempty(res.counter_rows) || println(io, "  guided-mode metrics below are Instruments' derived interval values, not raw counts; see the remarks lines")
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
            if !isempty(r.remarks)
                tot = sum(values(r.remarks))
                println(io, "      remarks: ", join(["$k $(round(Int, 100v / tot))%" for (k, v) in sort(collect(r.remarks); by = last, rev = true)], ", "))
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

# --- pprof via PProf.jl's protobuf types ----------------------------------------

const PB = PProf.perftools.profiles

"""
    pprof(result, path = "profile.pb.gz"; region = nothing, web = false, webhost = "localhost", webport = 57599)

Write a gzipped pprof profile using PProf.jl's `profile.proto` types. View with
`PProf.refresh(file = path)`, `pprof -http=: path`, or pass `web = true` to
start PProf's bundled web UI right away.

Sample values are `[samples, weight, counters...]`: weight is time in
nanoseconds (timer sampling) or trigger-event counts (event-triggered), then
one column per event of a manual event list, selectable in pprof with
`-sample_index=<EVENT>`; the first event is the default view. JIT frames are
symbolized and inlined frames become multi-line locations.

Every sample carries a `thread` label and one `region` label per enclosing
region: `-tagfocus=region=gather`, `-tagignore=region=profile`, `-tagroot=region`.
"""
function pprof(res::ProfileResult, path::AbstractString = "profile.pb.gz"; region = nothing, web::Bool = false,
               webhost::AbstractString = "localhost", webport::Integer = 57599)
    strings = String[""]; sidx = Dict{String,Int}("" => 0)
    str(s) = get!(sidx, s) do; push!(strings, s); length(strings) - 1; end
    funcs = Dict{Tuple{String,String},Int}()            # (name, file) -> id
    locs = Dict{Vector{Tuple{Int,Int}},Int}()           # [(func_id, line)...] -> id
    locaddr = Dict{Int,UInt64}()
    pbsamples = PB.Sample[]
    k_thread = str("thread"); k_region = str("region")
    for s in samples(res, region)
        isempty(s.stack) && continue
        ids = UInt64[]
        i = 1
        while i <= length(s.stack)                       # inlined frames join their caller's location
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
        vals = Int64[1, s.weight]
        for c in eachindex(res.counter_names)
            push!(vals, c <= length(s.values) ? s.values[c] : 0)
        end
        labels = PB.Label[PB.Label(key = k_thread, str = str(s.tid))]
        for nm in enclosing(res, s)
            push!(labels, PB.Label(key = k_region, str = str(nm)))
        end
        push!(pbsamples, PB.Sample(location_id = ids, value = vals, label = labels))
    end
    unit = res.weight_unit == "ns" ? "nanoseconds" : "count"
    sample_type = PB.ValueType[PB.ValueType(var"#type" = str("samples"), unit = str("count")),
                               PB.ValueType(var"#type" = str(res.weight_label), unit = str(unit))]
    for c in res.counter_names
        push!(sample_type, PB.ValueType(var"#type" = str(c), unit = str("count")))
    end
    locations = [PB.Location(id = lid, mapping_id = 1, address = locaddr[lid],
                             line = [PB.Line(function_id = fid, line = ln) for (fid, ln) in lines])
                 for (lines, lid) in sort(collect(locs); by = last)]
    functions = [PB.var"Function"(id = fid, name = str(name), system_name = str(name), filename = str(file))
                 for ((name, file), fid) in sort(collect(funcs); by = last)]
    mapping = [PB.Mapping(id = 1, memory_start = 0, memory_limit = typemax(UInt64) >> 1, filename = str("julia"),
                          has_functions = true, has_filenames = true, has_line_numbers = true, has_inline_frames = true)]
    comment = [str("ApplePerf.jl: " * res.template * " trace " * res.trace)]
    prof = PB.Profile(sample_type = sample_type, sample = pbsamples, mapping = mapping, location = locations,
                      var"#function" = functions, string_table = strings, drop_frames = 0, keep_frames = 0,
                      time_nanos = round(Int, time() * 1e9), duration_nanos = 0,
                      period_type = PB.ValueType(var"#type" = str(res.weight_label), unit = str(unit)), period = 0,
                      comment = comment,
                      # index into the string table of the preferred value type's name
                      default_sample_type = str(isempty(res.counter_names) ? res.weight_label : res.counter_names[1]))
    io = GzipCompressorStream(open(path, "w"))
    try
        ProtoBuf.encode(ProtoBuf.ProtoEncoder(io), prof)
    finally
        close(io)
    end
    web && PProf.refresh(; webhost, webport, file = path)
    return path
end

end # module Analysis
