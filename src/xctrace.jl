"""
    ApplePerf.XCTrace

Drive Instruments' command-line front end `xctrace` (ships with Xcode) and read
back exported tables. No privileges needed: xctrace's own helper carries the
kernel entitlement that hardware counters require.
"""
module XCTrace

using EzXML
using Dates
using Base64
using ..KPEP

# ---------------------------------------------------------------------------
# Locating xctrace
# ---------------------------------------------------------------------------

const _xctrace = Ref{String}("")
function xctrace_path()
    isempty(_xctrace[]) || return _xctrace[]
    p = try
        strip(read(`xcrun --find xctrace`, String))
    catch
        ""
    end
    isempty(p) && error("xctrace not found. Install Xcode (Instruments) and select it with xcode-select.")
    _xctrace[] = String(p)
    return _xctrace[]
end
xctrace_available() = try; !isempty(xctrace_path()); catch; false; end

function version()
    m = match(r"xctrace version ([0-9.]+)", read(`$(xctrace_path()) version`, String))
    return m === nothing ? v"0" : VersionNumber(m[1])
end

templates() = [String(strip(l)) for l in split(read(`$(xctrace_path()) list templates`, String), '\n') if !isempty(strip(l)) && !occursin(':', l)]
instruments() = [String(strip(l)) for l in split(read(`$(xctrace_path()) list instruments`, String), '\n') if !isempty(strip(l)) && !occursin(':', l)]

# ---------------------------------------------------------------------------
# Recording options
# ---------------------------------------------------------------------------

"""
    RecordingOptions(; kwargs...)

Options for the *CPU Counters* instrument, written to the JSON file that
`xctrace record --recording-options` accepts (Xcode 16+).

Two sampling strategies:

* **timer** (default): every thread is sampled every 1 ms (`high_frequency`
  raises this). Sample weights are time. Counters are read in a *guided*
  counting mode chosen by `mode`, e.g. `"bottlenecks"` (Cycles, Instruction
  Delivery / Discarded / Processing bottleneck), `"l1d_miss_sampling"`,
  `"delivery"`, `"processing"`, `"discarded_sampling"`, `"sme_streaming"`.
* **event** (`sample_event = "CORE_ACTIVE_CYCLE"`, `threshold = 200_000`):
  a sample with a call stack is taken every `threshold` occurrences of the
  event on the profiled thread. Sample weights are then event counts, so
  per-function / per-line attribution is in that event's units. Configurable
  events only (`FIXED_*` are rejected by Instruments as PMI triggers).

Independently of the strategy, `events = ["FIXED_CYCLES", "L1D_CACHE_MISS_LD_NONSPEC", ...]`
selects a *manual* event list (up to 2 fixed + 8 configurable, checked with
`KPEP.can_coexist`). Every sample then carries the per-sample delta of each
event (`Sample.values`), giving exact per-region totals and per-function /
per-line attribution for several events at once. Events are transmitted the
way the Instruments GUI stores them: base64 `NSKeyedArchiver` blobs of
`XRCountersSetupEventOrFormula` objects (see [`event_blob`](@ref)).

`template` may name a `.tracetemplate` saved from the Instruments GUI (the
only way, as of Xcode 16, to record a hand-picked *manual* event list; save
your document as a template and pass its path here). `extra` is merged into
the JSON verbatim for options not modelled here.
"""
Base.@kwdef struct RecordingOptions
    template::String = "CPU Counters"
    mode::String = "bottlenecks"
    sample_event::Union{Nothing,String} = nothing
    threshold::Int = 1_000_000
    events::Vector{String} = String[]
    high_frequency::Bool = false
    kernel::Bool = false
    debug_info::Bool = false
    extra::Dict{String,Any} = Dict{String,Any}()
end

const COUNTING_MODES = Dict(
    "bottlenecks" => ("bottleneck", "CPU Bottlenecks"),
    "delivery" => ("bottleneck", "Instruction Delivery"),
    "processing" => ("bottleneck", "Instruction Processing"),
    "discarded_sampling" => ("bottleneck", "Discarded Instructions"),
    "discarded_indirect_sampling" => ("bottleneck", "Discarded Indirect"),
    "l1d_miss_sampling" => ("bottleneck", "L1D Cache Misses"),
    "sme_streaming" => ("bottleneck", "SME Streaming"),
)

_json(s::AbstractString) = "\"" * escape_string(String(s)) * "\""
_json(b::Bool) = b ? "true" : "false"
_json(n::Integer) = string(n)
_json(n::AbstractFloat) = string(n)
_json(::Nothing) = "null"
_json(v::AbstractVector) = "[" * join(map(_json, v), ",") * "]"
_json(d::AbstractDict) = "{" * join(["$(_json(string(k))):$(_json(v))" for (k, v) in d], ",") * "}"

"""
    event_blob(mnemonic; alias = mnemonic, display = mnemonic) -> String

Base64 of an `NSKeyedArchiver` archive (XML plist form, which
`NSKeyedUnarchiver` accepts) of an `XRCountersSetupEventOrFormula` naming one
PMU event. This is the element type of `allEventsAndFormulas` in the CPU
Counters recording options and in saved `.tracetemplate` files.
"""
function event_blob(mnemonic::AbstractString; alias::AbstractString = mnemonic, display::AbstractString = mnemonic)
    esc(x) = replace(String(x), "&" => "&amp;", "<" => "&lt;", ">" => "&gt;")
    uid(i) = "<dict><key>CF\$UID</key><integer>$i</integer></dict>"
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>\$archiver</key><string>NSKeyedArchiver</string>
<key>\$version</key><integer>100000</integer>
<key>\$top</key><dict><key>root</key>$(uid(1))</dict>
<key>\$objects</key><array>
<string>\$null</string>
<dict><key>\$class</key>$(uid(5))
<key>_mnemonic</key>$(uid(2))<key>_aliasOrMnemonic</key>$(uid(3))<key>_displayName</key>$(uid(4))
<key>_formulaText</key>$(uid(0))<key>_explanation</key>$(uid(0))<key>_formulaEvaluator</key>$(uid(0))<key>_beingEdited</key><false/></dict>
<string>$(esc(mnemonic))</string><string>$(esc(alias))</string><string>$(esc(display))</string>
<dict><key>\$classname</key><string>XRCountersSetupEventOrFormula</string>
<key>\$classes</key><array><string>XRCountersSetupEventOrFormula</string><string>NSObject</string></array></dict>
</array></dict></plist>"""
    return base64encode(xml)
end

"""JSON text for `xctrace record --recording-options`."""
function options_json(o::RecordingOptions)
    evs = String[KPEP.event(e).name for e in o.events]
    if !isempty(evs)
        KPEP.can_coexist(evs...) || throw(ArgumentError("events cannot be counted together on this CPU: $(join(evs, ", ")). Groups that work: $(KPEP.plan_groups(evs))"))
    end
    if o.sample_event !== nothing
        ev = KPEP.event(o.sample_event)
        ev.fixed && throw(ArgumentError("Instruments rejects fixed counters as sampling triggers; use CORE_ACTIVE_CYCLE or INST_ALL instead of $(ev.name)"))
    end
    haskey(COUNTING_MODES, o.mode) || throw(ArgumentError("unknown counting mode $(o.mode); one of $(join(keys(COUNTING_MODES), ", "))"))
    analysis, display = COUNTING_MODES[o.mode]
    cpu = Dict{String,Any}(
        # Instruments only honours an event-triggered (PMI) sampler when the
        # configuration type is "manual"; timer sampling uses the guided modes.
        "configurationType" => (o.sample_event === nothing && isempty(evs)) ? Dict("guided" => Dict()) : Dict("manual" => Dict()),
        "allEventsAndFormulas" => Any[event_blob(e; alias = (a = KPEP.event(e).alias; isempty(a) ? e : a)) for e in KPEP.greedy_order(evs)],
        "countingLevel" => o.kernel ? "EL1" : "EL0",
        "pmiEventAliasOrMnemonic" => something(o.sample_event, ""),
        "pmiThreshold" => o.threshold,
        "processBucketSize" => 10,
        "sampleByTime" => o.sample_event === nothing,
        "selectedCountingMode" => Dict("analysisMode" => analysis, "countingMode" => o.mode),
        "selectedCountingModeDisplayName" => display,
        "useDebuggingInformation" => o.debug_info,
        "useHighFrequencyForGuidedMode" => o.high_frequency,
        "useHighFrequencyForManualMode" => o.high_frequency,
    )
    merge!(cpu, o.extra)
    top = Dict{String,Any}(
        "CPU Counters" => cpu,
        "Points of Interest" => Dict("excludeOSLogs" => false),
        "Time Profiler" => Dict("contextSwitchSampling" => false, "highFrequencySampling" => o.high_frequency,
                                "recordKernelStacks" => o.kernel, "recordWaitingThreads" => false),
    )
    return _json(top)
end

"""Print the recording options xctrace reports for a template (as JSON)."""
show_recording_options(template::AbstractString = "CPU Counters") =
    print(read(`$(xctrace_path()) record --template $template --show-recording-options`, String))

# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

_uses_cpu_counters(t) = t == "CPU Counters" || endswith(t, ".tracetemplate")

function _base_cmd(o::RecordingOptions, output, time_limit, notify)
    args = String[xctrace_path(), "record", "--template", o.template, "--output", output, "--no-prompt"]
    if o.template == "CPU Counters"
        f = tempname() * ".json"
        write(f, options_json(o))
        append!(args, ["--recording-options", f])
    end
    time_limit === nothing || append!(args, ["--time-limit", time_limit isa AbstractString ? String(time_limit) : "$(round(Int, time_limit*1000))ms"])
    notify === nothing || append!(args, ["--notify-tracing-started", String(notify)])
    return args
end

"""
    record(cmd::Cmd; options = RecordingOptions(), output = tempname()*".trace", time_limit = nothing) -> String

Launch `cmd` under xctrace and record it until it exits (or `time_limit`,
seconds). Returns the `.trace` path.
"""
function record(cmd::Cmd; options::RecordingOptions = RecordingOptions(), output::AbstractString = tempname() * ".trace",
                time_limit = nothing, env = nothing, verbose::Bool = false)
    args = _base_cmd(options, output, time_limit, nothing)
    env === nothing || for (k, v) in env; append!(args, ["--env", "$k=$v"]); end
    append!(args, ["--target-stdout", "-", "--launch", "--"]); append!(args, cmd.exec)
    out = IOBuffer()
    ok = success(pipeline(Cmd(args); stdout = out, stderr = out))
    txt = String(take!(out))
    verbose && print(txt)
    _check_output(txt, ok)
    return String(output)
end

function _check_output(txt, ok)
    if occursin("[Error]", txt) || !ok
        msg = join(filter(l -> occursin("Error", l) || occursin("Recovery", l) || occursin("fail", lowercase(l)), split(txt, '\n')), '\n')
        error("xctrace failed:\n" * (isempty(msg) ? txt : msg))
    end
end

"""
    AttachedRecording

A running `xctrace record --attach` process. `stop!` it to finish and save.
"""
mutable struct AttachedRecording
    proc::Base.Process
    output::String
    log::IOBuffer
    notify_name::String
    started::Bool
end

"""
    attach(pid = getpid(); options, output, time_limit = 3600, wait_for_start = true) -> AttachedRecording

Attach xctrace to a process and start recording. With `wait_for_start`, block
until the kernel tracing session is live (via a Darwin notification), so code
run afterwards is guaranteed to be captured.
"""
function attach(pid::Integer = getpid(); options::RecordingOptions = RecordingOptions(), output::AbstractString = tempname() * ".trace",
                time_limit = 3600, wait_for_start::Bool = true, start_timeout::Real = 30)
    name = "org.julialang.ApplePerf.started." * string(rand(UInt64); base = 16)
    token = Ref{Cint}(0)
    ccall(:notify_register_check, UInt32, (Cstring, Ref{Cint}), name, token) == 0 || error("notify_register_check failed")
    ccall(:notify_check, UInt32, (Cint, Ref{Cint}), token[], Ref{Cint}(0))  # clear initial state
    args = _base_cmd(options, output, time_limit, name)
    append!(args, ["--attach", string(pid)])
    log = IOBuffer()
    proc = run(pipeline(Cmd(args); stdout = log, stderr = log); wait = false)
    rec = AttachedRecording(proc, String(output), log, name, false)
    if wait_for_start
        t0 = time()
        while true
            chk = Ref{Cint}(0)
            ccall(:notify_check, UInt32, (Cint, Ref{Cint}), token[], chk)
            if chk[] != 0
                rec.started = true
                break
            end
            if process_exited(proc)
                _check_output(String(take!(copy(log))), false)
                error("xctrace exited before tracing started:\n" * String(take!(copy(log))))
            end
            time() - t0 > start_timeout && (kill(proc); error("xctrace did not start tracing within $start_timeout s:\n" * String(take!(copy(log)))))
            sleep(0.01)
        end
        # tracing is live in the kernel; give the PMU sampler a moment to arm
        sleep(0.05)
    end
    ccall(:notify_cancel, UInt32, (Cint,), token[])
    return rec
end

"""Stop an attached recording (sends Ctrl-C to xctrace) and wait for the trace to be saved. Returns the trace path."""
function stop!(rec::AttachedRecording; timeout::Real = 120)
    if process_running(rec.proc)
        kill(rec.proc, Base.SIGINT)
        t0 = time()
        while process_running(rec.proc) && time() - t0 < timeout
            sleep(0.05)
        end
        process_running(rec.proc) && (kill(rec.proc); error("xctrace did not stop within $timeout s"))
    end
    txt = String(take!(copy(rec.log)))
    _check_output(txt, isdir(rec.output))
    return rec.output
end

"""Open a trace file in the Instruments GUI."""
open_in_instruments(trace::AbstractString) = run(`open -a Instruments $trace`; wait = false)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

"""Schemas (table names) present in a trace's first run."""
function list_tables(trace::AbstractString)
    toc = read(`$(xctrace_path()) export --input $trace --toc`, String)
    return unique!(sort!([m[1] for m in eachmatch(r"schema=\"([^\"]+)\"", toc)]))
end

"""Raw table-of-contents XML."""
toc(trace::AbstractString) = read(`$(xctrace_path()) export --input $trace --toc`, String)

"""Attributes recorded on a table's schema entry in the toc (e.g. `pmi-event`, `pmc-events`, `sample-rate-micro-seconds`)."""
function table_attributes(trace::AbstractString, schema::AbstractString)
    for m in eachmatch(r"<table ([^>]*)>", toc(trace))
        occursin("schema=\"$schema\"", m[1]) || continue
        return Dict(a[1] => a[2] for a in eachmatch(r"([a-z\-]+)=\"([^\"]*)\"", m[1]))
    end
    return Dict{String,String}()
end

"""
    XNode

A cell of an exported row: element `tag`, its attributes (`fmt` is the human
formatted value), its text (the raw value), and children (e.g. frames of a
backtrace). Cross-references (`ref="..."`) are already resolved.
"""
struct XNode
    tag::String
    attrs::Dict{String,String}
    text::String
    children::Vector{XNode}
end
Base.getindex(n::XNode, k::AbstractString) = n.attrs[k]
Base.haskey(n::XNode, k::AbstractString) = haskey(n.attrs, k)
Base.get(n::XNode, k::AbstractString, d) = get(n.attrs, k, d)
"""Formatted value if present, else raw text."""
fmt(n::XNode) = get(n.attrs, "fmt", n.text)
"""Raw integer value (nanoseconds for times, counts for weights)."""
raw(n::XNode) = n.text
rawint(n::XNode) = parse(Int, strip(n.text))
"""First child element with the given tag, or `nothing`."""
child(n::XNode, tag::AbstractString) = (i = findfirst(c -> c.tag == tag, n.children); i === nothing ? nothing : n.children[i])
Base.show(io::IO, n::XNode) = print(io, "<", n.tag, isempty(n.attrs) ? "" : " " * join(["$k=\"$v\"" for (k, v) in n.attrs if k != "id"], " "), ">", isempty(n.children) ? fmt(n) : "…$(length(n.children)) children", "</", n.tag, ">")

function _convert(node::EzXML.Node, store::Dict{String,XNode})
    if haskey(node, "ref")
        r = node["ref"]
        haskey(store, r) || error("unresolved ref $r in xctrace export")
        return store[r]
    end
    attrs = Dict{String,String}()
    for a in eachattribute(node)
        attrs[nodename(a)] = nodecontent(a)
    end
    kids = XNode[]
    text = ""
    for c in eachnode(node)
        if iselement(c)
            push!(kids, _convert(c, store))
        elseif istext(c)
            text *= nodecontent(c)
        end
    end
    x = XNode(nodename(node), attrs, strip(text), kids)
    haskey(attrs, "id") && (store[attrs["id"]] = x)
    return x
end

"""
    Table

An exported xctrace table: `schema`, column names, and `rows` as vectors of [`XNode`](@ref).
"""
struct Table
    schema::String
    columns::Vector{String}
    mnemonics::Vector{String}
    rows::Vector{Vector{XNode}}
end
Base.length(t::Table) = length(t.rows)
Base.iterate(t::Table, s...) = iterate(t.rows, s...)
Base.show(io::IO, t::Table) = print(io, "Table(", t.schema, ", ", length(t.rows), " rows, columns = ", t.columns, ")")
"""Column index by name or mnemonic."""
function colindex(t::Table, name::AbstractString)
    i = findfirst(==(name), t.columns); i === nothing && (i = findfirst(==(name), t.mnemonics))
    i === nothing && error("no column $name in $(t.schema); have $(t.columns)")
    return i
end
Base.getindex(row::Vector{XNode}, t::Table, name::AbstractString) = row[colindex(t, name)]

"""
    export_table(trace, schema; run = 1) -> Table
    export_table(f, trace, schema; run = 1)

Export one table of a trace. The second form streams: `f(columns, row)` is
called per row without keeping the table in memory (use it for very large
tables such as `processor-trace-intervals`).
"""
function export_table(f::Function, trace::AbstractString, schema::AbstractString; run::Integer = 1)
    xml = tempname() * ".xml"
    xpath = "/trace-toc/run[@number=\"$run\"]/data/table[@schema=\"$schema\"]"
    Base.run(pipeline(`$(xctrace_path()) export --input $trace --xpath $xpath`; stdout = xml))
    columns = String[]; mnemonics = String[]
    store = Dict{String,XNode}()
    reader = open(EzXML.StreamReader, xml)
    try
        for typ in reader
            typ == EzXML.READER_ELEMENT || continue
            nm = nodename(reader)
            if nm == "col"
                node = expandtree(reader)
                for c in eachelement(node)
                    nodename(c) == "name" && push!(columns, nodecontent(c))
                    nodename(c) == "mnemonic" && push!(mnemonics, nodecontent(c))
                end
            elseif nm == "row"
                node = expandtree(reader)
                cells = XNode[_convert(c, store) for c in eachelement(node)]
                f(columns, cells)
            end
        end
    finally
        close(reader)
        rm(xml; force = true)
    end
    return columns, mnemonics
end

function export_table(trace::AbstractString, schema::AbstractString; run::Integer = 1)
    rows = Vector{XNode}[]
    columns, mnemonics = export_table(trace, schema; run) do _, cells
        push!(rows, cells)
    end
    return Table(String(schema), columns, mnemonics, rows)
end

end # module XCTrace
