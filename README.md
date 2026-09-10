# ApplePerf.jl

Hardware performance counters and region profiling for Julia on Apple Silicon,
driven from inside the Julia process. Think `LinuxPerf.jl` / `LIKWID.jl`, but
for macOS, where the PMU is reachable only through Apple's private `kperf`
frameworks (root) or through Instruments (no root).

```julia
using ApplePerf

res = profile() do                       # xctrace attaches to this process, no sudo
    for _ in 1:20
        @region "gather" gather(A, B)    # os_signpost intervals, visible in Instruments too
        @region "sum"    sum(A)
    end
end
res                                      # per-region wall time, samples, counter metrics, top functions
ApplePerf.Analysis.report(res; region = "gather")   # self weight per source line (JIT frames symbolized)
ApplePerf.Analysis.pprof(res, "run.pb.gz"; web = true)   # PProf web UI; or pprof -tagfocus=region=gather run.pb.gz
ApplePerf.Analysis.collapsed(res, "gather.folded")  # speedscope / flamegraph.pl
open_in_instruments(res.trace)
```

## What it does

| Backend | Privileges | What you get |
|---|---|---|
| `KPC.measure(f, events)` | **root** | exact per-thread counter deltas around a call (2 fixed + 8 configurable counters, any of the ~136 events in Apple's kpep database); software multiplexing across repeated runs when events conflict |
| `profile(f)` (default) | none | 1 ms timer samples with call stacks for every thread, each carrying per-sample deltas of cycles, instructions, L1D load misses and branch mispredictions, joined against `@region` intervals |
| `profile(f; options = RecordingOptions(sample_event = "L1D_CACHE_MISS_LD_NONSPEC", threshold = 20_000))` | none | one stack sample every N occurrences of an event, so per-function / per-line attribution is in **that event's units** (misses, branch mispredicts, cycles, ...) |
| `profile(f; options = RecordingOptions(template = "Processor Trace"))` | none, but the Julia binary needs `get-task-allow` (see `make_debuggable_julia`) | exact traced instructions and cycles per region from the M4+/M5 processor trace unit (~1 s window, drops data on branch-dense code) |
| `profile(f; options = RecordingOptions(events = ["FIXED_CYCLES", "L1D_CACHE_MISS_LD_NONSPEC", ...]))` | none | hand-picked event list (up to 2 fixed + 8 configurable): every 1 ms sample carries the per-sample delta of each event, giving exact per-region totals and per-event attribution to functions and lines, all in one run |
| `profile(f; options = RecordingOptions(template = "/path/My.tracetemplate"))` | none | any configuration saved from the Instruments GUI |

Everything `profile` produces stays in Julia: regions, samples, counters, and
symbolized stacks. JIT frames are resolved with `Base.StackTraces.lookup` in the
profiled process, so Julia functions, inlined callees, and `file:line` show up
in the reports and exports. Instruments itself has no hook for JIT symbols, so
the GUI shows Julia frames as addresses; use the exports for symbolized views.

## Requirements

* macOS on Apple Silicon (tested: M5, macOS 27, Xcode 16 / xctrace 16).
* Xcode (for `xctrace`) for everything except the root `KPC` backend.
* `sudo` for `KPC`. There is no way around it short of the private
  `com.apple.private.kernel.kpc` entitlement.

## API tour

### Event database (no privileges)

```julia
events()                       # Vector{Event}: name, alias, description, slot mask, fixed?
describe("L1D")                # print matching events with masks and descriptions
counter_slots()                # (fixed = 2, configurable = 8)
can_coexist("INST_ALL", "RETIRE_UOP")           # false: both need the same slot
plan_groups(["FIXED_CYCLES", "INST_ALL", "RETIRE_UOP", "L1D_CACHE_MISS_LD_NONSPEC"])
# -> [["FIXED_CYCLES", "INST_ALL", "L1D_CACHE_MISS_LD_NONSPEC"], ["RETIRE_UOP"]]
```

Slot conflicts are solved exactly (bipartite matching over the `counters_mask`
of each event), and `KPEP.greedy_order` yields an insertion order that
Instruments' first-free-slot booker accepts.

### Exact counters (root)

```julia
KPC.measure(["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC"]) do
    gather(A, B)
end                                   # Dict("FIXED_CYCLES" => ..., ...)

s = KPC.Session(["FIXED_CYCLES", "FIXED_INSTRUCTIONS"]); KPC.start!(s)
KPC.measure(() -> sum(A), s)          # many measurements, one PMU programming
KPC.overhead(s)                       # cost of the two counter reads themselves
KPC.stop!(s)
```

Counting is per thread (the kernel saves and restores counters on context
switch). A `measure` costs about two sysctls, a few microseconds.

### Regions

```julia
@region "name" expr
region(f, "name")
mark_event("event")                    # point marker
```

Regions are `os_signpost` intervals in subsystem `org.julialang.ApplePerf`.
They show in Instruments' Points of Interest track with the region name as the
signpost *message*; the signpost *name* is a fixed literal (`julia`) because
the system requires name and format strings to live in a loaded image's
`__TEXT` segment, the same trick Julia's own `WITH_APPLE_OSLOG` build uses.

### Profiling with xctrace

```julia
opts = RecordingOptions(;
    template = "CPU Counters",        # or "Time Profiler", "Processor Trace", or a .tracetemplate path
    events = ApplePerf.XCTrace.DEFAULT_EVENTS,   # per-sample event deltas; String[] switches to a guided mode
    mode = "bottlenecks",             # guided counting mode (only when `events` is empty)
    sample_event = nothing,           # set to an event mnemonic for event-triggered sampling
    threshold = 1_000_000,            # events per sample
    high_frequency = false,
    kernel = false)                   # count/sample EL1 too
res = profile(f; options = opts, name = "outer", output = "run.trace")

ApplePerf.Analysis.regions(res)       # RegionSummary per region name
ApplePerf.Analysis.counters(res, "gather")
ApplePerf.Analysis.by_function(res; region = "gather")
ApplePerf.Analysis.by_line(res; region = "gather", by = "L1D_CACHE_MISS_LD_NONSPEC")  # attribute a counter instead of time
ApplePerf.Analysis.inclusive(res)
ApplePerf.Analysis.samples(res, "gather")   # raw Sample objects with symbolized stacks
```

Lower-level pieces are exposed too: `XCTrace.record(cmd)` to wrap a child
process, `XCTrace.attach(pid)` / `XCTrace.stop!`, `export_table(trace, schema)`
(streaming, `ref`s resolved) and `list_tables(trace)`, and
`Analysis.analyze(trace)` to post-process any trace file.

### pprof export

`Analysis.pprof(res, path; region = nothing, web = false)` writes a gzipped
`profile.proto` through PProf.jl's protobuf types; `web = true` opens PProf's
bundled web UI on it, and `PProf.refresh(file = path)` reopens it later. Sample values are `[samples, weight, counters...]`: weight in
nanoseconds (timer) or trigger-event counts (event-triggered), then one column
per event of a manual event list, selectable with `-sample_index=<EVENT>` (the
first event is the default view). Each sample is labelled
with `thread` and with one `region` per enclosing interval, so one file serves
all views:

```
pprof -http=: run.pb.gz                        # everything
pprof -tagfocus=region=gather run.pb.gz     # only samples inside "gather"
pprof -tagignore=region=profile run.pb.gz   # nothing from the outer region
pprof -tagroot=region -top run.pb.gz        # group by region
```

### Processor Trace

```julia
exe = make_debuggable_julia(expanduser("~/.julia/julia-debuggable"))
# start Julia from `exe`, then
res = profile(f; options = RecordingOptions(template = "Processor Trace"), time_limit = 5)
```

Processor Trace records every branch with timing for about one second, then
stops. It gives exact per-region instruction and cycle counts (and per-function
intervals in the `processor-trace-intervals` table), but the trace buffer
overflows on branch-dense loops, which appear as gaps. `RegionSummary.pt_gaps`
tells you how much was lost.

## Caveats and things learned the hard way

* **Guided-mode metric values** (`events = String[]`: Cycles, Instruction
  Delivery / Discarded / Processing Bottleneck) are Instruments' derived
  per-thread interval values, not raw event counts, and are not attached to
  samples. The default manual event list gives raw per-sample counts.
* **xctrace is slow to start and stop.** Attaching takes about 2.3 s, stopping
  and saving about 2.5 s, and every `xctrace export` invocation about 2 s
  regardless of table size. `analyze` therefore makes exactly two invocations
  (toc, then all tables in one export); a `profile` call costs roughly 8 s on
  top of the workload.
* **How manual event lists reach xctrace.** `--recording-options` (Xcode 16)
  takes the same JSON the GUI stores in `.tracetemplate` files. Its
  `allEventsAndFormulas` entries are base64 `NSKeyedArchiver` blobs of
  `XRCountersSetupEventOrFormula` objects (found via the plug-in's Swift
  reflection metadata); `XCTrace.event_blob` builds them, so no GUI is needed.
  Event-triggered sampling and manual lists both require `configurationType`
  `manual`.
* **Only one PMU user at a time.** Instruments, xctrace, and `KPC` program the
  same hardware; running two at once breaks both.
* **The trace is kept** at `res.trace` (a directory). Delete it when done; a
  Processor Trace run is about 1 GB per second of execution.
* Requires signposts to be emitted from the same thread the work runs on;
  regions are per thread, so `Threads.@spawn` bodies need their own `@region`.

## Demo

```
julia --project=. examples/demo.jl          # add --open to also open the trace in Instruments
```

Profiles a contiguous versus strided matrix sum and a predictable versus
unpredictable branch with five events at once, prints exact per-region
counters (IPC, L1D and TLB misses, mispredictions per run), the source lines
responsible, and writes pprof and folded-stack exports. About 20 seconds.

## Files

* `examples/demo.jl` — the walkthrough above.

* `examples/basic.jl` — timer profile with regions, exports.
* `examples/l1d_misses.jl` — L1D-miss-triggered sampling and per-line miss attribution.
* `examples/manual_events.jl` — five events per sample, exact per-region totals, per-event pprof columns.
* `examples/kpc_root.jl` — exact counters (run with `sudo`).
