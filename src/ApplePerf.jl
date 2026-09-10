"""
    ApplePerf

Hardware performance counters and region profiling for Julia on Apple Silicon.

Three backends, all driven from inside the Julia process:

* [`ApplePerf.KPC`](@ref) — exact per-thread counter deltas around a call, read
  through the private `kperf`/`kperfdata` frameworks. Requires root.
* [`ApplePerf.Signposts`](@ref) — `os_signpost` regions that Instruments and
  `xctrace` understand. No privileges needed.
* [`ApplePerf.XCTrace`](@ref) / [`profile`](@ref) — drive `xctrace` (Instruments'
  CLI) to sample the current process while a function runs, then join the
  samples against the signposted regions, symbolize JIT frames in-process, and
  report per-region counters plus per-function / per-line attribution.
  No privileges needed. Optional Processor Trace support (needs a re-signed
  Julia binary, see [`make_debuggable_julia`](@ref)).
"""
module ApplePerf

using Libdl, Printf, Dates, Statistics

include("kpep.jl")
include("kpc.jl")
include("signposts.jl")
include("xctrace.jl")
include("analysis.jl")
include("profile.jl")
include("entitlements.jl")

using .KPEP: events, event_names, describe, plan_groups, can_coexist, counter_slots
using .KPC
using .Signposts: @region, region, mark_event, signposts_enabled
using .XCTrace: RecordingOptions, record, attach, export_table, list_tables, xctrace_available, open_in_instruments
using .Analysis
using .Profile: profile, ProfileResult
using .Entitlements: has_get_task_allow, make_debuggable_julia

export events, event_names, describe, plan_groups, can_coexist, counter_slots,
       @region, region, mark_event, signposts_enabled,
       RecordingOptions, record, attach, export_table, list_tables, xctrace_available, open_in_instruments,
       profile, ProfileResult, has_get_task_allow, make_debuggable_julia,
       KPC, KPEP, Signposts, XCTrace, Analysis

end # module
