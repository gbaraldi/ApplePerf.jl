module Profile

using ..XCTrace, ..Signposts, ..Analysis
using ..XCTrace: RecordingOptions
using ..Analysis: ProfileResult

"""
    profile(f; options = RecordingOptions(), name = "profile", output = tempname()*".trace",
            time_limit = 3600, symbolize = true) -> ProfileResult

Sample the current Julia process with Instruments' `xctrace` while `f()` runs
(no root needed), then join the samples against signposted regions and
symbolize JIT frames in-process.

`f` itself is wrapped in a region called `name`; nest `@region "..." expr`
inside `f` for finer attribution. Choose what to sample with `options`:

```julia
profile(() -> work())                                            # 1 ms timer, CPU bottleneck metrics
profile(() -> work(); options = RecordingOptions(sample_event = "L1D_CACHE_MISS_LD_NONSPEC", threshold = 10_000))
profile(() -> work(); options = RecordingOptions(template = "Time Profiler"))
profile(() -> work(); options = RecordingOptions(template = "Processor Trace"), time_limit = 5)  # needs make_debuggable_julia
profile(() -> work(); options = RecordingOptions(template = "/path/to/MyEvents.tracetemplate"))
```

The trace file is kept (`result.trace`); `open_in_instruments(result.trace)`
shows it in the GUI (JIT frames appear as addresses there; the symbolized view
lives in the result, `collapsed`, and `pprof` exports).
"""
function profile(f; options::RecordingOptions = RecordingOptions(), name::AbstractString = "profile",
                 output::AbstractString = tempname() * ".trace", time_limit = 3600, symbolize::Bool = true, verbose::Bool = false)
    XCTrace.xctrace_available() || error("xctrace (Xcode / Instruments) is required for ApplePerf.profile")
    Signposts.signposts_enabled() || @warn "signposts unavailable: regions will not be recorded"
    rec = XCTrace.attach(getpid(); options, output, time_limit)
    verbose && @info "xctrace attached and tracing" output
    result_value = nothing
    try
        result_value = Signposts.region(f, name)
    finally
        trace = XCTrace.stop!(rec)
        verbose && @info "trace saved" trace
    end
    res = Analysis.analyze(output; symbolize_jit = symbolize, template = options.template)
    return res
end

end # module Profile
