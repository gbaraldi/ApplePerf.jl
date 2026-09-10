# Basic use: profile a few regions with the default event list (cycles, instructions,
# L1D load misses, branch mispredictions), then look at the results four ways.
#
#   julia --project=. examples/basic.jl
using ApplePerf

function gather(A, B)
    acc = 0.0
    @inbounds for i in B
        x = A[i]
        acc += x * x
    end
    return acc
end
A = rand(Float64, 1 << 24); B = rand(1:length(A), 2_000_000)
As = rand(Float64, 1 << 10); Bs = rand(1:length(As), 2_000_000)
gather(A, B); gather(As, Bs); sum(A)   # compile first, so the profile is about the work

# xctrace attaches to this process (no sudo); each @region becomes an os_signpost interval.
res = profile() do
    for _ in 1:20
        @region "gather 128 MiB" gather(A, B)
        @region "gather 8 KiB" gather(As, Bs)
        @region "sum 128 MiB" sum(A)
    end
end

# 1. Per-region summary: wall time, samples, exact counter totals, top functions.
show(stdout, MIME"text/plain"(), res); println()

# 2. Which source lines pay, in time or in any recorded event.
ApplePerf.Analysis.report(res; region = "gather 8 KiB", top = 6)
ApplePerf.Analysis.report(res; region = "gather 128 MiB", top = 6, by = "L1D_CACHE_MISS_LD_NONSPEC")

# 3. Per function, events per sample: high misses-per-sample marks memory-bound code.
ApplePerf.Analysis.bottleneck_table(res; top = 6)

# 4. Exports: pprof (one column per event, region/thread labels), folded stacks, flame graph.
ApplePerf.Analysis.pprof(res, "profile.pb.gz")                    # add web = true for PProf's UI
ApplePerf.Analysis.collapsed(res, "profile.folded")               # speedscope / flamegraph.pl
ApplePerf.Analysis.flamegraph(res, "profile.svg"; by = "L1D_CACHE_MISS_LD_NONSPEC")   # heat map of misses
println("wrote profile.pb.gz, profile.folded, profile.svg; trace at ", res.trace)
println("  pprof -sample_index=FIXED_CYCLES -tagfocus='region=gather 8 KiB' -top profile.pb.gz")
