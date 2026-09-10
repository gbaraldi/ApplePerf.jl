# Event-triggered sampling: one stack sample every `threshold` L1D load misses instead
# of every millisecond. Sample weights are then misses, so every view (report, pprof,
# flame graph) is in misses, and hot spots of *time* that miss little disappear.
#
#   julia --project=. examples/l1d_misses.jl
using ApplePerf

function gather(A, B)
    acc = 0.0
    @inbounds for i in B
        acc += A[i]
    end
    return acc
end
A = rand(Float64, 1 << 24); B = rand(1:length(A), 4_000_000)
As = rand(Float64, 1 << 10); Bs = rand(1:length(As), 4_000_000)
gather(A, B); gather(As, Bs)

opts = RecordingOptions(sample_event = "L1D_CACHE_MISS_LD_NONSPEC", threshold = 20_000)
res = profile(; options = opts) do
    for _ in 1:10
        @region "gather 128 MiB" gather(A, B)
        @region "gather 8 KiB" gather(As, Bs)      # same instructions, tiny working set
    end
end
show(stdout, MIME"text/plain"(), res); println()
ApplePerf.Analysis.report(res; region = "gather 128 MiB", top = 5)     # misses by source line
ApplePerf.Analysis.pprof(res, "l1d.pb.gz")
ApplePerf.Analysis.flamegraph(res, "l1d.svg")                          # widths are misses
println("wrote l1d.pb.gz and l1d.svg; trace: ", res.trace)
println("note: samples × threshold estimates the total; the 8 KiB gather barely appears")
