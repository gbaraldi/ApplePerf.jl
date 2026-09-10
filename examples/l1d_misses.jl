# Event-triggered sampling: one stack sample every `threshold` L1D load misses.
# Sample weights are then misses, so by_line/by_function attribute cache misses to code.
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
        @region "gather 8 KiB" gather(As, Bs)
    end
end
show(stdout, MIME"text/plain"(), res); println()
ApplePerf.Analysis.report(res; region = "gather 128 MiB", top = 5)
ApplePerf.Analysis.pprof(res, "l1d.pb"); ApplePerf.Analysis.collapsed(res, "l1d.folded")
println("trace: ", res.trace)
