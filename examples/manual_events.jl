# Hand-picked event list: every 1 ms sample carries per-sample deltas of each event,
# so regions get exact totals and functions/lines get attribution per event.
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

opts = RecordingOptions(events = ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "BRANCH_MISPRED_NONSPEC", "L1D_TLB_MISS_NONSPEC"])
res = profile(; options = opts) do
    for _ in 1:10
        @region "gather 128 MiB" gather(A, B)
        @region "gather 8 KiB" gather(As, Bs)
    end
end
show(stdout, MIME"text/plain"(), res); println()
ApplePerf.Analysis.report(res; region = "gather 128 MiB", top = 4, by = "L1D_CACHE_MISS_LD_NONSPEC")
ApplePerf.Analysis.report(res; region = "gather 8 KiB", top = 4, by = "FIXED_INSTRUCTIONS")
ApplePerf.Analysis.pprof(res, "events.pb.gz")
println("trace: ", res.trace)
