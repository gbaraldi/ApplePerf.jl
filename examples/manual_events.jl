# Hand-picked event list (up to 2 fixed + 8 configurable). Every 1 ms sample carries the
# per-sample delta of each event, so regions get exact totals and every function and
# line can be attributed in any of the events, all from one run.
#
#   julia --project=. examples/manual_events.jl
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

events = ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "BRANCH_MISPRED_NONSPEC", "L1D_TLB_MISS_NONSPEC"]
println("can be counted together: ", can_coexist(events...))   # slot conflicts are checked up front
res = profile(; options = RecordingOptions(events = events)) do
    for _ in 1:10
        @region "gather 128 MiB" gather(A, B)
        @region "gather 8 KiB" gather(As, Bs)
    end
end
show(stdout, MIME"text/plain"(), res); println()
ApplePerf.Analysis.report(res; region = "gather 128 MiB", top = 4, by = "L1D_CACHE_MISS_LD_NONSPEC")
ApplePerf.Analysis.report(res; region = "gather 8 KiB", top = 4, by = "FIXED_INSTRUCTIONS")
ApplePerf.Analysis.bottleneck_table(res; top = 5)       # events per sample, per function
ApplePerf.Analysis.pprof(res, "events.pb.gz")            # -sample_index=<EVENT> picks the column
ApplePerf.Analysis.flamegraph(res, "events_tlb.svg"; by = "L1D_TLB_MISS_NONSPEC")
println("wrote events.pb.gz and events_tlb.svg; trace: ", res.trace)
