# Exact in-process counters through the private kperf framework. Requires root:
#
#   sudo julia --project=. examples/kpc_root.jl
#
# Unlike `profile`, nothing is sampled: the counters are read on this thread right
# before and after the call, so short regions (microseconds) are measurable.
using ApplePerf

A = rand(Float64, 1 << 24); B = rand(1:length(A), 1_000_000)
gather(A, B) = (acc = 0.0; @inbounds for i in B; acc += A[i]; end; acc)
gather(A, B); sum(A)

KPC.has_access() || error("run with sudo: the PMU sysctls are gated on root")

events = ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "BRANCH_MISPRED_NONSPEC", "INST_ALL", "RETIRE_UOP"]
println("groups: ", plan_groups(events))          # events that cannot share the PMU are multiplexed across runs
println("empty region: ", KPC.measure(() -> nothing, events))
println("sum(A):       ", KPC.measure(() -> sum(A), events; repeat = 3))
println("gather:       ", KPC.measure(() -> gather(A, B), events; repeat = 3))

# A long-lived session avoids reprogramming the PMU for every measurement.
s = KPC.Session(["FIXED_CYCLES", "FIXED_INSTRUCTIONS"])
KPC.start!(s)
try
    println("overhead of one measure(): ", KPC.overhead(s))
    for n in (10^3, 10^5, 10^7)
        v = rand(n)
        d = KPC.measure(() -> sum(v), s)
        println("sum of $n: ", d, "  IPC = ", round(d["FIXED_INSTRUCTIONS"] / d["FIXED_CYCLES"]; digits = 2))
    end
finally
    KPC.stop!(s)
end
