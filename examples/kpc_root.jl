# Exact in-process counters. Run with:  sudo julia --project=. examples/kpc_root.jl
using ApplePerf

A = rand(Float64, 1 << 24); B = rand(1:length(A), 1_000_000)
gather(A, B) = (acc = 0.0; @inbounds for i in B; acc += A[i]; end; acc)
gather(A, B); sum(A)

events = ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "BRANCH_MISPRED_NONSPEC", "INST_ALL", "RETIRE_UOP"]
println("groups: ", plan_groups(events))          # INST_ALL and RETIRE_UOP share one slot -> two groups
println("empty region: ", KPC.measure(() -> nothing, events))
println("sum(A):       ", KPC.measure(() -> sum(A), events; repeat = 3))
println("gather:       ", KPC.measure(() -> gather(A, B), events; repeat = 3))

# Long-lived session for many measurements without reprogramming the PMU
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
