# ApplePerf.jl demo — hardware counters for Julia on Apple Silicon, no sudo.
#
#   julia --project=/path/to/ApplePerf.jl examples/demo.jl [--open]
#
# Two classic pitfalls, diagnosed with real PMU events attributed to regions,
# functions and source lines: strided memory access (cache/TLB misses) and
# data-dependent branches (branch mispredictions).

using ApplePerf, Printf

banner(s) = (println(); printstyled("── ", s, " ", "─"^max(0, 70 - length(s)), "\n"; bold = true, color = :cyan))

banner("1. The event database (no privileges needed)")
println("CPU: ", strip(read(`sysctl -n machdep.cpu.brand_string`, String)), "   counters: ", counter_slots(), "   events in kpep db: ", length(events()))
evs = ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "L1D_TLB_MISS_NONSPEC", "BRANCH_MISPRED_NONSPEC"]
println("can these five be counted together?  ", can_coexist(evs...))
println("INST_ALL + RETIRE_UOP + 7 more wide events → groups: ", length(plan_groups(vcat(["INST_ALL", "RETIRE_UOP"], fill("CORE_ACTIVE_CYCLE", 7)))))

banner("2. Workloads")
# (a) strided vs contiguous traversal of a column-major matrix
const N = 4096
M = rand(Float64, N, N)                                  # 128 MiB
sum_cols(M) = (s = 0.0; @inbounds for j in axes(M, 2), i in axes(M, 1); s += M[i, j]; end; s)   # contiguous
sum_rows(M) = (s = 0.0; @inbounds for i in axes(M, 1), j in axes(M, 2); s += M[i, j]; end; s)   # stride N
# (b) a data-dependent branch over random vs sorted data. The call in the taken
#     branch keeps LLVM from if-converting it into a select, so the branch is real.
data = rand(Int32(-100):Int32(100), 8_000_000); sorted = sort(data)
@noinline bump(c, x) = c + Int(x)
function count_pos(v)
    c = 0
    @inbounds for x in v
        if x > 0          # unpredictable on random data, predictable on sorted
            c = bump(c, x)
        end
    end
    return c
end
sum_cols(M); sum_rows(M); count_pos(data); count_pos(sorted)   # compile everything first
println("matrix $(N)×$(N) Float64 (", Base.format_bytes(sizeof(M)), "), branchy reduction over ", length(data), " Int32")

banner("3. Profile with a hand-picked event list (xctrace attaches to this process)")
opts = RecordingOptions(events = evs)
res = profile(; options = opts, name = "demo") do
    for _ in 1:3
        @region "sum by columns (contiguous)" sum_cols(M)
        @region "sum by rows (stride 4096)"   sum_rows(M)
        @region "count_pos random"           count_pos(data)
        @region "count_pos sorted"           count_pos(sorted)
    end
end
println("trace: ", res.trace)

banner("4. Exact per-region counters (summed from per-sample deltas)")
regs = filter(r -> r.name != "demo", ApplePerf.Analysis.regions(res))
@printf("%-30s %9s %8s %6s %14s %12s %12s\n", "region", "wall ms", "IPC", "", "L1D misses", "TLB misses", "mispredicts")
for r in regs
    c = r.counters
    cyc = c["FIXED_CYCLES"]; ins = c["FIXED_INSTRUCTIONS"]
    @printf("%-30s %9.1f %8.2f %6s %14s %12s %12s\n", r.name, r.total_ns / 1e6 / r.count, ins / cyc, "",
            ApplePerf.Analysis._commas(round(Int, c["L1D_CACHE_MISS_LD_NONSPEC"] / r.count)),
            ApplePerf.Analysis._commas(round(Int, c["L1D_TLB_MISS_NONSPEC"] / r.count)),
            ApplePerf.Analysis._commas(round(Int, c["BRANCH_MISPRED_NONSPEC"] / r.count)))
end
println("(per run; the two matrix sums execute the same instructions, the two count_pos calls too)")

banner("5. Which line pays for it?")
ApplePerf.Analysis.report(res; region = "sum by rows (stride 4096)", top = 3, by = "L1D_TLB_MISS_NONSPEC")
ApplePerf.Analysis.report(res; region = "count_pos random", top = 3, by = "BRANCH_MISPRED_NONSPEC")

banner("6. Export for pprof / speedscope")
pb = joinpath(pwd(), "demo.pb.gz"); folded = joinpath(pwd(), "demo.folded")
ApplePerf.Analysis.pprof(res, pb)
ApplePerf.Analysis.collapsed(res, folded; by = "L1D_CACHE_MISS_LD_NONSPEC")
println("wrote ", pb, " and ", folded)
println("  julia> using PProf; PProf.refresh(file = \"", pb, "\")     # or: pprof -http=: ", pb)
println("  pprof -sample_index=BRANCH_MISPRED_NONSPEC -tagfocus='region=count_pos random' -top ", pb)
println("  speedscope ", folded, "                         # flame graph weighted by L1D misses")

if "--open" in ARGS
    banner("7. Same trace in Instruments (Points of Interest shows the regions)")
    open_in_instruments(res.trace)
end
