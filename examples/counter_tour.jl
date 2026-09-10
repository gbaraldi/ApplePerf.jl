# A tour of the interesting PMU events, grouped into sets that fit the 2 fixed + 8
# configurable counters at once, each exercised by micro-workloads designed to move them.
# Every group is one `profile` run (~10 s of xctrace overhead), so the whole tour takes
# about 90 s.
#
#   julia -t 4 --project=. examples/counter_tour.jl [branches|memory|mix|frontend|pipeline|atomics ...]
using ApplePerf, Printf

const SINK = Ref{Float64}(0.0)                 # keep results alive
sink(x) = (SINK[] += Float64(x); nothing)

fmtn(v) = v >= 1e9 ? @sprintf("%.2fG", v / 1e9) : v >= 1e6 ? @sprintf("%.2fM", v / 1e6) : v >= 1e3 ? @sprintf("%.1fk", v / 1e3) : @sprintf("%.0f", v)

function tour(title, events, workloads; runs = 3)
    printstyled("\n── ", title, " ", "─"^max(0, 78 - length(title)), "\n"; bold = true, color = :cyan)
    # The event catalog is read from the running CPU's kpep database (`events()`), so
    # names that this chip lacks are dropped rather than assumed.
    available = Set(event_names())
    missing = filter(!in(available), events)
    isempty(missing) || println("  not available on this CPU, skipped: ", join(missing, ", "))
    events = filter(in(available), events)
    for e in events
        ev = ApplePerf.KPEP.event(e)
        println("  ", rpad(e, 36), ev.fixed ? "" : first(ev.description, 84))
    end
    can_coexist(events...) || error("events cannot be counted together: $(plan_groups(events))")
    for (_, f) in workloads; f(); end          # compile
    res = profile(; options = RecordingOptions(events = events), name = title) do
        for _ in 1:runs, (name, f) in workloads
            @region name f()
        end
    end
    regs = filter(r -> r.name != title, ApplePerf.Analysis.regions(res))
    println()
    @printf("  %-30s %8s", "per run", "ms")
    for e in events; @printf(" %9s", first(replace(e, "_NONSPEC" => "", "FIXED_" => "", "BRANCH_" => "BR_", "INST_" => "I_"), 9)); end
    println()
    for r in regs
        @printf("  %-30s %8.2f", first(r.name, 30), r.total_ns / 1e6 / r.count)
        for e in events; @printf(" %9s", fmtn(get(r.counters, e, 0.0) / r.count)); end
        println()
    end
    return res
end

which = isempty(ARGS) ? ["branches", "memory", "mix", "frontend", "pipeline", "atomics"] : ARGS

# ─── 1. Branches ────────────────────────────────────────────────────────────────────
if "branches" in which
    data = rand(Int32(-100):Int32(100), 4_000_000); sorted = sort(data)
    @noinline bump(c, x) = c + Int(x)
    count_pos(v) = (c = 0; @inbounds for x in v; if x > 0; c = bump(c, x); end; end; sink(c))
    fs = Any[x -> x + i for i in 1:8]                         # indirect calls through a table
    idx_rand = rand(1:8, 2_000_000); idx_same = fill(3, 2_000_000)
    calls(idx) = (s = 0; @inbounds for i in idx; s = fs[i](s); end; sink(s))
    tour("branches", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "INST_BRANCH", "INST_BRANCH_COND", "BRANCH_COND_MISPRED_NONSPEC",
                      "INST_BRANCH_CALL_INDIR", "BRANCH_CALL_INDIR_MISPRED_NONSPEC", "BRANCH_RET_INDIR_MISPRED_NONSPEC", "ARM_BR_MIS_PRED"],
         ["cond branch, random data" => () -> count_pos(data),
          "cond branch, sorted data" => () -> count_pos(sorted),
          "indirect calls, random target" => () -> calls(idx_rand),
          "indirect calls, same target" => () -> calls(idx_same)])
end

# ─── 2. Data cache and TLB ───────────────────────────────────────────────────────────
if "memory" in which
    A_l1 = rand(Float64, 1 << 13)            # 64 KiB: L1-resident
    A_l2 = rand(Float64, 1 << 19)            # 4 MiB: L2-resident
    A_dram = rand(Float64, 1 << 26)          # 512 MiB: memory, many pages
    idx(A) = rand(1:length(A), 2_000_000)
    I1, I2, I3 = idx(A_l1), idx(A_l2), idx(A_dram)
    gather(A, I) = (s = 0.0; @inbounds for i in I; s += A[i]; end; sink(s))
    stream(A) = sink(sum(A))
    W = zeros(Float64, 1 << 24)              # 128 MiB store target
    tour("memory", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC", "L1D_CACHE_MISS_ST_NONSPEC", "L1D_TLB_MISS_NONSPEC",
                    "LD_SRC_LL_CACHE_NONSPEC", "LD_SRC_MEMSYS_NONSPEC", "L2_TLB_MISS_DATA", "MMU_TABLE_WALK_DATA", "L1D_CACHE_WRITEBACK"],
         ["gather 64 KiB (L1)" => () -> gather(A_l1, I1),
          "gather 4 MiB (L2)" => () -> gather(A_l2, I2),
          "gather 512 MiB (DRAM+TLB)" => () -> gather(A_dram, I3),
          "stream 128 MiB read" => () -> stream(W),
          "fill 128 MiB write" => () -> (fill!(W, 1.0); sink(W[end]))])
end

# ─── 3. Instruction and uop mix ──────────────────────────────────────────────────────
if "mix" in which
    xorshift(n) = (x = UInt64(88172645463325252); for _ in 1:n; x ⊻= x << 13; x ⊻= x >> 7; x ⊻= x << 17; end; sink(x & 0xff))
    V = rand(Float32, 1 << 22); W2 = similar(V)
    dot(V) = (s = 0f0; for _ in 1:8; @inbounds @simd for i in eachindex(V); s += V[i] * V[i]; end; end; sink(s))
    copy_(V, W2) = (for _ in 1:8; copyto!(W2, V); end; sink(W2[1]))
    S = rand(1:1000, 1 << 22)
    scalar_sum(S) = (s = 0; for _ in 1:4; @inbounds for x in S; s += x & 7; end; end; sink(s))
    tour("mix", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "RETIRE_UOP", "INST_INT_LD", "INST_INT_ST", "INST_SIMD_LD", "INST_SIMD_ST",
                 "INST_SIMD_ALU", "MAP_INT_UOP", "MAP_SIMD_UOP"],
         ["integer ALU chain (xorshift)" => () -> xorshift(20_000_000),
          "simd float dot 16 MiB x8" => () -> dot(V),
          "memcpy 16 MiB x8" => () -> copy_(V, W2),
          "scalar int reduction" => () -> scalar_sum(S)])
end

# ─── 4. Front end: instruction cache, ITLB, fetch ────────────────────────────────────
if "frontend" in which
    # 3000 distinct small methods called round-robin: a code footprint far beyond the L1I.
    for i in 1:3000
        @eval @noinline $(Symbol("leaf_", i))(x) = x + $i ⊻ (x >> 3)
    end
    leaves = Function[getfield(@__MODULE__, Symbol("leaf_", i)) for i in 1:3000]
    big_code(n) = (s = 0; for _ in 1:n, f in leaves; s = f(s)::Int; end; sink(s))
    tight(n) = (s = 0; for i in 1:n; s += i ⊻ (s >> 3); end; sink(s))
    tour("frontend", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1I_CACHE_MISS_DEMAND", "L1I_TLB_MISS_DEMAND", "L2_TLB_MISS_INSTRUCTION",
                      "MMU_TABLE_WALK_INSTRUCTION", "FETCH_RESTART", "MAP_DISPATCH_BUBBLE", "MAP_DISPATCH_BUBBLE_IC", "MAP_DISPATCH_BUBBLE_TAKENBR_SLOT"],
         ["3000 methods round-robin" => () -> big_code(50),
          "tight loop" => () -> tight(10_000_000)])
end

# ─── 5. Pipeline stalls ──────────────────────────────────────────────────────────────
if "pipeline" in which
    A = rand(Float64, 1 << 25); I = rand(1:length(A), 2_000_000)
    gather2(A, I) = (s = 0.0; @inbounds for i in I; s += A[i]; end; sink(s))
    serial(n) = (x = 1.0; for _ in 1:n; x = sqrt(x + 1.0); end; sink(x))          # dependent latency chain
    V = rand(Float64, 1 << 21)
    dot2(V) = (s = 0.0; for _ in 1:16; @inbounds @simd for i in eachindex(V); s += V[i] * V[i]; end; end; sink(s))
    data = rand(Int32(-100):Int32(100), 2_000_000)
    @noinline bump2(c, x) = c + Int(x)
    branchy(v) = (c = 0; @inbounds for x in v; if x > 0; c = bump2(c, x); end; end; sink(c))
    tour("pipeline", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "ARM_STALL_FRONTEND", "ARM_STALL_BACKEND", "SCHEDULE_EMPTY", "SCHEDULE_UOP_ANY",
                      "MAP_STALL", "MAP_REWIND", "LDST_UNIT_WAITING_OLD_L1D_CACHE_MISS", "FLUSH_RESTART_OTHER_NONSPEC"],
         ["memory bound gather" => () -> gather2(A, I),
          "dependent sqrt chain" => () -> serial(5_000_000),
          "simd dot (throughput)" => () -> dot2(V),
          "mispredicting branch" => () -> branchy(data)])
end

# ─── 6. Atomics, store forwarding, memory ordering, unaligned access ─────────────────
if "atomics" in which
    # Note: Threads.atomic_add! compiles to LSE atomics (ldadd), which the
    # ATOMIC_OR_EXCLUSIVE_* events largely do not count; they show up instead as
    # loads sourced from stores (LD_SRC_STORE_NONSPEC). Regions are per thread, so the
    # contended case puts its @region inside each worker.
    counter = Threads.Atomic{Int}(0)
    uncontended(n) = (for _ in 1:n; Threads.atomic_add!(counter, 1); end; sink(counter[]))
    function contended(n)
        Threads.@threads for _ in 1:Threads.nthreads()
            @region "atomic add, $(Threads.nthreads()) threads (per thread)" begin
                for _ in 1:n; Threads.atomic_add!(counter, 1); end
            end
        end
        sink(counter[])
    end
    # Store→load forwarding: write through P and read back through an aliasing view Q,
    # so LLVM cannot keep the carried value in a register and the load must be
    # forwarded from the just-executed store in hardware.
    P = rand(Float64, 1 << 22); Q = unsafe_wrap(Array, pointer(P), length(P))
    prefix!(P, Q) = (for _ in 1:4; @inbounds for i in 2:length(P); P[i] = Q[i-1] + P[i]; end; end; sink(P[end]))
    bytes = rand(UInt8, 1 << 26)
    function unaligned(bytes, stride, reps)                                            # loads straddling 64 B lines / 16 KiB pages
        p = pointer(bytes); s = UInt64(0)
        GC.@preserve bytes for _ in 1:reps, off in (stride - 4):stride:(length(bytes) - 8)
            s += unsafe_load(Ptr{UInt64}(p + off))
        end
        sink(s & 0xff)
    end
    const FENCE_TARGET = Threads.Atomic{Int}(0)       # global: the stores and fences cannot be eliminated
    function fences(n)
        for i in 1:n; Threads.atomic_fence(); FENCE_TARGET[] = i; end
        sink(FENCE_TARGET[])
    end
    tour("atomics", ["FIXED_CYCLES", "FIXED_INSTRUCTIONS", "ATOMIC_OR_EXCLUSIVE_SUCC", "ATOMIC_OR_EXCLUSIVE_FAIL", "ST_MEM_ORDER_VIOL_LD_NONSPEC",
                     "LD_SRC_STORE_NONSPEC", "INST_BARRIER", "LDST_X64_UOP", "LDST_XPG_UOP"],
         ["atomic add, 1 thread" => () -> uncontended(2_000_000),
          "atomic add, $(Threads.nthreads()) threads (main: waiting)" => () -> contended(2_000_000),
          "in-place prefix sum (forwarding)" => () -> prefix!(P, Q),
          "loads crossing 64B lines" => () -> unaligned(bytes, 64, 4),
          "loads crossing 16KiB pages" => () -> unaligned(bytes, 16384, 400),
          "fences" => () -> fences(20_000_000)])
end
