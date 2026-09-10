# Instruments' guided CPU-bottleneck analysis. No raw counters, but every sample is
# flagged as instruction-delivery-, discarded- (bad speculation) or processing-bound,
# and those flags are attributed to regions, functions and a colored flame graph.
#
#   julia --project=. examples/bottlenecks.jl
using ApplePerf

A = rand(Float64, 1 << 24); B = rand(1:length(A), 4_000_000)
gather(A, B) = (s = 0.0; @inbounds for i in B; s += A[i]; end; s)                    # memory bound
function dotp(A) s = 0.0; @inbounds @simd for i in eachindex(A); s += A[i] * A[i]; end; s end
data = rand(Int32(-100):Int32(100), 8_000_000)
@noinline bump(c, x) = c + Int(x)
count_pos(v) = (c = 0; @inbounds for x in v; if x > 0; c = bump(c, x); end; end; c)  # bad speculation
fs = Any[x -> x + i for i in 1:512]
dispatch_chain(fs, n) = (s = 0; @inbounds for k in 1:n, f in fs; s = f(s); end; s)   # calls, dispatch
gather(A, B); dotp(A); count_pos(data); dispatch_chain(fs, 10)

res = profile(; options = RecordingOptions(bottlenecks = true)) do
    for _ in 1:3
        @region "gather (memory)" gather(A, B)
        @region "dot (streaming simd)" dotp(A)
        @region "count_pos (branchy)" count_pos(data)
        @region "dispatch chain (calls)" dispatch_chain(fs, 400)
    end
end
show(stdout, MIME"text/plain"(), res); println()     # remarks per region
ApplePerf.Analysis.bottleneck_table(res; top = 8)    # % of each function's samples flagged, per bottleneck
ApplePerf.Analysis.flamegraph(res, "bottlenecks.svg")
ApplePerf.Analysis.pprof(res, "bottlenecks.pb.gz")   # flags become columns: -sample_index='High Discarded'
println("wrote bottlenecks.svg (blue=delivery red=discarded purple=both orange=processing green=useful)")
println("trace: ", res.trace)
