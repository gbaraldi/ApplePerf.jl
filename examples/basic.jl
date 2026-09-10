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
gather(A, B); gather(As, Bs); sum(A)   # compile

res = profile() do
    for _ in 1:20
        @region "gather 128 MiB" gather(A, B)
        @region "gather 8 KiB" gather(As, Bs)
        @region "sum 128 MiB" sum(A)
    end
end
show(stdout, MIME"text/plain"(), res); println()
ApplePerf.Analysis.report(res; region = "gather 8 KiB", top = 6)
ApplePerf.Analysis.collapsed(res, "profile.folded")
ApplePerf.Analysis.pprof(res, "profile.pb")
println("wrote profile.folded and profile.pb; trace at ", res.trace)
