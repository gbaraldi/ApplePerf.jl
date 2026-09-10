using ApplePerf, Test

@testset "ApplePerf" begin
    hw = ApplePerf.KPEP.available()
    hw || @info "no kpep database on this machine (virtual machine?); skipping counter tests"

    @testset "kpep database" begin
        if !hw
            @test_throws ErrorException events()
        else
        evs = events()
        @test length(evs) > 50
        @test any(e -> e.name == "FIXED_CYCLES" && e.fixed, evs)
        @test counter_slots().fixed == 2
        @test can_coexist("FIXED_CYCLES", "FIXED_INSTRUCTIONS", "L1D_CACHE_MISS_LD_NONSPEC")
        # more events than a mask has slots can never coexist; which events share a
        # narrow mask differs per chip, so derive the set from the database
        narrow = filter(e -> !e.fixed && count_ones(e.mask) < 8, evs)
        if !isempty(narrow)
            m = narrow[1].mask
            same = [e.name for e in narrow if e.mask == m]
            toomany = [same[mod1(i, length(same))] for i in 1:count_ones(m)+1]
            @test !can_coexist(toomany...)
            @test length(plan_groups(toomany)) == 2
        end
        @test !can_coexist(fill("CORE_ACTIVE_CYCLE", 9)...)   # 9 configurable events, 8 slots
        @test_throws ErrorException ApplePerf.KPEP.event("NOT_AN_EVENT")
        @test occursin("L1D", sprint(io -> describe("L1D_CACHE_MISS_LD"; io)))
        end
    end

    @testset "signposts" begin
        @test signposts_enabled()
        @test (@region "test" 1 + 1) == 2
        @test region(() -> 42, "r") == 42
        @test mark_event("m") === nothing
    end

    @testset "recording options" begin
        if hw
        j = ApplePerf.XCTrace.options_json(RecordingOptions())
        @test occursin("\"sampleByTime\":true", j) && occursin("\"manual\"", j)
        @test occursin("\"guided\"", ApplePerf.XCTrace.options_json(RecordingOptions(events = String[])))
        @test occursin("\"guided\"", ApplePerf.XCTrace.options_json(RecordingOptions(bottlenecks = true)))
        j = ApplePerf.XCTrace.options_json(RecordingOptions(sample_event = "CORE_ACTIVE_CYCLE", threshold = 1000))
        @test occursin("\"pmiThreshold\":1000", j) && occursin("\"sampleByTime\":false", j)
        @test_throws ArgumentError ApplePerf.XCTrace.options_json(RecordingOptions(sample_event = "FIXED_CYCLES"))
        j = ApplePerf.XCTrace.options_json(RecordingOptions(events = ["FIXED_CYCLES", "L1D_CACHE_MISS_LD_NONSPEC"]))
        @test occursin("\"manual\"", j) && occursin("YnBsaXN0", j) == false   # XML archive, base64 of "<?xml"
        @test occursin("PD94bWwg", j)
        @test_throws ArgumentError ApplePerf.XCTrace.options_json(RecordingOptions(events = fill("CORE_ACTIVE_CYCLE", 9)))
        end
    end

    @testset "kpc (root only)" begin
        if !hw
            @test !KPC.has_access()
        elseif KPC.has_access()
            d = KPC.measure(() -> sum(rand(10^6)), ["FIXED_CYCLES", "FIXED_INSTRUCTIONS"])
            @test d["FIXED_CYCLES"] > 10^5 && d["FIXED_INSTRUCTIONS"] > 10^5
        else
            @test_throws ErrorException KPC.start!(KPC.Session(["FIXED_CYCLES"]))
        end
    end

    @testset "profile via xctrace" begin
        if hw && xctrace_available() && get(ENV, "APPLEPERF_TEST_XCTRACE", "1") == "1"
            A = rand(1 << 20); f(A) = sum(A); f(A)
            res = profile(; name = "outer") do
                t = time(); while time() - t < 0.3; @region "sum" f(A); end
            end
            regs = ApplePerf.Analysis.regions(res)
            @test any(r -> r.name == "sum" && r.count > 10, regs)
            @test !isempty(res.samples)
            @test "FIXED_CYCLES" in res.counter_names
            @test ApplePerf.Analysis.counters(res, "sum")["FIXED_CYCLES"] > 10^6
            @test any(p -> occursin("mapreduce", p.first) || occursin("sum", p.first), ApplePerf.Analysis.by_function(res))
            pb = tempname() * ".pb.gz"; ApplePerf.Analysis.pprof(res, pb); @test filesize(pb) > 100
            fo = tempname() * ".folded"; ApplePerf.Analysis.collapsed(res, fo); @test filesize(fo) > 10
            sv = tempname() * ".svg"; ApplePerf.Analysis.flamegraph(res, sv; by = "FIXED_CYCLES"); @test occursin("<svg", read(sv, String))
            @test occursin("FIXED_CYCLES", sprint(io -> ApplePerf.Analysis.bottleneck_table(res; io, top = 3)))
            rm(res.trace; recursive = true, force = true)
        else
            @info "skipping xctrace tests"
        end
    end
end
