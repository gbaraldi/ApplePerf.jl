module Entitlements

"""
    has_get_task_allow(binary = Sys.BINDIR/julia) -> Bool

Whether the executable carries `com.apple.security.get-task-allow`, which the
Processor Trace instrument requires of its target.
"""
function has_get_task_allow(binary::AbstractString = joinpath(Sys.BINDIR, "julia"))
    out = IOBuffer()
    run(pipeline(ignorestatus(`codesign -d --entitlements :- $binary`); stdout = out, stderr = devnull))
    return occursin("get-task-allow", String(take!(out)))
end

"""
    make_debuggable_julia(dest) -> String

Create a copy of the running Julia's executable at `dest/bin/julia`, ad-hoc
signed with the `com.apple.security.get-task-allow` entitlement, next to
symlinks of `lib`, `share`, `etc`, `libexec`, `include` so it runs in place.
Returns the path of the new executable. Needed once for Processor Trace:

```julia
julia_dbg = make_debuggable_julia(expanduser("~/.julia/julia-debuggable"))
# then start Julia with that path and use profile(...; options = RecordingOptions(template = "Processor Trace"))
```
"""
function make_debuggable_julia(dest::AbstractString)
    Sys.isapple() || error("macOS only")
    root = dirname(Sys.BINDIR)
    src = joinpath(Sys.BINDIR, "julia")
    mkpath(joinpath(dest, "bin"))
    exe = joinpath(dest, "bin", "julia")
    cp(src, exe; force = true)
    for d in ("lib", "share", "etc", "libexec", "include")
        p = joinpath(root, d)
        isdir(p) || continue
        l = joinpath(dest, d)
        islink(l) || isdir(l) || symlink(p, l)
    end
    ent = joinpath(dest, "get-task-allow.plist")
    write(ent, """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
        """)
    run(`codesign -s - -f --entitlements $ent $exe`)
    has_get_task_allow(exe) || error("re-signing failed")
    return exe
end

end # module Entitlements
