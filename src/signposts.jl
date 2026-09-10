"""
    ApplePerf.Signposts

`os_signpost` intervals and events emitted from Julia, visible in Instruments'
Points of Interest track and in `xctrace export` (`os-signpost` table). No
privileges needed.

The system requires the signpost *name* and *format* strings to live inside
the `__TEXT` segment of a loaded Mach-O image (they are transmitted as image
offsets). Julia heap strings therefore cannot be used directly. Like Julia's
own `WITH_APPLE_OSLOG` timing backend, we pass a literal that already exists in
`libjulia-codegen` as the name and a `"%s"` literal as the format, and ship the
real region name as the formatted message argument. Instruments shows it as
the signpost message; `ApplePerf.profile` uses it as the region name.
"""
module Signposts

using Libdl

const LIBTRACE = "/usr/lib/system/libsystem_trace.dylib"
const _emit = Ref{Ptr{Cvoid}}(C_NULL)
const _log = Ref{Ptr{Cvoid}}(C_NULL)
const _dso = Ref{Ptr{Cvoid}}(C_NULL)
const _lit_fmt = Ref{Ptr{UInt8}}(C_NULL)     # "%s" inside the image
const _lit_name = Ref{Ptr{UInt8}}(C_NULL)    # signpost name literal inside the image
const _ok = Ref{Bool}(false)
const SUBSYSTEM = "org.julialang.ApplePerf"

const OS_SIGNPOST_EVENT = UInt8(0)
const OS_SIGNPOST_INTERVAL_BEGIN = UInt8(1)
const OS_SIGNPOST_INTERVAL_END = UInt8(2)

function _image_header(pattern::Regex)
    n = ccall(:_dyld_image_count, UInt32, ())
    for i in 0:n-1
        nm = unsafe_string(ccall(:_dyld_get_image_name, Cstring, (UInt32,), i))
        occursin(pattern, nm) && return ccall(:_dyld_get_image_header, Ptr{Cvoid}, (UInt32,), i)
    end
    return C_NULL
end

# Find a NUL-terminated literal `s` inside the image's __TEXT,__cstring section.
function _find_literal(hdr::Ptr{Cvoid}, s::String)
    sz = Ref{Culong}(0)
    cs = ccall(:getsectiondata, Ptr{UInt8}, (Ptr{Cvoid}, Cstring, Cstring, Ref{Culong}), hdr, "__TEXT", "__cstring", sz)
    cs == C_NULL && return Ptr{UInt8}(C_NULL)
    needle = s * "\0"
    p = cs; last = cs + sz[]
    while p < last
        q = ccall(:memmem, Ptr{UInt8}, (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t), p, last - p, needle, sizeof(needle))
        q == C_NULL && return Ptr{UInt8}(C_NULL)
        (q == cs || unsafe_load(q - 1) == 0x00) && return q
        p = q + 1
    end
    return Ptr{UInt8}(C_NULL)
end

function __init__()
    Sys.isapple() || return
    try
        lib = dlopen(LIBTRACE)
        _emit[] = dlsym(lib, :_os_signpost_emit_with_name_impl)
        _log[] = ccall(:os_log_create, Ptr{Cvoid}, (Cstring, Cstring), SUBSYSTEM, "PointsOfInterest")
        for pat in (r"libjulia-codegen", r"libjulia-internal", r"libjulia\.")
            hdr = _image_header(pat)
            hdr == C_NULL && continue
            fmt = _find_literal(hdr, "%s")
            fmt == C_NULL && continue
            name = C_NULL
            for cand in ("julia", "Julia", "JIT", "region", "ccall", "codegen", "task")
                name = _find_literal(hdr, cand)
                name == C_NULL || break
            end
            name == C_NULL && continue
            _dso[] = hdr; _lit_fmt[] = fmt; _lit_name[] = name
            _ok[] = true
            break
        end
    catch err
        @debug "ApplePerf.Signposts unavailable" err
    end
end

"""Whether signposts can be emitted from this process."""
signposts_enabled() = _ok[]

"""The literal used as the signpost *name* (the region name travels in the message)."""
signpost_name() = _ok[] ? unsafe_string(_lit_name[]) : ""

"""Whether any tool (Instruments, xctrace, `log stream`) is currently collecting our signposts."""
function listening()
    _ok[] || return false
    return ccall(:os_signpost_enabled, Bool, (Ptr{Cvoid},), _log[])
end

new_id() = ccall(:os_signpost_id_generate, UInt64, (Ptr{Cvoid},), _log[])

# Argument buffer layout for a single "%s" argument (see os/log.h, and Julia's
# src/timing.c): summary byte 2 (has non-scalar items), 1 item, item kind 0x22
# (string, public), size 8, then the char* pointer.
@inline function _emit_msg(type::UInt8, id::UInt64, msg::String)
    _ok[] || return nothing
    buf = Ref{NTuple{12,UInt8}}()
    GC.@preserve buf msg begin
        p = Base.unsafe_convert(Ptr{UInt8}, buf)
        unsafe_store!(p, 0x02, 1); unsafe_store!(p, 0x01, 2); unsafe_store!(p, 0x22, 3); unsafe_store!(p, 0x08, 4)
        unsafe_store!(Ptr{Ptr{UInt8}}(p + 4), pointer(msg))
        ccall(_emit[], Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, UInt8, UInt64, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}, UInt32),
              _dso[], _log[], type, id, _lit_name[], _lit_fmt[], p, 12)
    end
    return nothing
end

"""Begin an interval; returns the id to pass to `finish`."""
function begin_interval(name::AbstractString)
    id = _ok[] ? new_id() : UInt64(0)
    _emit_msg(OS_SIGNPOST_INTERVAL_BEGIN, id, String(name))
    return id
end
finish(id::UInt64, name::AbstractString) = _emit_msg(OS_SIGNPOST_INTERVAL_END, id, String(name))

"""
    mark_event(name)

Emit a point event (shows as a marker in Instruments' Points of Interest).
"""
mark_event(name::AbstractString) = _emit_msg(OS_SIGNPOST_EVENT, _ok[] ? new_id() : UInt64(0), String(name))

"""
    region(f, name)

Run `f()` inside a signposted interval named `name`.
"""
function region(f, name::AbstractString)
    id = begin_interval(name)
    try
        return f()
    finally
        finish(id, name)
    end
end

"""
    @region "name" expr

Evaluate `expr` inside a signposted interval. `name` may be any expression
evaluating to a string.
"""
macro region(name, ex)
    quote
        local nm = String($(esc(name)))
        local id = begin_interval(nm)
        try
            $(esc(ex))
        finally
            finish(id, nm)
        end
    end
end

end # module Signposts
