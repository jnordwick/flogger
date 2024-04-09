const std = @import("std");

pub const is_debug = std.debug.runtime_safety;

pub fn Bytes(comptime T: type) type {
    return extern union {
        val: T,
        bytes: [@sizeOf(T)]u8,
    };
}

pub fn write_all(comptime Type: type, fd: std.os.fd_t, p: *const Type) !usize {
    const tsize = @sizeOf(Type);
    var bp: *const [tsize]u8 = @ptrCast(p);
    var wrote: usize = 0;

    while (wrote < tsize) {
        wrote += try std.os.write(fd, bp[wrote..]);
    }
    return wrote;
}

/// returns amount of padding needed to align to a.
/// a: must be a power of 2.
pub fn padding(addr: usize, comptime aline: usize) usize {
    if (is_debug) {
        std.debug.assert(@popCount(aline) == 1);
    }
    const p: isize = @bitCast(addr);
    const neg: usize = @as(usize, @bitCast(-p));
    return neg & (aline - 1);
}

/// round x up to next multiple of lot if not already a multiple
pub fn roundUp(x: anytype, lot: @TypeOf(x)) @TypeOf(x) {
    const ti = @typeInfo(@TypeOf(x));
    std.debug.assert(ti == .Int or ti == .ComptimeInt);
    return ((x - 1 + lot) / lot) * lot;
}

pub fn span_unaligned_cast(comptime Old: type, comptime New: type, span: []Old) []align(1) New {
    const osize = @sizeOf(Old);
    const nsize = @sizeOf(New);

    comptime {
        if (is_debug) {
            const small = @min(osize, nsize);
            const big = @max(osize, nsize);
            std.debug.assert(big % small == 0);
            std.debug.assert(osize * span.len % nsize == 0);
        }
    }

    const bytes = to_byte_span();
    const p: [*]align(1) New = bytes.ptr;
    const siz = (span.len * osize) / nsize;
    return p[0..siz];
}

pub fn to_byte_span(comptime Old: type, span: []Old) []u8 {
    const p: [*]u8 = span.ptr;
    const s = span.len * @sizeOf(Old);
    return p[0..s];
}
