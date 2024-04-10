const std = @import("std");

const ring = @import("ring.zig");

const fname = "/home/jason/devel/flogger/src/rbuf";
const print = std.debug.print;

fn return_type(comptime func: anytype) type {
    return @typeInfo(@TypeOf(func)).Fn.return_type.?;
}

const Prt = return_type(print);

fn p(comptime s: []const u8) Prt {
    return print(s ++ "\n", .{});
}

fn p1(comptime s: []const u8, a: anytype) Prt {
    return print(s ++ "\n", .{a});
}

fn pp(comptime s: []const u8, a: anytype) Prt {
    return print(s ++ "\n", a);
}

pub fn main() !void {
    p("mapping file...");
    var rb = try ring.RingBuffer.mapname(fname);
    print("mapped file... cap={} rd={} wr={}\n", .{
        rb.base.info.cap,
        rb.base.rd.pos,
        rb.base.wr.pos,
    });
    var abuf: [100]u8 = undefined;
    var sbuf: []u8 = &abuf;
    print("pulling\n", .{});
    const d = try rb.pull(sbuf);
    print("pulled {d} {s}\n", .{ d.len, d });
}
