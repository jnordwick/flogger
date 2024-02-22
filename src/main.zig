const std = @import("std");
const os = std.os;

// TODO add hugepage support
const header_page_size = 4096;
const ring_page_size = 4096;
const cache_line_size = 64;

pub fn write_all(comptime Type: type, fd: os.fd_t, p: *const Type) !usize {
    const tsize = @sizeOf(Type);
    var bp: *const [tsize]u8 = @ptrCast(p);
    var wrote: usize = 0;

    while (wrote < tsize) {
        wrote += try os.write(fd, bp[wrote..]);
    }
    return wrote;
}

const Magic = extern union {
    bytes: [8]u8,
    int: u64,
};

const AtomicLine = extern struct {
    const Type = std.atomic.Atomic(u32);
    const pad_size = cache_line_size - @sizeOf(Type);

    val: Type,
    pad: [pad_size]u8 = [_]u8{0} ** pad_size,
};

const HeaderInfo = extern struct {
    magic: Magic,
    ver: u32,
    len: u32,
};

pub const magic_string = Magic{ .bytes = .{ 'f', 'l', 'o', 'g', 'g', 'e', 'r', 0 } };

const Header = extern struct {
    const info_pad_size = cache_line_size - @sizeOf(HeaderInfo);
    const header_pad_size = header_page_size - cache_line_size * 3;

    info: HeaderInfo,
    pad1: [info_pad_size]u8 = [_]u8{0} ** info_pad_size,
    head: AtomicLine,
    tail: AtomicLine,
    pad2: [header_pad_size]u8 = [_]u8{0} ** header_pad_size,
};

fn roundUp(x: anytype, to: @TypeOf(x)) @TypeOf(x) {
    std.debug.assert(@typeInfo(@TypeOf(x)) == .Int);
    return ((x + to - 1) / to) * to;
}

const RingBuffer = struct {
    header: *Header,
    ring_low: [*]u8,
    ring_high: [*]u8,

    // TODO check ret values
    pub fn create(fname: []const u8, len: u32, force: bool) !RingBuffer {
        // zig fmt: off
        const flags: u32 = os.O.RDWR | os.O.NOATIME | os.O.CREAT
            | @as(u32, if (force) os.O.TRUNC else os.O.EXCL);

        const fd = try os.open(fname, flags, 0o666);
        defer os.close(fd);

        const len4k = roundUp(len, ring_page_size);
        const fsize = len4k + @sizeOf(Header);
        try os.ftruncate(fd, fsize);

        const head = Header{
            .info = .{
                .magic = magic_string,
                .ver = 1,
                .len = len4k,
            },
            .head = .{ .val = .{ .value = 0 } },
            .tail = .{ .val = .{ .value = 0 } },
        };

        try os.lseek_SET(fd, 0);
        _ = try write_all(@TypeOf(head), fd, &head);
        return mapfd(fd);
    }

    pub fn map(fname: [*:0]const u8) !RingBuffer {
        const flags = os.O.RDWR | os.O.NOATIME;
        const fd = try std.c.open(fname, flags);
        defer std.c.close(fd);
        return mapfd(fd);
    }

    // the strategy is to max fd for a larger region than the file,
    // specifixally header size + 2 * ring size and let the OS pick
    // a place, then map over the back of the area the rign data twice.
    // only 2 mmaps are really required but playing with huge pages made
    // the alignemnt easier to calculate (the last 2 mmaps have different
    // alignment than the first). This protects us from having the first
    // mmap not have enough space for the final mapping which had a
    // tendency to fail.
    pub fn mapfd(fd: c_int) !RingBuffer {
        try os.lseek_END(fd, 0);
        const head_size = @sizeOf(Header);
        const ring_size = try os.lseek_CUR_get(fd) - head_size;
        const over_size = 2 * ring_size + head_size;

        const prot = os.PROT.READ | os.PROT.WRITE;
        const flag = os.MAP.SHARED_VALIDATE | os.MAP.LOCKED | os.MAP.POPULATE;

        const addr = try os.mmap(null, over_size, prot, flag, fd, 0);
        const low_addr: [*]u8 = addr.ptr + head_size;
        const hig_addr: [*]u8 = addr.ptr + head_size + ring_size;
        const low = try os.mmap(@alignCast(low_addr), ring_size, prot, flag | os.MAP.FIXED, fd, head_size);
        const hig = try os.mmap(@alignCast(hig_addr), ring_size, prot, flag | os.MAP.FIXED, fd, head_size);

        return .{
            .header = @ptrCast(addr.ptr),
            .ring_low = @ptrCast(low.ptr),
            .ring_high = @ptrCast(hig.ptr),
        };
    }
};

const T = std.testing;

test "create" {
    try T.expectEqual(header_page_size, @sizeOf(Header));
    const rb = try RingBuffer.create("./rbuf", 100, true);
    try T.expectEqual(@as(u32, 0), rb.header.info.len % ring_page_size);
}
