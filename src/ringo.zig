const std = @import("std");
const os = std.os;

const util = @import("./util.zig");

const header_page_size = 4 * 1024;
const ring_page_size = 4 * 1024;
const cache_line_size = 64;

const RingError = error{NoSpace};

const EntrySize = u16;

// --- in file structs ---
const Magic4 = util.Bytes(u32);
const magicnum = Magic4{ .val = 1196379206 };

const Header = extern struct {
    const _pad_size = header_page_size - cache_line_size * 3;

    info: InfoLine,
    wr: SharedLine,
    rd: SharedLine,
    _pad: [_pad_size]u8 = [_]u8{0} ** _pad_size,

    pub fn init(magic: u32, ver: u32, cap: u64, wpos: u64, rpos: u64) @This() {
        return .{
            .info = .{
                .magic = magic,
                .ver = ver,
                .cap = cap,
            },
            .wr = .{ .pos = wpos },
            .rd = .{ .pos = rpos },
        };
    }
};

const InfoLine = extern struct {
    const _pad_size = cache_line_size - 4 - 4 - 8;

    magic: u32,
    ver: u32,
    cap: u64,
    _pad: [_pad_size]u8 = [_]u8{0} ** _pad_size,
};

const SharedLine = extern struct {
    const _pad_size = cache_line_size - 8;

    pos: u64,
    _pad: [_pad_size]u8 = [_]u8{0} ** _pad_size,
};

// --- non file structs ---
const LocalLine = extern struct {
    const _pad_size = cache_line_size - 8 * 3;

    pos: u64,
    lim: u64,
    _pad: [_pad_size]u8 = [_]u8{0} ** _pad_size,

    pub fn init(p: u64, l: u64) @This() {
        return .{ .pos = p, .lim = l };
    }
};

const RoLine = extern struct {
    const _pad_size = cache_line_size - 8 * 2;

    ring: [*]u8,
    cap: u64,
    _pad: [_pad_size]u8 = [_]u8{0} ** _pad_size,

    pub fn init(r: [*]u8, c: u64) @This() {
        return .{ .ring = r, .cap = c };
    }
};

/// shared SPSC ring buffer using mmap.
pub const RingBuffer = extern struct {
    const This = @This();

    /// base of mappings, extends for sizeof Header + 2*cap
    base: *Header,
    /// read only shared data - prevent unintended sharing and
    /// LLVM overly granular dirties stuff
    ro_loc: RoLine,
    /// writer local data
    wr_loc: LocalLine,
    /// reader local data
    rd_loc: LocalLine,

    /// create the RingBuffer and create disk file, if needed.
    /// fname: filename, if relative frpom pwd
    /// cap: ring capacity, only used if file needs to be created
    ///      too, if not then read from file
    /// mode: what to do if the fie alredy exists:
    ///           .Force truncate the file and craete a new RingBuffer
    ///           .Error return the error from open
    ///           .OrMap load the map from disk
    pub fn create(
        fname: []const u8,
        cap: u64,
        mode: enum { Force, OrMap, Error },
    ) !RingBuffer {
        var flags: u32 = os.O.RDWR | os.O.NOATIME | os.O.CREAT;
        flags |= switch (mode) {
            .Force => os.O.TRUNC,
            .Error => os.O.EXCL,
            else => 0,
        };

        const fd = os.open(fname, flags, 0o666) catch |err| {
            if (err == std.os.OpenError.PathAlreadyExists and mode == .OrMap)
                return mapname(fname);
            return err;
        };
        defer os.close(fd);

        const cap4k = util.roundUp(cap, ring_page_size);
        const full_size = cap4k + @sizeOf(Header);
        try os.ftruncate(fd, full_size);

        const head = Header.init(magicnum.val, 0, cap4k, 0, 0);

        try os.lseek_SET(fd, 0);
        _ = try util.write_all(@TypeOf(head), fd, &head);
        return mapfd(fd);
    }

    pub fn mapname(fname: []const u8) !RingBuffer {
        const flags = os.O.RDWR | os.O.NOATIME;
        const fd = try std.os.open(fname, flags, 0);
        defer std.os.close(fd);
        return mapfd(fd);
    }

    // the strategy is to map fd for a larger region than the file,
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
        std.debug.assert(head_size == header_page_size);
        const ring_size = try os.lseek_CUR_get(fd) - head_size;
        const over_size = 2 * ring_size + head_size;

        const prot = os.PROT.READ | os.PROT.WRITE;
        const flag = os.MAP.SHARED_VALIDATE | os.MAP.LOCKED | os.MAP.POPULATE;

        const addr = try os.mmap(null, over_size, prot, flag, fd, 0);
        const low_addr: [*]u8 = addr.ptr + head_size;
        const hig_addr: [*]u8 = addr.ptr + head_size + ring_size;
        _ = try os.mmap(@alignCast(low_addr), ring_size, prot, flag | os.MAP.FIXED, fd, head_size);
        _ = try os.mmap(@alignCast(hig_addr), ring_size, prot, flag | os.MAP.FIXED, fd, head_size);
        const header: *Header = @ptrCast(addr.ptr);

        const cap: u64 = header.info.cap;
        const wrpos: u64 = header.wr.pos;
        const rdpos: u64 = header.rd.pos;
        var wrlim: u64 = rdpos + (if (rdpos < wrpos) cap else 0);
        if (wrlim == 0) {
            wrlim = cap - 1;
        }
        const rdlim: u64 = wrpos + if (rdpos > wrpos) cap else 0;

        return RingBuffer{
            .base = header,
            .ro_loc = RoLine.init(low_addr, cap),
            .wr_loc = LocalLine.init(wrpos, wrlim),
            .rd_loc = LocalLine.init(rdpos, rdlim),
        };
    }

    pub fn push(s: *This, buf: []const u8) RingError!void {
        std.debug.print("\nbuf of {d}\n", .{buf.len});
        var mem = try s.write_alloc(@intCast(buf.len));
        write_string(mem.ptr, buf);
        s.write_commit();
    }

    pub fn write_alloc(s: *This, len: u64) RingError![]u8 {
        std.debug.assert(len < comptime std.math.maxInt(EntrySize));
        const pad = util.padding(@intCast(len), @alignOf(EntrySize));
        const data_len: u32 = @intCast(len + pad);
        const full_len: u32 = @intCast(data_len + @sizeOf(EntrySize));

        const npos = s.wr_loc.pos + full_len;
        if (npos >= s.wr_loc.lim)
            try s.recheck_write_alloc(npos);

        var base: [*]u8 = s.ro_loc.ring + s.wr_loc.pos;
        const es: *EntrySize = @alignCast(@ptrCast(base));
        es.* = @intCast(data_len);
        base += @sizeOf(EntrySize);
        const span = base[0..data_len];
        s.wr_loc.pos += full_len;
        return span;
    }

    fn recheck_write_alloc(s: *This, npos: u64) RingError!void {
        s.wr_loc.lim = s.gen_write_limit();
        if (npos >= s.wr_loc.lim)
            return error.NoSpace;
        return;
    }

    fn write_string(p: [*]u8, str: []const u8) void {
        const sz_ptr: *EntrySize = @alignCast(@ptrCast(p));
        sz_ptr.* = @intCast(str.len);
        @memcpy(p + @sizeOf(EntrySize), str);
    }

    pub fn pull(s: *This, buf: []u8) ![]u8 {
        const span = s.next_read_span();
        if (span.len > buf.len)
            return error.NoSpace;
        @memcpy(buf.ptr, span);
        s.read_commit();
        return buf[0..span.len];
    }

    fn peek_next_size(s: *const This) EntrySize {
        const p: *const EntrySize = @alignCast(@ptrCast(s.ro_loc.ring + s.rd_loc.pos));
        return p.*;
    }

    fn next_read_span(s: *This) []u8 {
        std.debug.assert(s.rd_loc.lim >= s.rd_loc.pos);
        const base = s.ro_loc.ring + s.rd_loc.pos + @sizeOf(EntrySize);
        var amt = s.rd_loc.lim - s.rd_loc.pos;
        if (amt == 0) {
            std.debug.print("nothing to read 1\n", .{});
            s.rd_loc.lim = s.gen_read_limit();
            std.debug.print("new read limit {d}\n", .{s.rd_loc.lim});
            amt = s.rd_loc.lim - s.rd_loc.pos;
            if (amt == 0) {
                std.debug.print("nothing to read 2\n", .{});
                return base[0..0];
            }
        }
        std.debug.print("found {d} to read\n", .{amt});
        // If there is any data is should be of at least entry size
        // since partial records should never be comm
        std.debug.assert(amt >= @sizeOf(EntrySize));

        const data_len = s.peek_next_size();
        std.debug.print("reading {d}\n", .{data_len});
        // need to keep even alignment for next EntrySize
        const bump = data_len + (data_len & 1) + @sizeOf(EntrySize);
        std.debug.print("bumping {d}, dl={d}, so={d}\n", .{ bump, data_len, @sizeOf(EntrySize) });
        s.rd_loc.pos += bump;
        return base[0..data_len];
    }

    fn read_string(dest: []u8, src: []const u8) EntrySize {
        @memcpy(dest.ptr, src);
        return src.len;
    }

    fn wpos_load(s: *const This) u64 {
        return @atomicLoad(u64, &s.base.wr.pos, .Monotonic);
    }

    fn rpos_load(s: *const This) u64 {
        return @atomicLoad(u64, &s.base.rd.pos, .Monotonic);
    }

    pub fn write_commit(s: *This) void {
        const cap = s.ro_loc.cap;
        if (s.wr_loc.pos >= cap) {
            s.wr_loc.pos -= cap;
            s.wr_loc.lim -= cap;
        }
        @atomicStore(u64, &s.base.wr.pos, s.wr_loc.pos, .Monotonic);
    }

    fn read_commit(s: *This) void {
        const cap = s.ro_loc.cap;
        if (s.rd_loc.pos >= cap) {
            s.rd_loc.pos -= cap;
            s.rd_loc.lim -= cap;
        }
        @atomicStore(u64, &s.base.rd.pos, s.rd_loc.pos, .Monotonic);
    }

    fn gen_write_limit(s: *const This) u64 {
        const r = s.rpos_load();
        return r + (if (r > s.wr_loc.pos) 0 else s.ro_loc.cap) - 1;
    }

    fn gen_read_limit(s: *const This) u64 {
        const w = s.wpos_load();
        const lim = w + if (w >= s.rd_loc.pos) 0 else s.ro_loc.cap;
        std.debug.print("gen_read_lim w={d} rdloc={d} lim={d}\n", .{ w, s.rd_loc.pos, lim });
        return lim;
    }
};

comptime {
    if (@sizeOf(Header) != header_page_size)
        @compileError("Header size unexpected");
}

const T = std.testing;

test "create" {
    try T.expectEqual(header_page_size, @sizeOf(Header));
    var rb = try RingBuffer.create("./rbuf", 100, .Force);
    try T.expectEqual(@as(u64, 0), rb.base.info.cap % ring_page_size);
    _ = try rb.push("a");
    _ = try rb.push("ab");
    //_ = try rb.push("abc");
    //_ = try rb.push("abcd");
    //_ = try rb.push("abcde");
    //_ = try rb.push("abcdef");
}
