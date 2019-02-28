const std = @import("std");
const os = std.os;
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const page_size = std.os.page_size;
const posix = std.os.posix;

fn up_to_nearest_power_of_2(comptime T: type, n: T) T {
    var power: T = 1;
    while (power < n)
        power *= 2;
    return power;
}

const GeneralPurposeDebugAllocator = struct {
    allocator: Allocator,
    buckets: [small_bucket_count]Bucket,
    used_bytes: [used_bytes_len]u8,

    const used_bytes_len = blk: {
        var total = 0;
        var i = 0;
        while (i < small_bucket_count) : (i += 1) {
            const obj_size = 1 << i;
            const this_bucket_used_bytes = page_size / (8 * obj_size);
            total += this_bucket_used_bytes;
        }
        break :blk total;
    };

    const small_bucket_count = 8;

    const Bucket = struct {
        ptr: ?[*]u8,
        used_bits: []u8,
        end_index: usize,
    };

    pub fn create() !*GeneralPurposeDebugAllocator {
        comptime assert(page_size >= @sizeOf(GeneralPurposeDebugAllocator));
        const perms = posix.PROT_READ | posix.PROT_WRITE;
        const flags = posix.MAP_PRIVATE | posix.MAP_ANONYMOUS;
        const addr = posix.mmap(null, page_size, perms, flags, -1, 0);
        if (addr == posix.MAP_FAILED) return error.OutOfMemory;
        const self = @intToPtr(*GeneralPurposeDebugAllocator, addr);
        self.* = GeneralPurposeDebugAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .reallocFn = realloc,
                .freeFn = free,
            },
            .buckets = undefined,
            .used_bytes = [1]u8{0} ** used_bytes_len,
        };
        var offset: usize = 0;
        for (self.buckets) |*bucket, i| {
            const obj_size = usize(1) << @intCast(u6, i);
            const this_bucket_used_bytes = page_size / (8 * obj_size);
            const next_offset = offset + this_bucket_used_bytes;
            bucket.* = Bucket{
                .ptr = null,
                .end_index = 0,
                .used_bits = self.used_bytes[offset..next_offset],
            };
            offset = next_offset;
        }
        try self.mprotectInit(posix.PROT_READ);
        return self;
    }

    fn mprotectInit(self: *GeneralPurposeDebugAllocator, protection: u32) !void {
        os.posixMProtect(@ptrToInt(self), page_size, protection) catch |e| switch (e) {
            error.AccessDenied => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
            error.Unexpected => return error.OutOfMemory,
        };
    }

    fn mprotect(self: *GeneralPurposeDebugAllocator, protection: u32) void {
        os.posixMProtect(@ptrToInt(self), page_size, protection) catch unreachable;
    }

    pub fn destroy(self: *GeneralPurposeDebugAllocator) void {
        for (self.buckets) |*bucket| {
            for (bucket.used_bits) |used_byte| {
                if (used_byte != 0) {
                    var bit_index: u3 = 0;
                    while (true) : (bit_index += 1) {
                        const is_used = @truncate(u1, used_byte >> bit_index) != 0;
                        if (is_used) {
                            std.debug.warn("\nMemory leak detected:\n");
                            // TODO
                        }
                        if (bit_index == std.math.maxInt(u3))
                            break;
                    }
                }
            }
        }
        const err = posix.munmap(@ptrToInt(self), page_size);
        assert(posix.getErrno(err) == 0);
    }

    fn alloc(allocator: *Allocator, n: usize, alignment: u29) error{OutOfMemory}![]u8 {
        const self = @fieldParentPtr(GeneralPurposeDebugAllocator, "allocator", allocator);
        self.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.mprotect(posix.PROT_READ);

        if (n > (1 << (small_bucket_count - 1))) {
            return error.OutOfMemory;
        }
        // round n up to nearest power of 2
        const rounded_n = up_to_nearest_power_of_2(usize, n);
        const bucket_index = std.math.log2(rounded_n);
        const bucket = &self.buckets[bucket_index];
        if (bucket.end_index == page_size)
            return error.OutOfMemory;
        const ptr = bucket.ptr orelse blk: {
            const perms = posix.PROT_READ | posix.PROT_WRITE;
            const flags = posix.MAP_PRIVATE | posix.MAP_ANONYMOUS;
            const addr = posix.mmap(null, page_size, perms, flags, -1, 0);
            if (addr == posix.MAP_FAILED) return error.OutOfMemory;
            const ptr = @intToPtr([*]align(page_size) u8, addr);
            bucket.ptr = ptr;
            break :blk ptr;
        };
        // what byte and bit does the slot correspond to?
        const slot_index = bucket.end_index / rounded_n;
        const used_byte_index = slot_index / 8;
        const used_bit_index = @intCast(u3, slot_index % 8);
        const used_byte = bucket.used_bits[used_byte_index];
        const is_used = @truncate(u1, used_byte >> used_bit_index) != 0;
        assert(!is_used);
        bucket.used_bits[used_byte_index] = used_byte | (u8(1) << used_bit_index);

        const result = (ptr + bucket.end_index)[0..n];
        bucket.end_index += rounded_n;
        assert(result.len != 0);
        return result;
    }

    fn realloc(
        allocator: *Allocator,
        old_mem: []u8,
        new_size: usize,
        alignment: u29,
    ) error{OutOfMemory}![]u8 {
        //const self = @fieldParentPtr(GeneralPurposeDebugAllocator, "allocator", allocator);
        if (new_size <= old_mem.len) {
            return old_mem[0..new_size];
        }
        const new_mem = try alloc(allocator, new_size, alignment);
        @memcpy(new_mem.ptr, old_mem.ptr, old_mem.len);
        return new_mem;
    }

    fn free(allocator: *Allocator, bytes: []u8) void {
        const self = @fieldParentPtr(GeneralPurposeDebugAllocator, "allocator", allocator);
        self.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.mprotect(posix.PROT_READ);
        const rounded_n = up_to_nearest_power_of_2(usize, bytes.len);
        const bucket_index = std.math.log2(rounded_n);
        const bucket = &self.buckets[bucket_index];
        const bucket_ptr = bucket.ptr.?;
        const byte_offset = @ptrToInt(bytes.ptr) - @ptrToInt(bucket.ptr);
        const slot_index = byte_offset / rounded_n;
        const used_byte_index = slot_index / 8;
        const used_bit_index = @intCast(u3, slot_index % 8);
        const used_byte = bucket.used_bits[used_byte_index];
        const is_used = @truncate(u1, used_byte >> used_bit_index) != 0;
        assert(is_used);
        bucket.used_bits[used_byte_index] = used_byte & ~(u8(1) << used_bit_index);
    }
};

test "basic" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const alloc1 = try allocator.create(i32);
        std.debug.warn("alloc1 = {}\n", alloc1);
        const alloc2 = try allocator.create(i32);
        std.debug.warn("alloc2 = {}\n", alloc2);
        allocator.destroy(alloc1);
    }
}
//    var frames: [4]usize = undefined;
//    var stack_trace = builtin.StackTrace{
//        .instruction_addresses = frames[0..],
//        .index = 0,
//    };
//    std.debug.captureStackTrace(null, &stack_trace);
//
//    std.debug.dumpStackTrace(stack_trace);
