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

const wanted_stack_frame_count = 4;

// Bucket: In memory, in order:
// * BucketHeader
// * bucket_used_bits: [N]u8, // 1 bit for every slot; 1 byte for every 8 slots
// * stack_trace_addresses: [N]usize, // 1 for every allocation

const BucketHeader = struct {
    prev: ?*BucketHeader,
    next: ?*BucketHeader,
    page: [*]align(page_size) u8,
    used_bits_index: usize,
    all_used: bool,

    fn usedBits(bucket: *BucketHeader, index: usize) *u8 {
        return @intToPtr(*u8, @ptrToInt(bucket) + @sizeOf(BucketHeader) + index);
    }
};

fn bucketSize(size_class: usize) usize {
    const stack_frames_start = std.mem.alignForward(
        @sizeOf(BucketHeader) + usedBitsCount(size_class),
        @alignOf(usize),
    );
    return stack_frames_start + wanted_stack_frame_count * @sizeOf(usize);
}

fn usedBitsCount(size_class: usize) usize {
    const slot_count = @divExact(page_size, size_class);
    return @divExact(slot_count, 8);
}

const GeneralPurposeDebugAllocator = struct {
    allocator: Allocator,
    buckets: [small_bucket_count]?*BucketHeader,

    const small_bucket_count = 8;

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
            .buckets = [1]?*BucketHeader{null} ** small_bucket_count,
        };
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
        for (self.buckets) |optional_bucket, bucket_i| {
            const bucket = optional_bucket orelse continue;
            const rounded_n = usize(1) << @intCast(u6, bucket_i);
            const used_bits_count = usedBitsCount(rounded_n);
            var used_bits_byte: usize = 0;
            while (used_bits_byte < used_bits_count) : (used_bits_byte += 1) {
                const used_byte = bucket.usedBits(used_bits_byte).*;
                if (used_byte != 0) {
                    var bit_index: u3 = 0;
                    while (true) : (bit_index += 1) {
                        const is_used = @truncate(u1, used_byte >> bit_index) != 0;
                        if (is_used) {
                            std.debug.warn("\nMemory leak detected:\n");
                            // TODO stack trace
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
        const bucket = self.buckets[bucket_index] orelse blk: {
            const perms = posix.PROT_READ | posix.PROT_WRITE;
            const flags = posix.MAP_PRIVATE | posix.MAP_ANONYMOUS;
            const addr = posix.mmap(null, page_size, perms, flags, -1, 0);
            if (addr == posix.MAP_FAILED) return error.OutOfMemory;
            errdefer assert(posix.getErrno(posix.munmap(addr, page_size)) == 0);

            const bucket_size = bucketSize(rounded_n);
            const aligned_bucket_size = std.mem.alignForward(bucket_size, page_size);
            const bucket_addr = posix.mmap(null, page_size, perms, flags, -1, 0);
            if (bucket_addr == posix.MAP_FAILED) return error.OutOfMemory;

            const ptr = @intToPtr(*BucketHeader, bucket_addr);
            ptr.* = BucketHeader{
                .prev = null,
                .next = null,
                .page = @intToPtr([*]align(page_size) u8, addr),
                .used_bits_index = 0,
                .all_used = false,
            };
            self.buckets[bucket_index] = ptr;
            break :blk ptr;
        };
        if (bucket.all_used) {
            // TODO: find available bucket, or allocate a new one
            return error.OutOfMemory;
        }
        const start_index = bucket.used_bits_index;
        var used_bits_byte = bucket.usedBits(bucket.used_bits_index);
        while (used_bits_byte.* == 0xff) {
            bucket.used_bits_index = (bucket.used_bits_index + 1) %
                usedBitsCount(rounded_n);
            if (bucket.used_bits_index == start_index) {
                bucket.all_used = true;
                // TODO: find available bucket, or allocate a new one
                return error.OutOfMemory;
            }
            used_bits_byte = bucket.usedBits(bucket.used_bits_index);
        }
        var used_bit_index: u3 = 0;
        while (@truncate(u1, used_bits_byte.* >> used_bit_index) == 1) {
            used_bit_index += 1;
        }

        used_bits_byte.* |= (u8(1) << used_bit_index);

        const slot_index = bucket.used_bits_index * 8 + used_bit_index;
        const result = (bucket.page + slot_index * rounded_n)[0..n];
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
        const bucket = self.buckets[bucket_index].?;
        // right now alloc will not create more buckets so we assume that
        const byte_offset = @ptrToInt(bytes.ptr) - @ptrToInt(bucket.page);
        const slot_index = byte_offset / rounded_n;
        const used_byte_index = slot_index / 8;
        const used_bit_index = @intCast(u3, slot_index % 8);
        const used_byte = bucket.usedBits(used_byte_index);
        const is_used = @truncate(u1, used_byte.* >> used_bit_index) != 0;
        assert(is_used);
        used_byte.* &= ~(u8(1) << used_bit_index);
        // TODO: if we freed the last slot, unmap the page
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