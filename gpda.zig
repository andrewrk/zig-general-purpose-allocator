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

// Number of stack frames to capture
const stack_n = 4;

const one_trace_size = @sizeOf(usize) * stack_n;
const traces_per_slot = 2;

// Bucket: In memory, in order:
// * BucketHeader
// * bucket_used_bits: [N]u8, // 1 bit for every slot; 1 byte for every 8 slots
// * stack_trace_addresses: [N]usize, // traces_per_slot for every allocation

const BucketHeader = struct {
    prev: *BucketHeader,
    next: *BucketHeader,
    page: [*]align(page_size) u8,
    used_bits_index: usize,
    used_count: usize,

    fn usedBits(bucket: *BucketHeader, index: usize) *u8 {
        return @intToPtr(*u8, @ptrToInt(bucket) + @sizeOf(BucketHeader) + index);
    }

    fn stackTracePtr(
        bucket: *BucketHeader,
        size_class: usize,
        slot_index: usize,
        trace_kind: TraceKind,
    ) *[stack_n]usize {
        const start_ptr = @ptrCast([*]u8, bucket) + bucketStackFramesStart(size_class);
        const addr = start_ptr + one_trace_size * traces_per_slot * slot_index +
            @enumToInt(trace_kind) * usize(one_trace_size);
        return @ptrCast(*[stack_n]usize, addr);
    }

    fn captureStackTrace(
        bucket: *BucketHeader,
        return_address: usize,
        size_class: usize,
        slot_index: usize,
        trace_kind: TraceKind,
    ) void {
        // Initialize them to 0. When determining the count we must look
        // for non zero addresses.
        const stack_addresses = bucket.stackTracePtr(size_class, slot_index, trace_kind);
        std.mem.set(usize, stack_addresses, 0);
        var stack_trace = builtin.StackTrace{
            .instruction_addresses = stack_addresses,
            .index = 0,
        };
        std.debug.captureStackTrace(return_address, &stack_trace);
    }
};

const TraceKind = enum {
    Alloc,
    Free,
};

fn bucketStackTrace(
    bucket: *BucketHeader,
    size_class: usize,
    slot_index: usize,
    trace_kind: TraceKind,
) builtin.StackTrace {
    const stack_addresses = bucket.stackTracePtr(size_class, slot_index, trace_kind);
    var len: usize = 0;
    while (len < stack_n and stack_addresses[len] != 0) {
        len += 1;
    }
    return builtin.StackTrace{
        .instruction_addresses = stack_addresses,
        .index = len,
    };
}

fn bucketStackFramesStart(size_class: usize) usize {
    return std.mem.alignForward(
        @sizeOf(BucketHeader) + usedBitsCount(size_class),
        @alignOf(usize),
    );
}

fn bucketSize(size_class: usize) usize {
    const slot_count = @divExact(page_size, size_class);
    return bucketStackFramesStart(size_class) + one_trace_size * traces_per_slot * slot_count;
}

fn usedBitsCount(size_class: usize) usize {
    const slot_count = @divExact(page_size, size_class);
    return @divExact(slot_count, 8);
}

fn hash_addr(addr: usize) u32 {
    // TODO ignore the least significant bits because addr is guaranteed
    // to be page aligned
    if (@sizeOf(usize) == @sizeOf(u32))
        return addr;
    comptime assert(@sizeOf(usize) == 8);
    return @intCast(u32, addr >> 32) ^ @truncate(u32, addr);
}

fn eql_addr(a: usize, b: usize) bool {
    return a == b;
}

fn sysAlloc(len: usize) error{OutOfMemory}![]align(page_size) u8 {
    const perms = posix.PROT_READ | posix.PROT_WRITE;
    const flags = posix.MAP_PRIVATE | posix.MAP_ANONYMOUS;
    const addr = posix.mmap(null, len, perms, flags, -1, 0);
    if (addr == posix.MAP_FAILED) return error.OutOfMemory;
    return @intToPtr([*]align(page_size) u8, addr)[0..len];
}

fn sysFree(old_mem: []u8) void {
    assert(posix.getErrno(posix.munmap(@ptrToInt(old_mem.ptr), old_mem.len)) == 0);
}

const SimpleAllocator = struct {
    allocator: Allocator,
    active_allocation: []u8,

    fn init() SimpleAllocator {
        return SimpleAllocator{
            .allocator = Allocator{
                .reallocFn = realloc,
                .shrinkFn = shrink,
            },
            .active_allocation = (([*]u8)(undefined))[0..0],
        };
    }

    fn deinit(self: SimpleAllocator) void {
        if (self.active_allocation.len == 0) return;
        sysFree(self.active_allocation);
    }

    fn realloc(
        allocator: *Allocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        new_align: u29,
    ) error{OutOfMemory}![]u8 {
        assert(old_mem.len == 0);
        assert(new_align < page_size);
        const self = @fieldParentPtr(SimpleAllocator, "allocator", allocator);
        const result = try sysAlloc(new_size);
        self.active_allocation = result;
        return result;
    }

    fn shrink(
        allocator: *Allocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        new_align: u29,
    ) []u8 {
        assert(new_size == 0);
        sysFree(old_mem);
        return old_mem[0..0];
    }

    /// Applies to all of the bytes in the entire allocator.
    pub fn mprotect(self: *SimpleAllocator, protection: u32) void {
        if (self.active_allocation.len == 0) return;
        os.posixMProtect(
            @ptrToInt(self.active_allocation.ptr),
            std.mem.alignForward(self.active_allocation.len, page_size),
            protection,
        ) catch unreachable;
    }
};

pub const GeneralPurposeDebugAllocator = struct {
    allocator: Allocator,
    buckets: [small_bucket_count]?*BucketHeader,
    simple_allocator: SimpleAllocator,
    large_allocations: LargeAllocTable,

    pub const Error = std.mem.Allocator.Error;

    const small_bucket_count = std.math.log2(page_size);
    const largest_bucket_object_size = 1 << (small_bucket_count - 1);

    const LargeAlloc = struct {
        bytes: []u8,
        stack_addresses: [stack_n]usize,

        fn dumpStackTrace(self: *LargeAlloc) void {
            var len: usize = 0;
            while (len < stack_n and self.stack_addresses[len] != 0) {
                len += 1;
            }
            const stack_trace = builtin.StackTrace{
                .instruction_addresses = &self.stack_addresses,
                .index = len,
            };
            std.debug.dumpStackTrace(stack_trace);
        }
    };
    const LargeAllocTable = std.HashMap(usize, LargeAlloc, hash_addr, eql_addr);

    pub fn create() !*GeneralPurposeDebugAllocator {
        const self_bytes = try sysAlloc(@sizeOf(GeneralPurposeDebugAllocator));
        const self = @ptrCast(*GeneralPurposeDebugAllocator, self_bytes.ptr);
        self.* = GeneralPurposeDebugAllocator{
            .allocator = Allocator{
                .reallocFn = realloc,
                .shrinkFn = shrink,
            },
            .buckets = [1]?*BucketHeader{null} ** small_bucket_count,
            .simple_allocator = SimpleAllocator.init(),
            .large_allocations = LargeAllocTable.init(&self.simple_allocator.allocator),
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
            const size_class = usize(1) << @intCast(u6, bucket_i);
            const used_bits_count = usedBitsCount(size_class);
            var used_bits_byte: usize = 0;
            while (used_bits_byte < used_bits_count) : (used_bits_byte += 1) {
                const used_byte = bucket.usedBits(used_bits_byte).*;
                if (used_byte != 0) {
                    var bit_index: u3 = 0;
                    while (true) : (bit_index += 1) {
                        const is_used = @truncate(u1, used_byte >> bit_index) != 0;
                        if (is_used) {
                            std.debug.warn("\nMemory leak detected:\n");
                            const slot_index = used_bits_byte * 8 + bit_index;
                            const stack_trace = bucketStackTrace(
                                bucket,
                                size_class,
                                slot_index,
                                .Alloc,
                            );
                            std.debug.dumpStackTrace(stack_trace);
                        }
                        if (bit_index == std.math.maxInt(u3))
                            break;
                    }
                }
            }
        }
        var large_it = self.large_allocations.iterator();
        while (large_it.next()) |large_alloc| {
            std.debug.warn("\nMemory leak detected:\n");
            large_alloc.value.dumpStackTrace();
        }
        self.simple_allocator.deinit(); // Free large_allocations memory.
        sysFree(@ptrCast([*]u8, self)[0..@sizeOf(GeneralPurposeDebugAllocator)]);
    }

    fn directAlloc(
        self: *GeneralPurposeDebugAllocator,
        n: usize,
        alignment: u29,
        first_trace_addr: usize,
    ) Error![]u8 {
        const p = posix;
        const alloc_size = if (alignment <= os.page_size) n else n + alignment;
        const slice = try sysAlloc(alloc_size);
        errdefer sysFree(slice);

        if (alloc_size == n) {
            try self.trackLargeAlloc(slice, first_trace_addr);
            return slice;
        }

        const addr = @ptrToInt(slice.ptr);
        const aligned_addr = std.mem.alignForward(addr, alignment);

        // We can unmap the unused portions of our mmap, but we must only
        // pass munmap bytes that exist outside our allocated pages or it
        // will happily eat us too.

        // Since alignment > page_size, we are by definition on a page boundary.
        const unused_len = aligned_addr - 1 - addr;

        sysFree(slice[0..unused_len]);

        // It is impossible that there is an unoccupied page at the top of our
        // mmap.
        const result = @intToPtr([*]u8, aligned_addr)[0..n];
        try self.trackLargeAlloc(result, first_trace_addr);
        return result;
    }

    fn trackLargeAlloc(
        self: *GeneralPurposeDebugAllocator,
        bytes: []u8,
        first_trace_addr: usize,
    ) !void {
        self.simple_allocator.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.simple_allocator.mprotect(posix.PROT_READ);

        const gop = try self.large_allocations.getOrPut(@ptrToInt(bytes.ptr));
        if (gop.found_existing) {
            @panic("OS provided unexpected memory address");
        }
        gop.kv.value.bytes = bytes;
        std.mem.set(usize, &gop.kv.value.stack_addresses, 0);
        var stack_trace = builtin.StackTrace{
            .instruction_addresses = &gop.kv.value.stack_addresses,
            .index = 0,
        };
        std.debug.captureStackTrace(first_trace_addr, &stack_trace);
    }

    fn allocSlot(
        self: *GeneralPurposeDebugAllocator,
        size_class: usize,
        trace_addr: usize,
    ) Error![*]u8 {
        const bucket_index = std.math.log2(size_class);
        const first_bucket = self.buckets[bucket_index] orelse try self.createBucket(
            size_class,
            bucket_index,
        );
        var bucket = first_bucket;
        while (bucket.used_count == usize(page_size) >> @intCast(u6, bucket_index)) {
            const prev_bucket = bucket;
            bucket = prev_bucket.next;
            if (bucket == first_bucket) {
                // make a new one
                bucket = try self.createBucket(size_class, bucket_index);
                bucket.prev = prev_bucket;
                bucket.next = prev_bucket.next;
                prev_bucket.next = bucket;
                bucket.next.prev = bucket;
            }
        }
        // change the allocator's current bucket to be this one
        self.buckets[bucket_index] = bucket;

        bucket.used_count += 1;
        var used_bits_byte = bucket.usedBits(bucket.used_bits_index);
        while (used_bits_byte.* == 0xff) {
            bucket.used_bits_index = (bucket.used_bits_index + 1) %
                usedBitsCount(size_class);
            used_bits_byte = bucket.usedBits(bucket.used_bits_index);
        }
        var used_bit_index: u3 = 0;
        while (@truncate(u1, used_bits_byte.* >> used_bit_index) == 1) {
            used_bit_index += 1;
        }

        used_bits_byte.* |= (u8(1) << used_bit_index);

        const slot_index = bucket.used_bits_index * 8 + used_bit_index;
        bucket.captureStackTrace(trace_addr, size_class, slot_index, .Alloc);

        return bucket.page + slot_index * size_class;
    }

    fn reallocLarge(
        self: *GeneralPurposeDebugAllocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        alignment: u29,
    ) Error![]u8 {
        @panic("TODO handle realloc of large object");
    }

    fn searchBucket(
        self: *GeneralPurposeDebugAllocator,
        bucket_index: usize,
        addr: usize,
    ) ?*BucketHeader {
        const first_bucket = self.buckets[bucket_index].?;
        var bucket = first_bucket;
        while (true) {
            const in_bucket_range = (addr >= @ptrToInt(bucket.page) and
                addr < @ptrToInt(bucket.page) + page_size);
            if (in_bucket_range) return bucket;
            bucket = bucket.prev;
            if (bucket == first_bucket) {
                return null;
            }
            self.buckets[bucket_index] = bucket;
        }
    }

    fn freeSlot(
        self: *GeneralPurposeDebugAllocator,
        bucket: *BucketHeader,
        bucket_index: usize,
        size_class: usize,
        slot_index: usize,
        used_byte: *u8,
        used_bit_index: u3,
        trace_addr: usize,
    ) void {
        // Capture stack trace to be the "first free", in case a double free happens.
        bucket.captureStackTrace(@returnAddress(), size_class, slot_index, .Free);

        used_byte.* &= ~(u8(1) << used_bit_index);
        bucket.used_count -= 1;
        if (bucket.used_count == 0) {
            if (bucket.next == bucket) {
                // it's the only bucket and therefore the current one
                self.buckets[bucket_index] = null;
            } else {
                bucket.next.prev = bucket.prev;
                bucket.prev.next = bucket.next;
                self.buckets[bucket_index] = bucket.prev;
            }
            sysFree(bucket.page[0..page_size]);
            const bucket_size = bucketSize(size_class);
            const aligned_bucket_size = std.mem.alignForward(bucket_size, page_size);
            sysFree(@ptrCast([*]u8, bucket)[0..aligned_bucket_size]);
        }
    }

    fn realloc(
        allocator: *Allocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        new_align: u29,
    ) Error![]u8 {
        const self = @fieldParentPtr(GeneralPurposeDebugAllocator, "allocator", allocator);
        self.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.mprotect(posix.PROT_READ);

        if (old_mem.len == 0) {
            const new_aligned_size = std.math.max(new_size, new_align);
            if (new_aligned_size > largest_bucket_object_size) {
                return self.directAlloc(new_size, new_align, @returnAddress());
            } else {
                const new_size_class = up_to_nearest_power_of_2(usize, new_aligned_size);
                const ptr = try self.allocSlot(new_size_class, @returnAddress());
                return ptr[0..new_size];
            }
        }

        const aligned_size = std.math.max(old_mem.len, old_align);
        if (aligned_size > largest_bucket_object_size) {
            return self.reallocLarge(old_mem, old_align, new_size, new_align);
        }
        const size_class = up_to_nearest_power_of_2(usize, aligned_size);

        var bucket_index = std.math.log2(size_class);
        const bucket = while (bucket_index < small_bucket_count) : (bucket_index += 1) {
            if (self.searchBucket(bucket_index, @ptrToInt(old_mem.ptr))) |bucket| {
                break bucket;
            }
        } else {
            return self.reallocLarge(old_mem, old_align, new_size, new_align);
        };
        const byte_offset = @ptrToInt(old_mem.ptr) - @ptrToInt(bucket.page);
        const slot_index = byte_offset / size_class;
        const used_byte_index = slot_index / 8;
        const used_bit_index = @intCast(u3, slot_index % 8);
        const used_byte = bucket.usedBits(used_byte_index);
        const is_used = @truncate(u1, used_byte.* >> used_bit_index) != 0;
        if (!is_used) {
            // print allocation stack trace
            std.debug.warn("\nDouble free detected, allocated here:\n");
            const alloc_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .Alloc);
            std.debug.dumpStackTrace(alloc_stack_trace);
            std.debug.warn("\nFirst free here:\n");
            const free_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .Free);
            std.debug.dumpStackTrace(free_stack_trace);
            @panic("\nSecond free here:");
        }
        if (new_size == 0) {
            self.freeSlot(
                bucket,
                bucket_index,
                size_class,
                slot_index,
                used_byte,
                used_bit_index,
                @returnAddress(),
            );
            return old_mem[0..0];
        }
        const new_aligned_size = std.math.max(new_size, new_align);
        const new_size_class = up_to_nearest_power_of_2(usize, new_aligned_size);
        if (size_class == new_size_class) {
            return old_mem.ptr[0..new_size];
        }
        if (new_aligned_size > largest_bucket_object_size) {
            @panic("realloc moving from buckets to non buckets");
        }
        const ptr = try self.allocSlot(new_size_class, @returnAddress());
        @memcpy(ptr, old_mem.ptr, old_mem.len);
        self.freeSlot(
            bucket,
            bucket_index,
            size_class,
            slot_index,
            used_byte,
            used_bit_index,
            @returnAddress(),
        );
        return ptr[0..new_size];
    }

    fn directFree(self: *GeneralPurposeDebugAllocator, bytes: []u8) void {
        self.simple_allocator.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.simple_allocator.mprotect(posix.PROT_READ);

        const kv = self.large_allocations.get(@ptrToInt(bytes.ptr)).?;
        if (bytes.len != kv.value.bytes.len) {
            std.debug.warn(
                "\nAllocation size {} bytes does not match free size {}. Allocated here:\n",
                kv.value.bytes.len,
                bytes.len,
            );
            kv.value.dumpStackTrace();

            @panic("\nFree here:");
        }

        // TODO we should be able to replace the above call to get() with remove()
        // is it a hash table bug?
        assert(self.large_allocations.remove(@ptrToInt(bytes.ptr)) != null);
        sysFree(bytes);
    }

    fn shrink(
        allocator: *Allocator,
        old_mem: []u8,
        old_align: u29,
        new_size: usize,
        new_align: u29,
    ) []u8 {
        const self = @fieldParentPtr(GeneralPurposeDebugAllocator, "allocator", allocator);
        self.mprotect(posix.PROT_WRITE | posix.PROT_READ);
        defer self.mprotect(posix.PROT_READ);
        if (new_size > 0) {
            @panic("TODO handle shrink to nonzero");
        }
        const aligned_size = std.math.max(old_mem.len, old_align);
        if (aligned_size > largest_bucket_object_size) {
            self.directFree(old_mem);
            return old_mem[0..0];
        }
        const size_class = up_to_nearest_power_of_2(usize, aligned_size);
        const bucket_index = std.math.log2(size_class);
        const bucket = self.searchBucket(bucket_index, @ptrToInt(old_mem.ptr)) orelse {
            @panic("Invalid free");
        };
        const byte_offset = @ptrToInt(old_mem.ptr) - @ptrToInt(bucket.page);
        const slot_index = byte_offset / size_class;
        const used_byte_index = slot_index / 8;
        const used_bit_index = @intCast(u3, slot_index % 8);
        const used_byte = bucket.usedBits(used_byte_index);
        const is_used = @truncate(u1, used_byte.* >> used_bit_index) != 0;
        if (!is_used) {
            // print allocation stack trace
            std.debug.warn("\nDouble free detected, allocated here:\n");
            const alloc_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .Alloc);
            std.debug.dumpStackTrace(alloc_stack_trace);
            std.debug.warn("\nFirst free here:\n");
            const free_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .Free);
            std.debug.dumpStackTrace(free_stack_trace);
            @panic("\nSecond free here:");
        }
        self.freeSlot(
            bucket,
            bucket_index,
            size_class,
            slot_index,
            used_byte,
            used_bit_index,
            @returnAddress(),
        );
        return old_mem[0..0];
    }

    fn createBucket(
        self: *GeneralPurposeDebugAllocator,
        size_class: usize,
        bucket_index: usize,
    ) Error!*BucketHeader {
        const page = try sysAlloc(page_size);
        errdefer sysFree(page);

        const bucket_size = bucketSize(size_class);
        const aligned_bucket_size = std.mem.alignForward(bucket_size, page_size);
        const bucket_bytes = try sysAlloc(aligned_bucket_size);
        const ptr = @ptrCast(*BucketHeader, bucket_bytes.ptr);
        ptr.* = BucketHeader{
            .prev = ptr,
            .next = ptr,
            .page = page.ptr,
            .used_bits_index = 0,
            .used_count = 0,
        };
        self.buckets[bucket_index] = ptr;
        return ptr;
    }
};

test "small allocations - free in same order" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var list = std.ArrayList(*u64).init(std.debug.global_allocator);

    var i: usize = 0;
    while (i < 513) : (i += 1) {
        const ptr = try allocator.create(u64);
        try list.append(ptr);
    }

    for (list.toSlice()) |ptr| {
        allocator.destroy(ptr);
    }
}

test "small allocations - free in reverse order" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var list = std.ArrayList(*u64).init(std.debug.global_allocator);

    var i: usize = 0;
    while (i < 513) : (i += 1) {
        const ptr = try allocator.create(u64);
        try list.append(ptr);
    }

    while (list.popOrNull()) |ptr| {
        allocator.destroy(ptr);
    }
}

test "large allocations" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const ptr1 = try allocator.alloc(u64, 42768);
    const ptr2 = try allocator.alloc(u64, 52768);
    allocator.free(ptr1);
    const ptr3 = try allocator.alloc(u64, 62768);
    allocator.free(ptr3);
    allocator.free(ptr2);
}

test "realloc" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alignedAlloc(u8, @alignOf(u32), 1);
    defer allocator.free(slice);
    slice[0] = 0x12;

    // This reallocation should keep its pointer address.
    const old_slice = slice;
    slice = try allocator.realloc(slice, 2);
    assert(old_slice.ptr == slice.ptr);
    assert(slice[0] == 0x12);
    slice[1] = 0x34;

    // This requires upgrading to a larger size class
    slice = try allocator.realloc(slice, 17);
    assert(slice[0] == 0x12);
    assert(slice[1] == 0x34);
}
