const std = @import("std");
const os = std.os;
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const page_size = std.mem.page_size;

/// Integer type for pointing to slots in a small allocation
const SlotIndex = @IntType(false, std.math.log2(page_size) + 1);

pub const Config = struct {
    /// Number of stack frames to capture.
    stack_trace_frames: usize = 4,

    /// Whether the allocator is configured to accept a backing
    /// allocator used for the underlying memory.
    /// false means it will make syscalls directly, and
    /// the create() function takes no arguments.
    /// If this is set to true, create() takes a *Allocator parameter.
    backing_allocator: bool = false,

    /// Whether to use mprotect to take away write permission
    /// from allocator internal state to prevent allocator state
    /// corruption. Enabling this catches bugs but is slower.
    memory_protection: bool = true,
};

pub fn GeneralPurposeDebugAllocator(comptime config: Config) type {
    return struct {
        allocator: Allocator,
        backing_allocator: BackingAllocator,
        buckets: [small_bucket_count]?*BucketHeader,
        simple_allocator: SimpleAllocatorType,
        large_allocations: LargeAllocTable,

        total_requested_bytes: usize,
        requested_memory_limit: usize,

        comptime {
            if (config.backing_allocator and config.memory_protection) {
                @compileError("Memory protection is unavailable when using a backing allocator");
            }
        }

        const Self = @This();

        const BackingAllocator = if (config.backing_allocator) *Allocator else void;
        const SimpleAllocatorType = if (config.backing_allocator) void else SimpleAllocator;

        const stack_n = config.stack_trace_frames;
        const one_trace_size = @sizeOf(usize) * stack_n;
        const traces_per_slot = 2;

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

        pub fn createWithAllocator(backing_allocator: BackingAllocator) !*Self {
            const self = blk: {
                if (config.backing_allocator) {
                    break :blk try backing_allocator.create(Self);
                } else {
                    const self_bytes = try sysAlloc(undefined, @sizeOf(Self));
                    break :blk @ptrCast(*Self, self_bytes.ptr);
                }
            };
            self.* = Self{
                .allocator = Allocator{
                    .reallocFn = realloc,
                    .shrinkFn = shrink,
                },
                .backing_allocator = backing_allocator,
                .buckets = [1]?*BucketHeader{null} ** small_bucket_count,
                .simple_allocator = if (config.backing_allocator) {} else SimpleAllocator.init(),
                .large_allocations = LargeAllocTable.init(if (config.backing_allocator)
                    backing_allocator
                else
                    &self.simple_allocator.allocator),

                .total_requested_bytes = 0,
                .requested_memory_limit = std.math.maxInt(usize),
            };
            try self.mprotectInit(os.PROT_READ);
            return self;
        }

        pub fn create() !*Self {
            if (config.backing_allocator) {
                @compileError("GeneralPurposeDebugAllocator has backing_allocator enabled therefore client must call createWithAllocator()");
            }
            return createWithAllocator({});
        }

        // Bucket: In memory, in order:
        // * BucketHeader
        // * bucket_used_bits: [N]u8, // 1 bit for every slot; 1 byte for every 8 slots
        // * stack_trace_addresses: [N]usize, // traces_per_slot for every allocation

        const BucketHeader = struct {
            prev: *BucketHeader,
            next: *BucketHeader,
            page: [*]align(page_size) u8,
            alloc_cursor: SlotIndex,
            used_count: SlotIndex,

            fn usedBits(bucket: *BucketHeader, index: usize) *u8 {
                return @intToPtr(*u8, @ptrToInt(bucket) + @sizeOf(BucketHeader) + index);
            }

            fn stackTracePtr(
                bucket: *BucketHeader,
                size_class: usize,
                slot_index: SlotIndex,
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
                slot_index: SlotIndex,
                trace_kind: TraceKind,
            ) void {
                // Initialize them to 0. When determining the count we must look
                // for non zero addresses.
                const stack_addresses = bucket.stackTracePtr(size_class, slot_index, trace_kind);
                collectStackTrace(return_address, stack_addresses);
            }
        };

        fn bucketStackTrace(
            bucket: *BucketHeader,
            size_class: usize,
            slot_index: SlotIndex,
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
            if (slot_count < 8) return 1;
            return @divExact(slot_count, 8);
        }

        fn mprotectInit(self: *Self, protection: u32) Error!void {
            if (!config.memory_protection) return;
            const slice = @intToPtr([*]align(page_size) u8, @ptrToInt(self))[0..page_size];
            os.mprotect(slice, protection) catch |e| switch (e) {
                error.AccessDenied => unreachable,
                error.OutOfMemory => return error.OutOfMemory,
                error.Unexpected => return error.OutOfMemory,
            };
        }

        fn mprotect(self: *Self, protection: u32) void {
            if (!config.memory_protection) return;
            const slice = @intToPtr([*]align(page_size) u8, @ptrToInt(self))[0..page_size];
            os.mprotect(slice, protection) catch unreachable;
        }

        fn detectLeaksInBucket(
            bucket: *BucketHeader,
            size_class: usize,
            used_bits_count: usize,
        ) void {
            var used_bits_byte: usize = 0;
            while (used_bits_byte < used_bits_count) : (used_bits_byte += 1) {
                const used_byte = bucket.usedBits(used_bits_byte).*;
                if (used_byte != 0) {
                    var bit_index: u3 = 0;
                    while (true) : (bit_index += 1) {
                        const is_used = @truncate(u1, used_byte >> bit_index) != 0;
                        if (is_used) {
                            std.debug.warn("\nMemory leak detected:\n");
                            const slot_index = @intCast(SlotIndex, used_bits_byte * 8 + bit_index);
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

        pub fn destroy(self: *Self) void {
            for (self.buckets) |optional_bucket, bucket_i| {
                const first_bucket = optional_bucket orelse continue;
                const size_class = usize(1) << @intCast(u6, bucket_i);
                const used_bits_count = usedBitsCount(size_class);
                var bucket = first_bucket;
                while (true) {
                    detectLeaksInBucket(bucket, size_class, used_bits_count);
                    bucket = bucket.next;
                    if (bucket == first_bucket)
                        break;
                }
            }
            var large_it = self.large_allocations.iterator();
            while (large_it.next()) |large_alloc| {
                std.debug.warn("\nMemory leak detected:\n");
                large_alloc.value.dumpStackTrace();
            }
            if (!config.backing_allocator)
                self.simple_allocator.deinit(); // Free large_allocations memory.
            self.sysFree(@ptrCast([*]u8, self)[0..@sizeOf(Self)]);
        }

        fn directAlloc(
            self: *Self,
            n: usize,
            alignment: u29,
            first_trace_addr: usize,
        ) Error![]u8 {
            const alloc_size = if (alignment <= page_size) n else n + alignment;
            const slice = try sysAlloc(self, alloc_size);
            errdefer self.sysFree(slice);

            if (alloc_size == n) {
                try self.trackLargeAlloc(slice, first_trace_addr);
                return slice;
            }

            const addr = @ptrToInt(slice.ptr);
            const aligned_addr = std.mem.alignForward(addr, alignment);

            // Unmap the extra bytes that were only requested in order to guarantee
            // that the range of memory we were provided had a proper alignment in
            // it somewhere. The extra bytes could be at the beginning, or end, or both.
            const unused_start = slice[0 .. aligned_addr - addr];
            if (unused_start.len != 0) {
                self.sysFree(unused_start);
            }
            const aligned_end_addr = std.mem.alignForward(aligned_addr + n, page_size);
            const unused_end_len = @ptrToInt(slice.ptr + slice.len) - aligned_end_addr;
            const unused_end = @intToPtr([*]u8, aligned_end_addr)[0..unused_end_len];
            if (unused_end.len != 0) {
                self.sysFree(unused_end);
            }

            const result = @intToPtr([*]u8, aligned_addr)[0..n];
            try self.trackLargeAlloc(result, first_trace_addr);
            return result;
        }

        fn mprotectLargeAllocs(self: *Self, flags: u32) void {
            if (!config.memory_protection) return;
            if (config.backing_allocator) return;
            self.simple_allocator.mprotect(flags);
        }

        fn trackLargeAlloc(
            self: *Self,
            bytes: []u8,
            first_trace_addr: usize,
        ) !void {
            self.mprotectLargeAllocs(os.PROT_WRITE | os.PROT_READ);
            defer self.mprotectLargeAllocs(os.PROT_READ);

            const gop = try self.large_allocations.getOrPut(@ptrToInt(bytes.ptr));
            if (gop.found_existing) {
                @panic("OS provided unexpected memory address");
            }
            gop.kv.value.bytes = bytes;
            collectStackTrace(first_trace_addr, &gop.kv.value.stack_addresses);
        }

        fn collectStackTrace(first_trace_addr: usize, addresses: *[stack_n]usize) void {
            std.mem.set(usize, addresses, 0);
            var stack_trace = builtin.StackTrace{
                .instruction_addresses = addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(first_trace_addr, &stack_trace);
        }

        fn allocSlot(
            self: *Self,
            size_class: usize,
            trace_addr: usize,
        ) Error![*]u8 {
            const bucket_index = std.math.log2(size_class);
            const first_bucket = self.buckets[bucket_index] orelse try self.createBucket(
                size_class,
                bucket_index,
            );
            var bucket = first_bucket;
            const slot_count = @divExact(page_size, size_class);
            while (bucket.alloc_cursor == slot_count) {
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

            const slot_index = bucket.alloc_cursor;
            bucket.alloc_cursor += 1;

            var used_bits_byte = bucket.usedBits(slot_index / 8);
            const used_bit_index: u3 = @intCast(u3, slot_index % 8); // TODO cast should be unnecessary
            used_bits_byte.* |= (u8(1) << used_bit_index);
            bucket.used_count += 1;
            bucket.captureStackTrace(trace_addr, size_class, slot_index, .Alloc);
            return bucket.page + slot_index * size_class;
        }

        fn searchBucket(
            self: *Self,
            bucket_index: usize,
            addr: usize,
        ) ?*BucketHeader {
            const first_bucket = self.buckets[bucket_index] orelse return null;
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
            self: *Self,
            bucket: *BucketHeader,
            bucket_index: usize,
            size_class: usize,
            slot_index: SlotIndex,
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
                self.sysFree(bucket.page[0..page_size]);
                const bucket_size = bucketSize(size_class);
                const aligned_bucket_size = std.mem.alignForward(bucket_size, page_size);
                self.sysFree(@ptrCast([*]u8, bucket)[0..aligned_bucket_size]);
            }
        }

        const ResizeBehavior = enum {
            shrink,
            realloc,
        };

        fn directRealloc(
            self: *Self,
            old_mem: []u8,
            new_size: usize,
            return_addr: usize,
            behavior: ResizeBehavior,
        ) Error![]u8 {
            self.mprotectLargeAllocs(os.PROT_WRITE | os.PROT_READ);
            defer self.mprotectLargeAllocs(os.PROT_READ);

            const old_kv = self.large_allocations.get(@ptrToInt(old_mem.ptr)).?;
            const result = old_mem.ptr[0..new_size];
            // TODO test if the old_mem.len is correct
            old_kv.value.bytes = result;
            collectStackTrace(return_addr, &old_kv.value.stack_addresses);
            const old_end_page = std.mem.alignForward(old_mem.len, page_size);
            const new_end_page = std.mem.alignForward(new_size, page_size);
            if (new_end_page < old_end_page) {
                self.sysFree(old_mem.ptr[new_end_page..old_end_page]);
            } else if (behavior == .realloc) {
                return error.OutOfMemory;
            }
            return result;
        }

        /// This function assumes the object is in the large object storage regardless
        /// of the parameters.
        fn resizeLarge(
            self: *Self,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            new_align: u29,
            return_addr: usize,
            behavior: ResizeBehavior,
        ) Error![]u8 {
            if (new_size == 0) {
                self.directFree(old_mem);
                return old_mem[0..0];
            } else if (new_size > old_mem.len or new_align > old_align) {
                self.mprotectLargeAllocs(os.PROT_WRITE | os.PROT_READ);
                defer self.mprotectLargeAllocs(os.PROT_READ);

                const old_kv = self.large_allocations.get(@ptrToInt(old_mem.ptr)).?;
                const end_page = std.mem.alignForward(old_kv.value.bytes.len, page_size);
                if (new_size <= end_page and (new_align <= old_align or
                    isAligned(@ptrToInt(old_mem.ptr), new_align)))
                {
                    const result = old_mem.ptr[0..new_size];
                    // TODO test if the old_mem.len is correct
                    old_kv.value.bytes = result;
                    collectStackTrace(return_addr, &old_kv.value.stack_addresses);
                    return result;
                }
                const new_mem = try self.directAlloc(new_size, new_align, return_addr);
                @memcpy(new_mem.ptr, old_mem.ptr, std.math.min(old_mem.len, new_mem.len));
                self.directFree(old_mem);
                return new_mem;
            } else {
                const new_aligned_size = std.math.max(new_size, new_align);
                if (new_aligned_size > largest_bucket_object_size) {
                    return self.directRealloc(old_mem, new_size, return_addr, behavior);
                } else {
                    const new_size_class = up_to_nearest_power_of_2(usize, new_aligned_size);
                    const ptr = self.allocSlot(new_size_class, return_addr) catch |e| switch (e) {
                        error.OutOfMemory => return self.directRealloc(
                            old_mem,
                            new_size,
                            return_addr,
                            behavior,
                        ),
                    };
                    @memcpy(ptr, old_mem.ptr, new_size);
                    self.directFree(old_mem);
                    return ptr[0..new_size];
                }
            }
        }

        pub fn setRequestedMemoryLimit(self: *Self, limit: usize) void {
            self.mprotect(os.PROT_WRITE | os.PROT_READ);
            defer self.mprotect(os.PROT_READ);

            self.requested_memory_limit = limit;
        }

        fn reallocOrShrink(
            allocator: *Allocator,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            new_align: u29,
            return_addr: usize,
            behavior: ResizeBehavior,
        ) Error![]u8 {
            const self = @fieldParentPtr(Self, "allocator", allocator);
            self.mprotect(os.PROT_WRITE | os.PROT_READ);
            defer self.mprotect(os.PROT_READ);

            const prev_req_bytes = self.total_requested_bytes;
            const new_req_bytes = prev_req_bytes + new_size - old_mem.len;
            if (new_req_bytes > prev_req_bytes and
                new_req_bytes > self.requested_memory_limit)
            {
                return error.OutOfMemory;
            }

            self.total_requested_bytes = new_req_bytes;
            errdefer self.total_requested_bytes = prev_req_bytes;

            if (old_mem.len == 0) {
                assert(behavior == .realloc);
                const new_aligned_size = std.math.max(new_size, new_align);
                if (new_aligned_size > largest_bucket_object_size) {
                    return self.directAlloc(new_size, new_align, return_addr);
                } else {
                    const new_size_class = up_to_nearest_power_of_2(usize, new_aligned_size);
                    const ptr = try self.allocSlot(new_size_class, return_addr);
                    return ptr[0..new_size];
                }
            }

            const aligned_size = std.math.max(old_mem.len, old_align);
            if (aligned_size > largest_bucket_object_size) {
                return self.resizeLarge(old_mem, old_align, new_size, new_align, return_addr, behavior);
            }
            const size_class = up_to_nearest_power_of_2(usize, aligned_size);

            var bucket_index = std.math.log2(size_class);
            const bucket = while (bucket_index < small_bucket_count) : (bucket_index += 1) {
                if (self.searchBucket(bucket_index, @ptrToInt(old_mem.ptr))) |bucket| {
                    break bucket;
                }
            } else {
                return self.resizeLarge(old_mem, old_align, new_size, new_align, return_addr, behavior);
            };
            const byte_offset = @ptrToInt(old_mem.ptr) - @ptrToInt(bucket.page);
            const slot_index = @intCast(SlotIndex, byte_offset / size_class);
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
                    return_addr,
                );
                return old_mem[0..0];
            }
            const new_aligned_size = std.math.max(new_size, new_align);
            const new_size_class = up_to_nearest_power_of_2(usize, new_aligned_size);
            if (size_class == new_size_class) {
                return old_mem.ptr[0..new_size];
            }
            if (new_aligned_size > largest_bucket_object_size) {
                self.mprotectLargeAllocs(os.PROT_WRITE | os.PROT_READ);
                defer self.mprotectLargeAllocs(os.PROT_READ);

                const new_mem = try self.directAlloc(new_size, new_align, return_addr);
                @memcpy(new_mem.ptr, old_mem.ptr, old_mem.len);
                self.freeSlot(
                    bucket,
                    bucket_index,
                    size_class,
                    slot_index,
                    used_byte,
                    used_bit_index,
                    return_addr,
                );
                return new_mem;
            }
            // Migrating to a smaller size class.
            const ptr = self.allocSlot(new_size_class, return_addr) catch |e| switch (e) {
                error.OutOfMemory => switch (behavior) {
                    .realloc => return error.OutOfMemory,
                    .shrink => return old_mem.ptr[0..new_size],
                },
            };
            @memcpy(ptr, old_mem.ptr, new_size);
            self.freeSlot(
                bucket,
                bucket_index,
                size_class,
                slot_index,
                used_byte,
                used_bit_index,
                return_addr,
            );
            return ptr[0..new_size];
        }

        fn directFree(self: *Self, bytes: []u8) void {
            self.mprotectLargeAllocs(os.PROT_WRITE | os.PROT_READ);
            defer self.mprotectLargeAllocs(os.PROT_READ);

            var kv = self.large_allocations.remove(@ptrToInt(bytes.ptr)).?;
            if (bytes.len != kv.value.bytes.len) {
                std.debug.warn(
                    "\nAllocation size {} bytes does not match free size {}. Allocated here:\n",
                    kv.value.bytes.len,
                    bytes.len,
                );
                kv.value.dumpStackTrace();

                @panic("\nFree here:");
            }

            self.sysFree(bytes);
        }

        fn shrink(
            allocator: *Allocator,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            new_align: u29,
        ) []u8 {
            return reallocOrShrink(
                allocator,
                old_mem,
                old_align,
                new_size,
                new_align,
                @returnAddress(),
                .shrink,
            ) catch unreachable;
        }

        fn realloc(
            allocator: *Allocator,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            new_align: u29,
        ) Error![]u8 {
            return reallocOrShrink(
                allocator,
                old_mem,
                old_align,
                new_size,
                new_align,
                @returnAddress(),
                .realloc,
            );
        }

        fn createBucket(
            self: *Self,
            size_class: usize,
            bucket_index: usize,
        ) Error!*BucketHeader {
            const page = try sysAlloc(self, page_size);
            errdefer self.sysFree(page);

            const bucket_size = bucketSize(size_class);
            const aligned_bucket_size = std.mem.alignForward(bucket_size, page_size);
            const bucket_bytes = try sysAlloc(self, aligned_bucket_size);
            const ptr = @ptrCast(*BucketHeader, bucket_bytes.ptr);
            ptr.* = BucketHeader{
                .prev = ptr,
                .next = ptr,
                .page = page.ptr,
                .alloc_cursor = 0,
                .used_count = 0,
            };
            self.buckets[bucket_index] = ptr;
            // Set the used bits to all zeroes
            @memset((*[1]u8)(ptr.usedBits(0)), 0, usedBitsCount(size_class));
            return ptr;
        }

        var next_addr_hint: ?[*]align(page_size) u8 = null;

        fn sysAlloc(self: *Self, len: usize) Error![]align(page_size) u8 {
            if (config.backing_allocator) {
                return self.backing_allocator.alignedAlloc(u8, page_size, len);
            } else {
                const perms = os.PROT_READ | os.PROT_WRITE;
                const flags = os.MAP_PRIVATE | os.MAP_ANONYMOUS;
                const hint = @atomicLoad(@typeOf(next_addr_hint), &next_addr_hint, .SeqCst);
                const result = os.mmap(hint, len, perms, flags, -1, 0) catch return error.OutOfMemory;
                const new_hint = result.ptr + std.mem.alignForward(result.len, page_size);
                _ = @cmpxchgStrong(@typeOf(next_addr_hint), &next_addr_hint, hint, new_hint, .SeqCst, .SeqCst);
                return result;
            }
        }

        fn sysFree(self: *Self, old_mem: []u8) void {
            if (config.backing_allocator) {
                return self.backing_allocator.free(old_mem);
            } else {
                // This call cannot fail because we are giving the full memory back (not splitting a
                // vm page).
                os.munmap(@alignCast(page_size, old_mem));
            }
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
                comptime assert(!config.backing_allocator);
                sysFree(undefined, self.active_allocation);
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
                comptime assert(!config.backing_allocator);
                const self = @fieldParentPtr(SimpleAllocator, "allocator", allocator);
                const result = try sysAlloc(undefined, new_size);
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
                comptime assert(!config.backing_allocator);
                sysFree(undefined, old_mem);
                return old_mem[0..0];
            }

            /// Applies to all of the bytes in the entire allocator.
            pub fn mprotect(self: *SimpleAllocator, protection: u32) void {
                if (!config.memory_protection) return;
                if (self.active_allocation.len == 0) return;
                const aligned_ptr = @alignCast(page_size, self.active_allocation.ptr);
                const aligned_len = std.mem.alignForward(self.active_allocation.len, page_size);
                const slice = aligned_ptr[0..aligned_len];
                os.mprotect(slice, protection) catch unreachable;
            }
        };
    };
}

const TraceKind = enum {
    Alloc,
    Free,
};

fn up_to_nearest_power_of_2(comptime T: type, n: T) T {
    var power: T = 1;
    while (power < n)
        power *= 2;
    return power;
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

const test_config = Config{};

const test_config_nomprotect = Config{ .memory_protection = false };

test "small allocations - free in same order" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
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
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
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
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
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
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
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

test "shrink" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alloc(u8, 20);
    defer allocator.free(slice);

    std.mem.set(u8, slice, 0x11);

    slice = allocator.shrink(slice, 17);

    for (slice) |b| {
        assert(b == 0x11);
    }

    slice = allocator.shrink(slice, 16);

    for (slice) |b| {
        assert(b == 0x11);
    }
}

test "large object - grow" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice1 = try allocator.alloc(u8, page_size * 2 - 20);
    defer allocator.free(slice1);

    var old = slice1;
    slice1 = try allocator.realloc(slice1, page_size * 2 - 10);
    assert(slice1.ptr == old.ptr);

    slice1 = try allocator.realloc(slice1, page_size * 2);
    assert(slice1.ptr == old.ptr);

    slice1 = try allocator.realloc(slice1, page_size * 2 + 1);
}

test "realloc small object to large object" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alloc(u8, 70);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[60] = 0x34;

    // This requires upgrading to a large object
    const large_object_size = page_size * 2 + 50;
    slice = try allocator.realloc(slice, large_object_size);
    assert(slice[0] == 0x12);
    assert(slice[60] == 0x34);
}

test "shrink large object to large object" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alloc(u8, page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[60] = 0x34;

    if (allocator.realloc(slice, page_size * 2 + 1)) |_| {
        @panic("expected failure");
    } else |e| assert(e == error.OutOfMemory);

    slice = allocator.shrink(slice, page_size * 2 + 1);
    assert(slice[0] == 0x12);
    assert(slice[60] == 0x34);

    slice = try allocator.realloc(slice, page_size * 2);
    assert(slice[0] == 0x12);
    assert(slice[60] == 0x34);
}

test "shrink large object to large object with larger alignment" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var debug_buffer: [1000]u8 = undefined;
    const debug_allocator = &std.heap.FixedBufferAllocator.init(&debug_buffer).allocator;

    const alloc_size = page_size * 2 + 50;
    var slice = try allocator.alignedAlloc(u8, 16, alloc_size);
    defer allocator.free(slice);

    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    while (isAligned(@ptrToInt(slice.ptr), page_size * 2)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, 16, alloc_size);
    }
    while (stuff_to_free.popOrNull()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[60] = 0x34;

    slice = try allocator.alignedRealloc(slice, page_size * 2, alloc_size / 2);
    assert(slice[0] == 0x12);
    assert(slice[60] == 0x34);
}

test "realloc large object to small object" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alloc(u8, page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[16] = 0x34;

    slice = try allocator.realloc(slice, 19);
    assert(slice[0] == 0x12);
    assert(slice[16] == 0x34);
}

test "backing allocator" {
    const gpda = try GeneralPurposeDebugAllocator(Config{
        .backing_allocator = true,
        .memory_protection = false,
    }).createWithAllocator(std.debug.global_allocator);
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const ptr = try allocator.create(i32);
    defer allocator.destroy(ptr);
}

test "realloc large object to larger alignment" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var debug_buffer: [1000]u8 = undefined;
    const debug_allocator = &std.heap.FixedBufferAllocator.init(&debug_buffer).allocator;

    var slice = try allocator.alignedAlloc(u8, 16, page_size * 2 + 50);
    defer allocator.free(slice);

    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    while (isAligned(@ptrToInt(slice.ptr), page_size * 2)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, 16, page_size * 2 + 50);
    }
    while (stuff_to_free.popOrNull()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[16] = 0x34;

    slice = try allocator.alignedRealloc(slice, 32, page_size * 2 + 100);
    assert(slice[0] == 0x12);
    assert(slice[16] == 0x34);

    slice = try allocator.alignedRealloc(slice, 32, page_size * 2 + 25);
    assert(slice[0] == 0x12);
    assert(slice[16] == 0x34);

    slice = try allocator.alignedRealloc(slice, page_size * 2, page_size * 2 + 100);
    assert(slice[0] == 0x12);
    assert(slice[16] == 0x34);
}

fn isAligned(addr: usize, alignment: usize) bool {
    // 000010000 // example addr
    // 000001111 // subtract 1
    // 111110000 // binary not
    const aligned_addr = (addr & ~(alignment - 1));
    return aligned_addr == addr;
}

test "isAligned works" {
    assert(isAligned(0, 4));
    assert(isAligned(1, 1));
    assert(isAligned(2, 1));
    assert(isAligned(2, 2));
    assert(!isAligned(2, 4));
    assert(isAligned(3, 1));
    assert(!isAligned(3, 2));
    assert(!isAligned(3, 4));
    assert(isAligned(4, 4));
    assert(isAligned(4, 2));
    assert(isAligned(4, 1));
    assert(!isAligned(4, 8));
    assert(!isAligned(4, 16));
}

test "large object shrinks to small but allocation fails during shrink" {
    var failing_allocator = std.debug.FailingAllocator.init(std.heap.direct_allocator, 3);
    const gpda = try GeneralPurposeDebugAllocator(Config{
        .backing_allocator = true,
        .memory_protection = false,
    }).createWithAllocator(&failing_allocator.allocator);
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var slice = try allocator.alloc(u8, page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[3] = 0x34;

    // Next allocation will fail in the backing allocator of the GeneralPurposeDebugAllocator

    slice = allocator.shrink(slice, 4);
    assert(slice[0] == 0x12);
    assert(slice[3] == 0x34);
}

test "objects of size 1024 and 2048" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const slice = try allocator.alloc(u8, 1025);
    const slice2 = try allocator.alloc(u8, 3000);

    allocator.free(slice);
    allocator.free(slice2);
}

test "setting a memory cap" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    gpda.setRequestedMemoryLimit(1010);

    const small = try allocator.create(i32);
    assert(gpda.total_requested_bytes == 4);

    const big = try allocator.alloc(u8, 1000);
    assert(gpda.total_requested_bytes == 1004);

    std.testing.expectError(error.OutOfMemory, allocator.create(u64));

    allocator.destroy(small);
    assert(gpda.total_requested_bytes == 1000);

    allocator.free(big);
    assert(gpda.total_requested_bytes == 0);

    const exact = try allocator.alloc(u8, 1010);
    assert(gpda.total_requested_bytes == 1010);
    allocator.free(exact);
}
