const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{
    .stack_trace_frames = 4,
    .backing_allocator = false,
    .memory_protection = true,
};

test "fuzz testing" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const seed = 0x1234;
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = &prng.random;

    var allocated_n: usize = 0;
    var freed_n: usize = 0;

    const Free = struct {
        slice: []u8,
        it_index: usize,
    };

    var free_queue = std.ArrayList(Free).init(allocator);
    var it_index: usize = 0;

    while (true) : (it_index += 1) {
        const is_small = rand.boolean();
        const size = if (is_small)
            rand.uintLessThanBiased(usize, std.os.page_size)
        else 
            std.os.page_size + rand.uintLessThanBiased(usize, 10 * 1024 * 1024);

        const iterations_until_free = rand.uintLessThanBiased(usize, 100);
        const slice = allocator.alloc(u8, size) catch unreachable;
        allocated_n += size;
        free_queue.append(Free{
            .slice = slice,
            .it_index = it_index + iterations_until_free,
        }) catch unreachable;

        var free_i: usize = 0;
        while (free_i < free_queue.len) {
            const item = &free_queue.toSlice()[free_i];
            if (item.it_index <= it_index) {
                // free time
                allocator.free(item.slice);
                freed_n += item.slice.len;
                _ = free_queue.swapRemove(free_i);
                continue;
            }
            free_i += 1;
        }
        std.debug.warn("index={} allocated: {Bi2} freed: {Bi2}\n",
            it_index, allocated_n, freed_n);
    }
}
