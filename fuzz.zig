const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{
    .stack_trace_frames = 4,
    .backing_allocator = false,
    .memory_protection = true,
};

test "fuzz testing" {
    const gpda = try GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const seed = 0x1234;
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = &prng.random;

    while (true) {
        const is_small = rand.boolean();
        if (is_small) {
            const size = rand.uintLessThanBiased(usize, std.os.page_size);
            const slice = allocator.alloc(u8, size) catch unreachable;
            allocator.free(slice);
        } else {
            const size = rand.uintLessThanBiased(usize, std.os.page_size + 20 * 1024 * 1024);
            const slice = allocator.alloc(u8, size) catch unreachable;
            allocator.free(slice);
        }
    }
}
