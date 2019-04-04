const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{
    .stack_trace_frames = 4,
};

test "leaks" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    std.debug.warn("\n");
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const alloc1 = try allocator.create(i32);
        std.debug.warn("alloc1 = {}\n", alloc1);
        defer allocator.destroy(alloc1);

        const alloc2 = try allocator.create(i32);
        std.debug.warn("alloc2 = {}\n", alloc2);
        //defer allocator.destroy(alloc2);
    }
}
