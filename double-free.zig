const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{
    .stack_trace_frames = 4,
    .backing_allocator = false,
    .memory_protection = true,
};

test "double free" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    std.debug.warn("\n");

    const alloc1 = try allocator.create(i32);
    std.debug.warn("alloc1 = {}\n", alloc1);

    const alloc2 = try allocator.create(i32);
    std.debug.warn("alloc2 = {}\n", alloc2);

    allocator.destroy(alloc1);
    allocator.destroy(alloc1);
}
