const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{
    .stack_trace_frames = 4,
    .backing_allocator = false,
    .memory_protection = true,
};

test "invalid free" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    std.debug.warn("\n");

    const alloc1 = try allocator.create(i32);
    std.debug.warn("alloc1 = {}\n", alloc1);

    allocator.destroy(@intToPtr(*i32, 0x12345));
}
