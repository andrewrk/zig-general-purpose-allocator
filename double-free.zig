const std = @import("std");
const GeneralPurposeDebugAllocator = @import("gpda.zig").GeneralPurposeDebugAllocator;

test "double free" {
    const gpda = try GeneralPurposeDebugAllocator.create();
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

