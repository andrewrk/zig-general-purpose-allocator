const std = @import("std");
const GeneralPurposeDebugAllocator = @import("gpda.zig").GeneralPurposeDebugAllocator;

test "invalid free" {
    const gpda = try GeneralPurposeDebugAllocator.create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    std.debug.warn("\n");

    const alloc1 = try allocator.create(i32);
    std.debug.warn("alloc1 = {}\n", alloc1);

    allocator.destroy(@intToPtr(*i32, 0x12345));
}
