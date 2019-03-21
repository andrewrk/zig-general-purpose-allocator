const std = @import("std");
const GeneralPurposeDebugAllocator = @import("gpda.zig").GeneralPurposeDebugAllocator;

test "leaks" {
    const gpda = try GeneralPurposeDebugAllocator.create();
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
