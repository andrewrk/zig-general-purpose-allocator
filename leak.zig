const std = @import("std");
const gpda_module = @import("gpda.zig");

const test_config = gpda_module.Config{};

test "basic leaks" {
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

test "leak in the first bucket" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    var buffer: [8000]u8 = undefined;
    const fixed = &std.heap.FixedBufferAllocator.init(&buffer).allocator;

    var list = std.ArrayList(*u64).init(fixed);

    std.debug.warn("\n");

    {
        // fill up a whole bucket, plus 1 extra
        var i: usize = 0;
        while (i < 513) : (i += 1) {
            const ptr = allocator.create(u64) catch unreachable;
            list.append(ptr) catch unreachable;
        }
    }

    // grab the extra one which should be in its own bucket
    // but forget to free it
    const leaky_pointer1 = list.pop();
    const leaky_pointer2 = list.pop();

    while (list.popOrNull()) |ptr| {
        allocator.destroy(ptr);
    }

    // now we expect to see 2 memory leaks
}
