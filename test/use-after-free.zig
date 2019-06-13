const std = @import("std");
const testing = std.testing;
const gpda_module = @import("../gpda.zig");

const test_config = gpda_module.Config{};

test "use after free - large" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const first = try allocator.alloc(u8, 3000);
    allocator.free(first);

    const second = try allocator.alloc(f32, 1000);
    second[0] = 3.14;
    std.mem.copy(u8, first, "hello this is dog");
    testing.expect(second[0] == 3.14);

    allocator.free(second);
}

test "use after free - small" {
    const gpda = try gpda_module.GeneralPurposeDebugAllocator(test_config).create();
    defer gpda.destroy();
    const allocator = &gpda.allocator;

    const first = try allocator.alloc(u8, 4);
    std.debug.warn("first = {*}\n", first.ptr);

    // this one keeps the page mapped for size class 4
    const anchor = try allocator.create(i32);
    std.debug.warn("anchor = {*}\n", anchor);
    defer allocator.destroy(anchor);

    allocator.free(first);

    const second = try allocator.create(f32);
    std.debug.warn("second = {*}\n", second);
    second.* = 3.14;
    std.mem.copy(u8, first, "hell");
    testing.expect(second.* == 3.14);

    allocator.destroy(second);
}
