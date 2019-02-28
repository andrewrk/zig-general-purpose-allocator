# GeneralPurposeDebugAllocator

This is the code for [my Zig Live Coding Stream](https://www.twitch.tv/andrewrok).
[Support my work on Patreon](https://www.patreon.com/andrewrk).

This is a work-in-progress general purpose allocator intended to be eventually merged
into the [Zig](https://ziglang.org/) standard library, with the focus on these goals:

 * Detect double free, and print stack trace of:
   - Where it was first allocated
   - Where it was freed the first time
   - Where it was freed the second time

 * Detect leaks and print stack trace of:
   - Where it was allocated

 * Ideally, freed memory would be unmapped so that it
   would cause page faults if used.

 * Make pointer math errors unlikely to harm memory from
   unrelated allocations

 * It's OK for these mechanisms to cost some extra bytes and for
   memory to become a little fragmented.

 * OK for performance cost for these mechanisms.

 * Rogue memory writes should not harm the allocator's state.

## Goals for Other General Purpose Allocators But Not This One

ReleaseFast and ReleaseSmall Modes:

 * Low fragmentation is primary concern
 * Performance of worst-case latency is secondary concern
 * Performance of average-case latency is next
 * Finally, having freed memory unmapped, and pointer math errors unlikely to
   harm memory from unrelated allocations are nice-to-haves.

ReleaseSafe Mode:

 * Low fragmentation is primary concern
 * All the safety mechanisms from Debug Mode are the next concern.
 * It's OK for these mechanisms to take up some percent overhead
   of memory, but not at the cost of fragmentation, which can cause
   the equivalent of memory leaks.

## Current Status

POSIX-only so far.

Able to detect memory leaks:

```
zig test test.zig
Test 1/1 oaeu...alloc1 = i32@7f27fbfda000
alloc2 = i32@7f27fbfda004
alloc1 = i32@7f27fbfda008
alloc2 = i32@7f27fbfda00c
alloc1 = i32@7f27fbfda010
alloc2 = i32@7f27fbfda014
alloc1 = i32@7f27fbfda018
alloc2 = i32@7f27fbfda01c

Memory leak detected:

Memory leak detected:

Memory leak detected:

Memory leak detected:
OK
All tests passed.
```

Only able to allocate 1 memory page per bucket, and does not support
large allocations.

### Current Design

Small allocations are divided into buckets:

```
index obj_size
0     1
1     2
2     4
3     8
4     16
5     32
6     64
7     128
```

Each bucket starts with no pages allocated. When the first object is allocated
for a given bucket, it allocates 1 page of memory from the OS. Each successive
allocation grabs the next slot from the bucket. Once all slots are exhausted
the allocator always returns OutOfMemory.

Each bucket has 1 bit per slot representing whether the slot is used. Allocations
assert that the corresponding bit is 0 and set it to 1. Frees assert that the
corresponding bit is 1 and set it to 0.

## Roadmap

* Make the leak detector print stack traces of the allocations

* Decide if it's going to be thread-safe or not.
* Make it reuse freed memory
* Make it support allocations after one page is exhausted
* Make it support allocations larger than what fits in the small allocation buckets
* Prevent more kinds of errors
* Give memory back to the OS as often as possible. If a page can be unmapped then it
  should be unmapped.
* Clear read/write permission bits on the allocator state itself, outside of function
  calls, so that non-allocator code cannot modify its state.
* Validation fuzz testing
* Performance benchmarking
