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

![](https://i.imgur.com/KufxrKm.png)

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
8     256
9     512
10    1024
11    2048
```

Each bucket starts with no pages allocated. When the first object is allocated
for a given bucket, it allocates 1 page of memory from the OS. This page is
divided into "slots" - one per allocated object. Along with the page of memory
for object slots, as many pages as necessary are allocated to store the
BucketHeader, followed by "used bits", and a stack trace for each slot.

The "used bits" are 1 bit per slot representing whether the slot is used.
Allocations use the data to iterate to find a free slot. Frees assert that the
corresponding bit is 1 and set it to 0.

The memory for the allocator goes on its own page, with no write permissions.
On call to alloc and free, the allocator uses mprotect to make its own state
writable, and then removes write permissions before returning.

There are comptime configuration parameters. One of them is whether or not
the allocator should be thread-safe. If thread-safety is disabled, then the
debug allocator will detect invalid thread usage with it.

## Roadmap

* Make it support allocations after one page is exhausted
* Make it support allocations larger than what fits in the small allocation buckets
* Handle the case when realloc sized down and free would find another bucket.
* On double free, print the allocation stack trace, first free trace, and second free trace.
* Make allocations favor iterating forward over slots. Favor using new slots in
  the same memory page over reusing freed slots.
* Give memory back to the OS as often as possible. If a page can be unmapped then it
  should be unmapped.
* Catch the error when wrong n or wrong alignment is given to free or realloc/shrink.
* Ability to print stats
  * Requested Bytes Allocated (total of n for every alloc minus n for every free)
  * Resident Bytes (pagesize * number of pages mmapped for slots)
  * Overhead Bytes (how much memory the allocator state is using)
* Validation fuzz testing
* Performance benchmarking
* Iterate over usize instead of u8 for used bits
* Port to Windows
* Implement handling of multiple threads.
* When configured to be non-thread-safe, then detect usage with multiple threads,
  and print stack traces showing where it was used in each thread.
* Write unit tests / regression tests
