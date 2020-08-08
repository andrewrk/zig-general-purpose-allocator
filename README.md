# This Project Has Been Merged Upstream

This code was integrated into the Zig Standard Library in
[Pull Request #5998](https://github.com/ziglang/zig/pull/5998).

**This repository is no longer maintained.**

# GeneralPurposeDebugAllocator

This is the code for [my Zig Live Coding Stream](https://www.twitch.tv/andrewrok).

This is a work-in-progress general purpose allocator intended to be eventually merged
into the [Zig](https://ziglang.org/) standard library, with the focus on these goals:

 * Detect double free, and print stack trace of:
   - Where it was first allocated
   - Where it was freed the first time
   - Where it was freed the second time

 * Detect leaks and print stack trace of:
   - Where it was allocated

 * When a page of memory is no longer needed, give it back to resident memory,
   but keep it mapped with no permissions (read/write/exec) so that it causes
   page faults when used.

 * Make pointer math errors unlikely to harm memory from
   unrelated allocations

 * It's OK for these mechanisms to cost some extra bytes and for
   memory to become a little fragmented.

 * OK for performance cost for these mechanisms.

 * Rogue memory writes should not harm the allocator's state.

 * Cross platform. Allowed to take advatage of a specific operating system's
   features, but should work everywhere, even freestanding, by wrapping an
   existing allocator.

 * Compile-time configuration, including:
   - Whether the allocatior is to be thread-safe. If thread-safety is disabled,
     then the debug allocator will detect invalid thread usage with it.
   - How many stack frames to collect.

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

 * POSIX-only so far.
 * Most basic functionality works. See Roadmap below for what's left to do.
 * Not well tested yet.

Memory leak detection:

![](https://i.imgur.com/KufxrKm.png)

Double free detection:

![](https://i.imgur.com/5M5xS95.png)

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

The main allocator state has an array of all the "current" buckets for each
size class. Each slot in the array can be null, meaning the bucket for that
size class is not allocated. When the first object is allocated for a given
size class, it allocates 1 page of memory from the OS. This page is
divided into "slots" - one per allocated object. Along with the page of memory
for object slots, as many pages as necessary are allocated to store the
BucketHeader, followed by "used bits", and two stack traces for each slot
(allocation trace and free trace).

The "used bits" are 1 bit per slot representing whether the slot is used.
Allocations use the data to iterate to find a free slot. Frees assert that the
corresponding bit is 1 and set it to 0.

The memory for the allocator goes on its own page, with no write permissions.
On call to reallocFn and shrinkFn, the allocator uses mprotect to make its own state
writable, and then removes write permissions before returning. However bucket
metadata is not protected in this way yet.

Buckets have prev and next pointers. When there is only one bucket for a given
size class, both prev and next point to itself. When all slots of a bucket are
used, a new bucket is allocated, and enters the doubly linked list. The main
allocator state tracks the "current" bucket for each size class. Leak detection
currently only checks the current bucket.

Reallocation detects if the size class is unchanged, in which case the same
pointer is returned unmodified. If a different size class is required, the
allocator attempts to allocate a new slot, copy the bytes, and then free the
old slot.

Large objects are allocated directly using `mmap` and their metadata is stored
in a `std.HashMap` backed by a simple direct allocator. The hash map's data
is memory protected with the same strategy as the allocator's state.

## Roadmap

* Port to Windows
  - Make sure that use after free tests work.
* Test mmap hints on other platforms:
  - macOS
  - FreeBSD
* Ability to print stats
  - Requested Bytes Allocated (total of n for every alloc minus n for every free)
  - Resident Bytes (pagesize * number of pages mmapped for slots)
  - Overhead Bytes (how much memory the allocator state is using)
* Validation fuzz testing
  - vary the size and alignment of allocations
  - vary the number of and kind of operations in between allocations and
    corresponding frees
  - vary whether or not the backing allocator succeeds
  - how much memory capacity it goes up to
* When allocating new pages for small objects, if virtual address space is
  exhausted, fall back to using the oldest freed memory, whether that be
  unused pages, or freed slots.
* When falling back to old unused pages, if we get an error from the OS from
  reactivating the page, then fall back to a freed slot.
* Implement handling of multiple threads.
* On invalid free, print nearest allocation/deallocation stack trace
* Do the memory protection for bucket metadata too
* Catch the error when wrong size or wrong alignment is given to free or realloc/shrink.
* Performance benchmarking
  - Do we need meta-buckets?
* Iterate over usize instead of u8 for used bits
* When configured to be non-thread-safe, then detect usage with multiple threads,
  and print stack traces showing where it was used in each thread.
* Write unit tests / regression tests
* Make `std.HashMap` return bytes back to the allocator when the hash map gets
  smaller.
* Make deallocated but still mapped bytes be `0xdd`.
* Detect when client uses the wrong `old_align` or `old_mem.len`.
* Keep track of first allocation stack trace as well as reallocation stack trace
  for large objects.
* Test whether it is an improvement to try to use an mmap hint when growing
  a large object and it has to mmap more.
* Once a bucket becomes full, remove it from the linked list of buckets that are
  used to find allocation slots.
