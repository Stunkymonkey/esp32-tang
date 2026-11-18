#pragma once
// Host stand-in: the WipingAllocator asks the heap for a block's size.
#include <malloc.h>
inline size_t heap_caps_get_allocated_size(void *ptr) { return malloc_usable_size(ptr); }
