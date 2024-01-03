/*
 * mm-explicit.c - The best malloc package EVAR!
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

/** The node for each free block (used for the list of free blocks) */
typedef struct node_t {
    size_t size;
    struct node_t *next;
    struct node_t *prev;
} node_t;

/** The footer of each block */
typedef struct {
    size_t size;
} footer_t;

/** A linked list of the free blocks */
static node_t *mm_free_list = NULL;
/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts the previous block's size from its footer */
static size_t get_prev_size(block_t *block) {
    footer_t *footer = (void *) block - sizeof(footer_t);
    return footer->size & ~1;
}

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

/** Set's a block's footer using the given size and allocation state */
static void set_footer(block_t *block, size_t size, bool is_allocated) {
    footer_t *footer = (void *) block + size - sizeof(footer_t);
    footer->size = size | is_allocated;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * Removes a node to mm_free_list
 */
void remove_node(node_t *node) {
    assert(node != NULL);
    if (node->prev == NULL) {
        mm_free_list = node->next;
    }
    else {
        node->prev->next = node->next;
    }
    if (node->next != NULL) {
        node->next->prev = node->prev;
    }
}

/**
 * Adds a node to mm_free_list
 */
void add_node(node_t *node) {
    assert(node != NULL);
    if (mm_free_list == NULL) {
        node->prev = NULL;
        node->next = NULL;
        mm_free_list = node;
    }
    else {
        node->prev = NULL;
        node->next = mm_free_list;
        mm_free_list->prev = node;
        mm_free_list = node;
    }
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    if (mm_free_list == NULL) {
        return NULL;
    }
    for (node_t *node = mm_free_list; node != NULL; node = node->next) {
        if (get_size((block_t *) node) >= size) {
            return (block_t *) node;
        }
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    mm_free_list = NULL;
    return true;
}

/**
 * mm_check_alloc - checks to see if two neighboring blocks are not allocated
 */
void check_alloc(block_t *left, block_t *right) {
    if (is_allocated(left) || is_allocated(right)) {
        return;
    }
    size_t left_size = get_size(left);
    size_t right_size = get_size(right);
    set_header(left, left_size + right_size, false);
    set_footer(left, left_size + right_size, false);
    remove_node((node_t *) right);
    if (right == mm_heap_last) {
        mm_heap_last = left;
    }
}

/**
 * mm_coalesce - Coalesces the freed blocks
 */
void mm_coalesce(block_t *block) {
    assert(block != NULL);
    if (block < mm_heap_last) {
        block_t *next = (void *) block + get_size(block);
        check_alloc(block, next);
    }
    if (block > mm_heap_first) {
        block_t *prev = (void *) block - get_prev_size(block);
        check_alloc(prev, block);
    }
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size + sizeof(footer_t), ALIGNMENT);

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        remove_node((node_t *) block);
        size_t block_size = get_size(block);
        if (size + sizeof(block_t) + sizeof(footer_t) < get_size(block)) {
            block_t *split_block = ((void *) block) + size;
            set_header(split_block, block_size - size, false);
            set_footer(split_block, block_size - size, false);
            if (block == mm_heap_last) {
                mm_heap_last = split_block;
            }
            add_node((node_t *) split_block);
            set_header(block, size, true);
            set_footer(block, size, true);
        }
        else {
            set_header(block, block_size, true);
            set_footer(block, block_size, true);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header(block, size, true);
    set_footer(block, size, true);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    size_t size = get_size(block);
    set_header(block, size, false);
    set_footer(block, size, false);
    add_node((node_t *) block);
    mm_coalesce(block);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }

    void *new_ptr = mm_malloc(size);
    void *new_block = block_from_payload(new_ptr);
    void *old_block = block_from_payload(old_ptr);

    size_t new_size = get_size(new_block);
    size_t old_size = get_size(old_block);

    if (new_size < old_size) {
        memcpy(new_ptr, old_ptr, new_size - sizeof(size_t) - sizeof(block_t));
    }
    else {
        memcpy(new_ptr, old_ptr, old_size - sizeof(size_t) - sizeof(block_t));
    }

    mm_free(old_ptr);
    return new_ptr;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    void *block = mm_malloc(nmemb * size);
    memset(block, 0, nmemb * size);
    return block;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    size_t num_free_blocks = 0;
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        footer_t *footer = (void *) curr + get_size(curr) - sizeof(footer_t);
        assert(curr->header == footer->size);
        if (!is_allocated(curr)) {
            num_free_blocks++;
        }
    }
    size_t num_free_nodes = 0;
    for (node_t *node = mm_free_list; node != NULL; node = node->next) {
        num_free_nodes++;
    }
    assert(num_free_blocks == num_free_nodes);
}