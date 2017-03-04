/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */

#include <stdlib.h>
#include <string.h>

#include "mix3.h"
#include "mix3impl.h"

static mix3_allocator _alloc = NULL;
static mix3_deallocator _dealloc = NULL;
static mix3_reallocator _realloc = NULL;

void *
mix3_alloc(size_t n)
{
  if (_alloc)
    return _alloc(n);
  else
    return malloc(n);
}

void *
mix3_alloc_zero(size_t n)
{
  void *mem = mix3_alloc(n);
  if (mem)
    memset(mem, 0, n);
  return mem;
}

void *
mix3_realloc(void *ptr, size_t n)
{
  if (_realloc)
    return _realloc(ptr, n);
  else
    return realloc(ptr, n);
}

void
mix3_free(void *ptr)
{
  if (!ptr)
    return;
  if (_dealloc)
    _dealloc(ptr);
  else
    free(ptr);
}

void
mix3_set_allocator(mix3_allocator allocator,
                   mix3_reallocator reallocator,
		   mix3_deallocator deallocator)
{
  _alloc = allocator;
  _realloc = reallocator;
  _dealloc = deallocator;
}

/* internal functions */

char *
mix3_strndup(const char *s, size_t n)
{
  char *r = mix3_alloc(n+1);
  if (!r) return NULL;
  strncpy(r, s, n);
  r[n] = 0;
  return r;
}

void *
mix3_memdup(const void *s, size_t n)
{
  char *r = mix3_alloc(n);
  if (!r) return NULL;
  memcpy(r, s, n);
  return r;
}


