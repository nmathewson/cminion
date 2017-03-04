/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */
/* $Id$ */

#include <mix3.h>

static const struct err_ent {
  mix3_status_t k;
  const char *v;
} errornames[] = {
  { MIX3_OK,        "No error" },
  { MIX3_NOMEM,     "Out of memory" },
  { MIX3_BADARGS,   "Invalid arguments" },
  { MIX3_BADFORMAT, "Malformed object" },
  { MIX3_NOSPACE,   "Out of room" },
  { MIX3_NEED_MORE_FRAGMENTS, "Not enough framgents" },
  { MIX3_WANT_READ, "Can't proceed without more input" },
  { MIX3_WANT_WRITE,"Can't proceed until ready to write" },
  { MIX3_CLOSED,    "Unexpectedly closed connection" },
  { -1, NULL }
};

const char *
mix3_status_to_string(mix3_status_t status)
{
  int i;

  for (i = 0; errornames[i].v; ++i) {
    if (status == errornames[i].k)
      return errornames[i].v;
  }

  return "[Unrecognized error code]";
}
