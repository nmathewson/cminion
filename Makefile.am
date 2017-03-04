# Copyright 2006-2009 Nick Mathewson; See COPYING for license information. 

SUBDIRS = src test

DISTCLEANFILES = *~

mix3config.h: mix3config_pre.h
	cat mix3config_pre.h \
	  | $(SED) -e 's/^#define \([A-Z][A-Z]*\)/#define MIX3_\1/' \
	  > mix3config.h

include_HEADERS = mix3config.h
