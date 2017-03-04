/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */

#include <mix3.h>
#include <mix3impl.h>

#include <string.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>

struct desc_ent;

/* A single parsed sever descriptor entry, with link to next entry in
 * sequence. */
typedef struct desc_ent {
	struct desc_ent *next;
	char *k;
	char *v;
} desc_ent;

struct desc_sec;

/* A parsed server descriptor section, with link to next section in
   sequence.  */
typedef struct desc_sec {
	struct desc_sec *next;
	char *sec_name;
	desc_ent *entries;
	int recognized;
} desc_sec;

/* A linked list of parsed server descriptor sections. */
typedef struct desc {
	desc_sec *secs;
} desc;

static mix3_status_t parse_desc(desc **out, char *inp);

static void free_desc(desc *d) {
	desc_ent *e, *et;
	desc_sec *s, *st;
	for (s = d->secs; s; s=st) {
		st = s->next;
 		for (e = s->entries; e; e=et) {
			et = e->next;
			mix3_free(e->k);
			mix3_free(e->v);
			mix3_free(e);
		}
		mix3_free(s);
	}
	mix3_free(d);
}


static int tables_initialized = 0;
static uint8_t CHAR_IS_IDCHAR[256];
static uint8_t CHAR_IS_VALCHAR[256];

static void
init_tables(void)
{
  static char idchars[] =
    "!\"#$%&'()*+,-./"
    "0123456789;<=>?"
    "@ABCDEFGHIJLMNO"
    "PQRSTUVWXYZ\\^_`"
    "abcdefghijklmno"
    "pqrstuvwxyz{|}~";
  char *c;
  int i;
  for (i = 0; i < 256; ++i) {
    CHAR_IS_IDCHAR[i] = 0;
  }
  for (c = idchars; *c; ++c) {
    CHAR_IS_IDCHAR[(unsigned char) *c] = 1;
  }
  memcpy(CHAR_IS_VALCHAR, CHAR_IS_IDCHAR, sizeof(CHAR_IS_VALCHAR));
  CHAR_IS_VALCHAR[' '] = 1;
  CHAR_IS_VALCHAR['\t'] = 1;
  CHAR_IS_VALCHAR[':'] = 1;
  CHAR_IS_VALCHAR['['] = 1;
  CHAR_IS_VALCHAR[']'] = 1;

  tables_initialized = 1;
}

static char *
mix3_strndup_fold(const char *s, size_t n) {
  char *r = mix3_alloc(n+1);
  int last_was_space = 0;
  const char *end = s+n;
  char *p;
  if (!r) return NULL;
  p = r;
  while(*s && s < end) {
    if (*s == '\t' || *s == ' ') {
      if (last_was_space) { ++s; continue; }
      last_was_space = 1;
    } else {
      last_was_space = 0;
    }
    *p++ = *s++;
  }
  *p = 0;
  return r;
}

static inline void eat_space(char **inp)
{
	while (**inp == ' ' || **inp == '\t')
		++*inp;
}
/* return true on failure */
static inline int eat_eol(char **inp)
{
        eat_space(inp);
	if (**inp == '\r') {
		if ((*inp)[1] == '\n') {
			*inp += 2;
		} else {
			++*inp;
		}
		return 0;
	} else if (**inp == '\n') {
		++*inp;
		return 0;
	}
	return 1;
}

static inline mix3_status_t
get_identifier(char **out, char **inp) {
	char *start = *inp;
	char *r;
	while (CHAR_IS_IDCHAR[(unsigned char)**inp])
		++*inp;
	if (start == *inp)
		return MIX3_BADFORMAT;
	if (!(r = mix3_strndup(start, *inp-start)))
		return MIX3_NOMEM;
	*out = r;
	return MIX3_OK;
}

static inline mix3_status_t
get_value(char **out, char **inp) {
	char *start, *r, *last_nonspace;
	eat_space(inp);
	start = *inp;
	last_nonspace = *inp-1;
	while (CHAR_IS_VALCHAR[(unsigned char)**inp]) {
		if (**inp != ' ' && **inp != '\t')
			last_nonspace = *inp;
		++*inp;
	}
	if (!(r = mix3_strndup_fold(start, last_nonspace-start+1)))
		return MIX3_NOMEM;
	*out = r;
	return MIX3_OK;
}

static desc_sec *
new_sec(void)
{
	desc_sec *r;
	if (!(r = MIX3_NEW(desc_sec)))
		return NULL;
	r->next = NULL;
	r->sec_name = NULL;
	r->entries = NULL;
	r->recognized = 0;
	return r;
}

static desc_ent *
new_ent(void)
{
	desc_ent *r;
	if (!(r = MIX3_NEW(desc_ent)))
		return NULL;
	r->next = NULL;
	r->k = NULL;
	r->v = NULL;
	return r;
}

mix3_status_t
parse_desc(desc **out, char *inp)
{
	int lineno=1;
	desc *result;
	desc_sec **next_sec;
	desc_sec *cur_sec;
	desc_ent **next_ent;
	desc_ent *cur_ent;
	mix3_status_t status = -1;

	if (!tables_initialized)
		init_tables();

	if (!(result = MIX3_NEW(desc)))
		return MIX3_NOMEM;
	result->secs = NULL;
	next_sec = &result->secs;

	while(*inp) {
		if (*inp++ != '[') goto invalid;
		if (!(*next_sec = new_sec()))
			goto nomem;
		cur_sec = *next_sec;
		next_sec = &cur_sec->next;
		next_ent = &cur_sec->entries;
		if ((status = get_identifier(&cur_sec->sec_name, &inp)))
			goto error;
		if (*inp++ != ']') goto invalid;
		if (eat_eol(&inp)) goto invalid;
		++lineno;

		while (*inp && *inp != '[') {
			if (!(*next_ent = new_ent()))
				goto nomem;
			cur_ent = *next_ent;
			next_ent = &cur_ent->next;
			if ((status = get_identifier(&cur_ent->k, &inp)))
				goto error;
			if (*inp++ != ':')
				goto invalid;
			if (*inp != ' ' && *inp != '\t')
				goto invalid;
			if ((status = get_value(&cur_ent->v, &inp)))
				goto error;
			if (eat_eol(&inp))
				goto invalid;
			++lineno;
		}
	}

	*out = result;
	return MIX3_OK;

 invalid:
	status = MIX3_BADFORMAT;
	goto error;
 nomem:
	status = MIX3_NOMEM;
	goto error;
 error:
	free_desc(result);
	out = NULL;
	return status;
}


static void
feed_digest(SHA_CTX *sha1, char **inp) {
	char *c, *eol;
	for (c = *inp; *c && *c != '\r' && *c != '\n'; ++c)
		;
	eol = c;
	if (eol[0] == '\r' && eol[1] == '\n')
		++eol;
	--c;
	while (c > *inp && (*c == ' ' || *c == '\t'))
		--c;
	/* c now points to the last non-space char in the line;
	   eol now points to the last eol char in the line.*/
	SHA1_Update(sha1, *inp, (c-*inp)+1);
	SHA1_Update(sha1, "\n", 1);
	*inp = eol+1;
}

typedef struct unsigned_field
{
  const char *secname;
  const char *entname;
} unsigned_field;

static const unsigned_field UNSIGNED_SERVERDESC[] = {
  { "Server", "Digest" },
  { "Server", "Signature" },
  { NULL, NULL }
};

static const unsigned_field UNSIGNED_DIRHEADER[] = {
	{ "Signature", "DirectoryDigest" },
	{ "Signature", "DirectorySignature" },
	{ NULL, NULL }
};

static const unsigned_field UNSIGNED_NONE[] = {
	{ NULL, NULL }
};

static void
digest_desc(SHA_CTX *sha1, char *inp, const unsigned_field *uf) {
	char *s;
	char *tmp;
	char *cursec = NULL;
	const unsigned_field *u;
	int is_unsigned;
	mix3_status_t status;

	while (*inp) {
		if (*inp != '[') goto done;
		if (cursec) mix3_free(cursec);
		tmp = inp+1;
		if (!(status = get_identifier(&cursec, &tmp)))
			goto done;
		feed_digest(sha1, &inp);

		while (*inp && *inp != '[') {
			s = strchr(inp, ':');
			if (!s) goto done;
			is_unsigned = 0;
			for (u = uf; u->secname; ++u) {
				if (!strcmp(u->secname, cursec) &&
				    !strncmp(u->entname, inp, s-inp)) {
					is_unsigned = 1;
					break;
				}
			}
			if (is_unsigned) {
				SHA1_Update(sha1, inp, s-inp);
				SHA1_Update(sha1, ": \n", 3);
				while (*inp && *inp != '\r' && *inp != '\n')
					++inp;
				if (eat_eol(&inp)) goto done;
				continue;
			}
			feed_digest(sha1, &inp);
		}
	}

 done:
	mix3_free(cursec);
}

static char *
get_section_entry(desc *d, const char *secname, const char *entname,
                  int knownonly) {
	desc_sec *s;
	desc_ent *e;
	for (s = d->secs; s; s=s->next) {
		if (knownonly && !s->recognized)
			continue;
		if (strcmp(s->sec_name, secname))
			continue;
		for (e = s->entries; e; e=e->next) {
			if (!strcmp(e->k, entname)) {
			        return e->v;
			}
		}
	}
	return NULL;
}

typedef struct known_sections {
  const char *sec;
  const char *field;
  const char *ver[5];
} known_sections;

static const known_sections SERVERDESC_KNOWN_SECS[] = {
	{ "Server",        "Descriptor-Version", { "0.2" } },
	{ "Incoming/MMTP", "Version",            { "0.1" } },
	{ "Outgoing/MMTP", "Version",            { "0.1" } },
	{ "Delivery/Fragmented", "Version",      { "0.1" } },
	{ "Delivery/SMTP", "Version",            { "0.1" } },
	{ "Delivery/MBOX", "Version",            { "0.1" } },
	{ NULL,            NULL,                 { "0.1" } },
};

static void
setup_known_sections(desc *d, const known_sections *known)
{
	desc_sec *s;
	desc_ent *e;
	const known_sections *ks;
	char *ver;
	int i;

	for (s = d->secs; s; s=s->next) {
		for (ks = known; ks->sec; ++ks) {
			if (!strcmp(ks->sec, s->sec_name))
				break;
		}
		if (!ks->sec) continue;
		ver = NULL;
		for (e = s->entries; e; e=e->next) {
			if (!strcmp(ks->field, e->k)) {
				ver = e->v; break;
			}
		}
		if (ver == NULL) continue;
		for (i = 0; ks->ver[i]; ++i) {
			if (!strcmp(ver, ks->ver[i])) {
				s->recognized = 1;
				break;
			}
		}
	}
}


static int
check_pattern(const char *pat, const char *s) {
	while (*pat && *s) {
		if (*pat == 'd') {
			if (!isdigit(*s))
				return 0;
		} else if (*pat == 'D') {
			if (!isdigit(*s++))
				return 0;
			while (isdigit(s[1]))
			       ++s;
		} else {
			if (*pat != *s)
				return 0;
		}
		++s; ++pat;
	}
	return (!*pat && !*s);
}

static mix3_status_t
check_nickname(const char *s)
{
  (void)s;
  return MIX3_OK; /* XXXX IMPLEMENT */
}

static const char *TIME_PATTERNS[] = {
	"dddd-dd-dd",
	"dddd-dd-dd dd:dd:dd",
	"dddd-dd-dd dd:dd:dd.dddd",
};

static mix3_status_t
parse_time(time_t *out, const char *s, int dateonly) {
	struct tm t;
	const char *pat = NULL;
	int i;

	for (i = 0; i < 3; ++i) {
		if (check_pattern(TIME_PATTERNS[i], s)) {
			pat = TIME_PATTERNS[i]; break;
		}
	}
	if (!pat) return MIX3_BADFORMAT;
	if (pat != TIME_PATTERNS[0] && dateonly) return MIX3_BADFORMAT;
	t.tm_year = atoi(&s[0]);
	t.tm_mon = atoi(&s[5]);
	t.tm_mday = atoi(&s[8]);
	if (pat != TIME_PATTERNS[0]) {
		t.tm_hour = atoi(&s[11]);
		t.tm_min = atoi(&s[14]);
		t.tm_sec = atoi(&s[17]);
	} else {
		t.tm_hour = t.tm_min = t.tm_sec = 0;
	}
	t.tm_isdst = 0;

	*out = mktime(&t);
	return MIX3_OK;
}

static mix3_status_t
parse_boolean(int *out, const char *s)
{
	if (!strcmp(s, "yes")) {
		*out = 1;
	} else if (!strcmp(s, "no")) {
		*out = 0;
	} else {
		return MIX3_BADFORMAT;
	}
	return MIX3_OK;
}

static mix3_status_t
parse_integer(long *out, const char *s)
{
	*out = strtol(s, NULL, 10);
	if ((*out == LONG_MIN || *out == LONG_MAX) && errno == ERANGE)
		return MIX3_BADFORMAT;
	return MIX3_OK;
}

static mix3_status_t
parse_ipv4(int out[], const char *s)
{
	int i;
	if (!check_pattern("D.D.D.D", s))
		return MIX3_BADFORMAT;
	out[0] = atoi(s);
	s = strchr(s, '.')+1;
	out[1] = atoi(s);
	s = strchr(s, '.')+1;
	out[2] = atoi(s);
	s = strchr(s, '.')+1;
	out[3] = atoi(s);

	for (i = 0; i < 4; ++i) {
		if (out[i] < 0 || out[i] > 255) {
			return MIX3_BADFORMAT;
		}
	}

	return MIX3_OK;
}

static mix3_status_t
parse_binary(char **out, size_t *len_out, const char *s)
{
  return _mix3_parse_base64(out, len_out, s, strlen(s));
}

static mix3_status_t
parse_pubkey(RSA **out, const char *s)
{
	char *decoded;
	const unsigned char *decoded_u;
	size_t decoded_len;
	mix3_status_t status;
        RSA *rsa;

	if ((status = parse_binary(&decoded, &decoded_len, s)))
		return status;

	decoded_u = (unsigned char*)decoded;
	if (!(rsa = d2i_RSAPublicKey(NULL,
				 &decoded_u, decoded_len))) {
		mix3_free(decoded);
		return MIX3_BADFORMAT;
	}
        *out = rsa;
	return MIX3_OK;
}

static mix3_status_t
parse_csl(char ***out, const char *s)
{
	int n = 0, i;
	const char *cp = s;
	while (*cp && (cp = strchr(cp, ','))) {
		++cp; ++n;
	}
	if (!(*out = mix3_alloc(sizeof(char*)*(n+1))))
		return MIX3_NOMEM;
	i = 0;
	while (*s) {
		cp = s;
		s = strchr(s, ',');
		(*out)[i] = mix3_strndup(cp, s-cp);
		++s; ++i;
	}
	out[n] = NULL;

	return MIX3_OK;
}

/* Server descriptor functionality */

struct mix3_serverdesc {
	struct desc *d;
	int validated;

	/* [Server] entries */
	RSA *identity_key;
	RSA *packet_key;
	time_t published;
	time_t validAfter;
	time_t validUntil;
	/* ---- pointers into d. */
	char *nickname;

	/* [Incoming/MMTP] */
	int has_incoming_mmtp;
	int ipv4[4];
	unsigned int port;
	char keyid[20];
	char **protocols_in;
	/* XXXX allow/deny */

	/* [Outgoing/MMTP] */
	int has_outgoing_mmtp;
	char **protocols_out;
	/* XXXX allow/deny */

	/* [Delivery/Fragmented] */
	int has_delivery_fragmented;
	unsigned long max_fragments;

	/* [Delivery/SMTP] */
	int has_delivery_smtp;

	/* [Delivery/MBOX] */
	int has_delivery_mbox;

	mix3_routing_info_t routing_info;
};

static mix3_serverdesc *
mix3_new_serverdesc(void)
{
	mix3_serverdesc *r = MIX3_NEW(mix3_serverdesc);
	if (!r)
		return NULL;

	r->d = NULL;
	r->validated = 0;

	r->identity_key = r->packet_key = NULL;
	r->published = r->validAfter = r->validUntil = 0;
	r->nickname = NULL;

	r->has_incoming_mmtp = r->has_outgoing_mmtp =
		r->has_delivery_fragmented = r->has_delivery_smtp =
		r->has_delivery_mbox = 0;

	memset(r->ipv4, 0, 4);
	r->port = 0;
	memset(r->keyid, 0, 20);
	r->protocols_in = r->protocols_out = NULL;

	r->max_fragments = 0UL;

	return r;
}

void
_mix3_serverdesc_free(mix3_serverdesc *d)
{
	int i;

        if (!d)
          return;
	if (d->d)
          free_desc(d->d);
	if (d->identity_key)
          RSA_free(d->identity_key);
	if (d->packet_key)
          RSA_free(d->packet_key);


	if (d->protocols_in) {
		for (i = 0; d->protocols_in[i]; ++i)
			mix3_free(d->protocols_in[i]);
		mix3_free(d->protocols_in);
	}
	if (d->protocols_out) {
		for (i = 0; d->protocols_out[i]; ++i)
			mix3_free(d->protocols_out[i]);
		mix3_free(d->protocols_out);
	}
}

mix3_status_t
_mix3_serverdesc_parse(mix3_serverdesc **out, char *inp, int validate)
{
	mix3_serverdesc *sd;
	mix3_status_t status;
	char digest[20];
	char *e;

	char *s = NULL;
        size_t sz;
        long lng;
	SHA_CTX sha1;

	if (!(sd = mix3_new_serverdesc()))
		goto nomem;

	if ((status = parse_desc(&sd->d, inp)))
		return status;
	setup_known_sections(sd->d, SERVERDESC_KNOWN_SECS);

	if (validate) {
        	size_t len;
                SHA1_Init(&sha1);
		digest_desc(&sha1, inp, UNSIGNED_SERVERDESC);
		SHA1_Final((unsigned char*) digest, &sha1);
		e = get_section_entry(sd->d, "Server", "Digest", 1);
		if (!e) goto invalid;
		if ((status = parse_binary(&s, &len, e)))
			goto error;
                if (len != 20 || memcmp(s, digest, 20))
			goto invalid;
		mix3_free(s);
		s = NULL;
	}

	if (!(e = get_section_entry(sd->d, "Server", "Identity", 1)))
		goto invalid;
	if ((status = parse_pubkey(&sd->identity_key, e)))
		goto error;
	/* XXXX check size */

	if (!(e = get_section_entry(sd->d, "Server", "PublicKey", 1)))
		goto invalid;
	if ((status = parse_pubkey(&sd->packet_key, e)))
		goto error;
	/* XXXX check size */

	if (!(e = get_section_entry(sd->d, "Server", "Published", 1)))
		goto invalid;
	if ((status = parse_time(&sd->published, e, 0)))
		goto error;

	if (!(e = get_section_entry(sd->d, "Server", "ValidAfter", 1)))
		goto invalid;
	if ((status = parse_time(&sd->validAfter, e, 1)))
		goto error;

	if (!(e = get_section_entry(sd->d, "Server", "ValidUntil", 1)))
		goto invalid;
	if ((status = parse_time(&sd->validUntil, e, 1)))
		goto error;
	/* XXXX Check time ranges */

	if ((sd->nickname = get_section_entry(sd->d, "Server", "Nickname", 1)))
		goto invalid;
	if (check_nickname(sd->nickname))
		goto error;

	if (get_section_entry(sd->d, "Incoming/MMTP", "Version", 1)) {
		sd->has_incoming_mmtp = 1;

		if (!(e = get_section_entry(sd->d, "Incoming/MMTP", "IP", 1)))
			goto invalid;
		if ((status = parse_ipv4(sd->ipv4, e)))
			goto error;

		if (!(e = get_section_entry(sd->d, "Incoming/MMTP", "Port",1)))
			goto invalid;
		if ((status = parse_integer(&lng, e)))
			goto error;
                if (lng < 1 || lng > 65535)
                  goto invalid;

                sd->port = lng;

		if (!(e = get_section_entry(sd->d, "Incoming/MMTP","KeyID",1)))
			goto invalid;
		if ((status = parse_binary(&s, &sz, e)))
			goto error;
		if (sz != 20)
			goto invalid;
		memcpy(sd->keyid, s, 20);
		mix3_free(s); s = NULL;

		if (!(e = get_section_entry(sd->d, "Incoming/MMTP",
					    "Protocols", 1)))
			goto invalid;
		if ((status = parse_csl(&sd->protocols_in, e)))
			goto error;
	}

	if (get_section_entry(sd->d, "Outgoing/MMTP", "Version", 1)) {
		sd->has_incoming_mmtp = 1;

		if (!(e = get_section_entry(sd->d, "Outgoing/MMTP",
					    "Protocols", 1)))
			goto invalid;
		if ((status = parse_csl(&sd->protocols_out, e)))
			goto error;
	}

#if 0
	if (get_section_entry(sd->d,
                              /* IMPLEMENT ME XXXXX */)) {}
#endif

        


        *out = sd;
        goto done;
 invalid:
	status = MIX3_BADFORMAT;
	goto error;
 nomem:
	status = MIX3_NOMEM;
	goto error;
 error:
	if (sd)
          _mix3_serverdesc_free(sd);
          
 done:
	if (s)
		mix3_free(s);

	return status;
}
