/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */
/* $Id */

/*
 * This header file ("mix3.h") should be included by any C file
 * using type III Mix client functionality.
 */

#ifndef _MIX3_H
#define _MIX3_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/rsa.h>

/* We allow the caller to give us a special-purpose allocator -- for
 * example, in order to use mlocked memory.
 */
typedef void *(*mix3_allocator)(size_t n);
typedef void *(*mix3_reallocator)(void *ptr, size_t n);
typedef void (*mix3_deallocator)(void *ptr);
void mix3_set_allocator(mix3_allocator allocator,
                        mix3_reallocator reallocator,
                        mix3_deallocator deallocator);

/* ==================== */
/* Error handling */
/* ==================== */

/* Nearly all mix3 functions return a mix3_status_t code to indicate
 * whether they have succeeded -- and if not, why they have failed.
 *
 * (In another language, we'd use exceptions for this.)
 */
typedef enum {
        /* The operation completed successfully. */
        MIX3_OK = 0,
        /* The operation failed due to lack of memory. */
        MIX3_NOMEM,
        /* The operation failed because the arguments given to the
         * function were invalid.
         */
        MIX3_BADARGS,
        /* The operation failed because the directory, server
         * descriptor, message, etc provided was not correctly
         * formatted or signed.
         */
        MIX3_BADFORMAT,
        /* The operation failed because a provided output structure
         * is not long enough.
         */
        MIX3_NOSPACE,
        /* The operation failed because more fragments need to be
         * collected before we can reconstruct the message.
         */
        MIX3_NEED_MORE_FRAGMENTS,

        /* The network operation will block until the underlying file
         * descriptor has data to read. */
        MIX3_WANT_READ,
        /* The network operation will block until the underlying file
         * descriptor is ready for writing. */
        MIX3_WANT_WRITE,
        /* The network operation failed because the underlying file
         * decriptor is closed. */
        MIX3_CLOSED,
        MIX3_PATH_TOO_LONG,
        MIX3_CORRUPT_PACKET,
        MIX3_BAD_VERSION

        /* XXXX We need __way__ more error codes.  I don't know what. */
} mix3_status_t;

/* Effects: Given a mix3_status_t code, return a English string.
 * Allocates: nothing.
 */
const char *mix3_status_to_string(mix3_status_t status);

/* ==================== */
/* Directories */
/* ==================== */

/* Opaque struct to hold a Type III directory */
typedef struct mix3_directory mix3_directory;
/* Opaque struct to hold a Type III server descriptor */
typedef struct mix3_serverdesc mix3_serverdesc;

/* Struct to describe a part of a Type III path.  A path component may
 * either specify a server by nickname (type == MIX3_PC_NICKNAME); provide
 * a server explicitly (type == MIX3_PC_DESCRIPTOR); request a number
 * of randomly chosen servers (type == MIX3_PC_RANDOM); or specify a
 * swap point (type == MIX3_PC_SWAP).
 *
 * 'name' is used for MIX3_PC_NICKNAME; 'server' is used for
 * MIX3_PC_DESCRIPTOR; and 'n' is used for MIX3_PC_RANDOM.  If n>=0,
 * then exactly n random servers are chosen.  If n<0, then
 * approximately -n random servers are chosen.
 */
typedef struct mix3_pathcomponent {
        enum { MIX3_PC_NICKNAME, MIX3_PC_DESCRIPTOR, MIX3_PC_RANDOM,
               MIX3_PC_SWAP } type;
        union {
                char *name;
                mix3_serverdesc *server;
                int n;
        } info;
} mix3_pathcomponent;
/* Struct to describe a requested Type III path. */
typedef struct mix3_pathspec {
        int n_specifiers;
        mix3_pathcomponent *specifiers;
} mix3_pathspec;
/* Struct to describe a Type III directory server. */
typedef struct mix3_directory_server {
        char *server_name;
        char *server_directory_url;
        char *server_identity_fingerprint;
} mix3_directory_server;
/* Struct to specify a Type III server's basic capabilities. */
typedef struct mix3_capability_spec {
        int email;
        int news;
        int relay;
} mix3_capability_spec;
/* Struct to specify the destination of a Type III message. */
typedef struct mix3_address_spec {
        enum { MIX3_ADDR_EMAIL, MIX3_ADDR_MBOX, MIX3_ADDR_NEWS,
               MIX3_ADDR_DROP,  MIX3_ADDR_OTHER, MIX3_ADDR_REPLY } type;
        union {
                char *address;
                struct {
                        unsigned int routing_type;
                        int routinginfo_len;
                        char *routinginfo;
                        char *opt_exit_server_name;
                } raw_address;
        } val;
        RSA *recipient_key; /* XXXX describe */
} mix3_address_spec;

/* Effects: given NUL-terminated a string encoding a Type
 *    III directory parse it into a new directory, and
 *    point *dir_out at the new directory.
 * Arguments:
 *    dir_out -- A pointer to a pointer to hold the allocated
 *        directory.
 *    dir_string -- The string to parse.
 *    opt_prev_directory -- NULL, or a previous directory to compare
 *        this one to.
 *    known_directory_servers -- a NULL-terminated array of pointers
 *       to known mix3_directory_servers, and is used to check
 *       signatures.
 *    validate -- if false, the function does not check the
 *       directory's signature.
 * Allocates: *dir_out, which should be freed with mix_directory_free.
 */
mix3_status_t mix3_directory_parse_from_string(
        mix3_directory **dir_out,
        char *dir_string,
        mix3_directory_server **known_directory_servers,
        mix3_directory *opt_prev_directory,
        int validate);

/* Same as mix3_directory_parse_from_string, but reads from a stdio
 * FILE.
 */
mix3_status_t mix3_directory_parse_from_file(
        mix3_directory **dir_out,
        FILE *dir_file,
        mix3_directory_server **known_directory_servers,
        mix3_directory *opt_prev_directory,
        int validate);

/* Returns the number of server descriptors in a directory.
 */
unsigned int mix3_directory_get_n_descriptors(mix3_directory *dir);

/* Returns true iff the provided directory is valid at a given time. */
int mix3_directory_is_current(mix3_directory *dir, time_t when);

/* Try to download a directory, and store the result in a string.
 * This function may block for a while.
 *
 * Arguments:
 *    result -- a buffer to hold the downloaded string.
 *    result_len -- the usable length of the output buffer.
 *    mix3_directory_server -- the server to use.
 *
 * XXXX Should we try for an async version of this?
 */
mix3_status_t mix3_directory_download_to_string(
        char *result,
        int result_len,
        mix3_directory_server *server);

/* Same as mix3_directory_download_to_string, but write the result to
 * a stdio FILE.
 */
mix3_status_t mix3_directory_download_to_file(
        FILE *result,
        mix3_directory_server *server);

/* Allocate a new NULL-terminated array of server descriptors from a
 * directory that match certain properties.
 *
 * Arguments:
 *    servers_out -- If the function succeeds, *servers_out will be a
 *        NULL-terminated array of pointers to server descriptors.
 *    byNickname -- If not NULL, the function only yields server
 *        descriptors whose nicknames match byNickname.
 *    byCapability -- If not NULL, the function only yields server
 *        descriptors that have at leas tthe capabilities set in
 *        *byCapability.
 *    validBy -- If not 0, the function only yields server descriptors
 *        that become valid at some time before validBy.
 *    validUntil -- if not 0, the function only yields server
 *        descriptors that do not become invalid before validUntil.
 *
 * Allocates: servers_out; it must be freed.
 */
mix3_status_t mix3_directory_get_servers(
        mix3_serverdesc ***servers_out,
        char *byNickname,
        mix3_capability_spec *byCapability,
        time_t validBy,
        time_t validUntil);

/* Deallocate a mix3_directory and associated server descriptors. */
void mix3_directory_free(mix3_directory *directory);

/* ==================== */
/* Servers */
/* ==================== */

/* Returns the nickname of a server descriptor.  The returned string
 * must not be modified, and has the same lifetime as 'desc'. */
const char *mix3_serverdesc_get_nickname(mix3_serverdesc *desc);

/* Returns true iff a provided descriptor has at least given set of
 * capabilities. */
int mix3_serverdesc_has_capabilities(mix3_serverdesc *desc,
                                      mix3_capability_spec *capabilities);

/* Sets *becomes_valid_out and *becomes_invalid_out to match the
 * lifespan of 'desc'. */
void mix3_serverdesc_get_lifespan(mix3_serverdesc *desc,
                                  time_t *becomes_valid_out,
                                  time_t *becomes_invalid_out);

/* === Helper functions for server descriptors. === */

/* Return a raw field from a server descriptor, by section and field
 * name.
 */
const char *mix3_serverdesc_get_field(mix3_serverdesc *desc,
                                      const char *section,
                                      const char *field);

/* Parse a server descriptor from a string.
 *
 * Arguments:
 *    serverdesc_out -- If the function is successful,
 *        *serverdesc_out will point to a freshly allocated
 *        serverdesc.
 *    string -- Before the function is called, *string points to the
 *        descriptor to parse.  On success, after the function is
 *        called, *string points to the position immediately after the
 *        server descriptor.
 *    validate -- If true, check the signature on the descriptor.
 *
 * Allocates: *serverdesc_out, which must be freed with
 *    _mix3_serverdesc_free.
 */
mix3_status_t _mix3_serverdesc_parse(
        mix3_serverdesc **serverdesc_out,
        char *string,
        int validate);

/* Deallocates a mix3_serverdesc. */
void _mix3_serverdesc_free(mix3_serverdesc *server);

/* Compares two nicknames lexically; returns -1,0,or 1.*/
int mix3_nickname_cmp(const char *name1, const char *name2);

/* Returns true iff name could be a valid nickname. */
int mix3_nickname_is_valid(const char *name);



/* ==================== */
/* Path-related functionality. */
/* ==================== */

/* Given a string describing a path (e.g., "Foo:Bar,?,Baz,*2,~1"),
 * returns a mix3_pathspec.
 *
 * Allocates: *path_out, which must be freed with mix3_pathspec_free.
 */
mix3_status_t mix3_path_parse_specifier(
        mix3_pathspec **path_out,
        char *path);

/* Frees a pathspec allocated by mix3_parse_path_specifier. */
void mix3_pathspec_free(mix3_pathspec *pathspec);

/* Generates a path from a mix3_pathspec.
 *
 * Arguments:
 *    path1_out, path2_out -- On success, *path1_out and *path2_out
 *        are NULL-terminated arrays of pointers to mix3_serverdescs
 *        from directory.
 *    directory -- A directory to use as a source of server
 *        descriptors.
 *    pathspec -- A description of the path to generate.
 *    address -- Optionally, the exit address to use.  If the exit
 *        address is a reply block, only path1_out is generated.
 *    single_leg -- If true, generate the path in a single leg (as for
 *        a SURB.)
 * Allocates: *path1_out and possibly *path2_out, which should be
 *     passed to mix3_free.
 **/
mix3_status_t mix3_path_generate(
        mix3_serverdesc ***path_out1,
        mix3_serverdesc ***path_out2,
        mix3_directory *directory,
        mix3_pathspec *pathspec,
        mix3_address_spec *opt_address,
        int single_leg);

/* ==================== */
/* Message-generation functionality */
/* ==================== */

/* A structure to hold a payload and decoding handle for a single
 * packet. */
typedef struct mix3_payload {
        char decoding_handle[20];
        char payload[28*1024];
} mix3_payload;
/* A structure to hold a complete 32KB packet.
 */
typedef struct mix3_packet {
        char packet[32*1024];
} mix3_packet;
/* A structure to specify a message header for a SMTP or NEWS message.
 */
typedef struct mix3_header_spec {
        enum { MIX3_HDR_FROM, MIX3_HDR_SUBJECT, MIX3_HDR_IN_REPLY_TO,
               MIX3_HEADER_REFERENCES } header;
        char *value;
} mix3_header_spec;

/* An opaque structure to represent a Type III SURB. */
typedef struct mix3_surb mix3_surb;

/* Generate a set of message payloads from a message, fragmenting,
 * compressing, and encoding the message as needed.
 *
 * Arguments:
 *    mix3_payload_out -- On success, *mix3_payload_out points to a
 *        newly allocated array of pointers to mix3_payload.
 *    n_payloads_out -- *n_payloads_out is set to the number of
 *        payloads allocated
 *    message -- the incoming message to encode.
 *    message_len -- The length of message, in bytes.
 *    address -- the destination address to which the message will be
 *        sent.
 *    headers -- an optional NULL-terminated array of mix3_header_spec.
 *
 * Allocates: *mix3_payload_out. Each element of *mix3_payload_out[]
 * should be passed to mix3_free, followed by *mix3_payload_out
 * itself.
 *
 * XXXX This fails if the message won't all fit into memory with the
 * payloads.  That's probably okay.
 */
mix3_status_t mix3_package_message(
      mix3_payload ***mix3_payload_out,
      int *n_payloads_out,
      const char *message,
      size_t message_len,
      mix3_address_spec *address,
      mix3_header_spec **headers);

/* Generate a single mix3_packet from a payload and a pair of paths.
 *
 * Arguments:
 *     packet_out -- On success, *packet_out points to newly
 *        allocated mix3_packet.
 *     path1 -- A NULL-terminated array of servers to use for the
 *        first leg of the path.
 *     path2_opt -- A NULL-termanated array of servers to use for the
 *        second leg of the path, or NULL if using a SURB.
 *     surb_opt -- A SURB to use for the final leg of the path, or
 *        NULL.
 *     address -- The destination for the packet.
 *     payload -- An encoded payload as returned by mix3_package_message
 *
 * Allocates: *mix3_packet, which should be passed to mix3_free.
 */
mix3_status_t mix3_generate_packet(
        mix3_packet **packet_out,
        mix3_serverdesc **path1,
        mix3_serverdesc **path2_opt,
        mix3_surb *surb_opt,
        mix3_address_spec *address,
        mix3_payload *payload);

/* ==================== */
/* SURB functionality */
/* ==================== */

/* A structure to hold a secret used to generate SURBs for an identity. */
typedef struct mix3_surb_secret {
        char secret[20];
} mix3_surb_secret;

/* Generate a SURB.
 *
 * Arguments:
 *    surb_out -- On success, *surb_out points to a newly allocated
 *        mix3_surb.
 *    path -- A NULL-terminated array of server desc pointers.
 *    address -- the exit address to use.
 *    valid_min,valid_max -- An interval during which the SURB should
 *        be usable.
 *    secret -- The secret for this SURB identity.
 *
 * Allocates: *surb_out, which must be freed with mix3_surb_free.
 */
mix3_status_t mix3_surb_generate(
        mix3_surb **surb_out,
        mix3_serverdesc **path,
        mix3_address_spec *address,
        time_t valid_min,
        time_t valid_max,
        mix3_surb_secret secret);

/* Write a SURB to a string.
 *
 * Arguments:
 *    surb_out -- A string buffer to receive a representation of the
 *        SURB.
 *    surb_out_len -- The available space in surb_out.
 *    surb -- the SURB to encode.
 *    binary -- Use a text encoding iff binary is false.
 */
mix3_status_t mix3_surb_to_string(
        char **surb_out,
        int surb_out_len,
        mix3_surb *surb,
        int binary);

/* Same as mix3_surb_to_string, but write to a stdio FILE. */
mix3_status_t mix3_surb_to_file(
        FILE *out,
        mix3_surb *surb,
        int binary);

/* Read a SURB from a string.
 *
 * Arguments:
 *    surb_out -- On success, *surb_out points to the parsed SURB.
 *    strp -- Before invocation, *strp points to the start of a SURB.
 *        After successful invocation, *strp points to immediately
 *        after the end of the parsed SURB.
 *    str_len -- *str_len is the number of bytes in *strp.
 *
 * Allocates: *surb_out, which should be freed by mix3_surb_free.
 */
mix3_status_t mix3_surb_from_string(
        mix3_surb **surb_out,
        char **strp,
        int *str_len);

/* Same as mix3_surb_from_file, but reads from a stdio FILE. */
mix3_status_t mix3_surb_from_file(
        mix3_surb **surb_out,
        FILE *file);

/* Deallocate a mix3_surb */
void mix3_surb_free(mix3_surb *surb);

/* XXXX Functions to access the rest of the SURB fields */

/* ==================== */
/* MMTP */
/* ==================== */

/* Opaque structure to represent an MMTP connection -- possibly
 * closed */
typedef struct mix3_mmtp_connection mix3_mmtp_connection;

/* Allocates a new mix3_mttp_connection to connect to a given
 * server.  Performs no network activity.
 *
 * Arguments:
 *    out -- On success, *out holds a newly allocated
 *        mix3_mmtp_connection.
 *    server -- The server to connect to.
 *    blocking -- Should operations on this connection be blocking?
 *        In nonblocking mode, other operations may return
 *        MIX3_WANTREAD or MIX3_WANTWRITE as status.
 *
 * Allocates: *mix3_mmtp_connection, which must be freed with
 *    mix3_mmtp_connection_free.
 */
mix3_status_t mix3_mmtp_new_connection(
        mix3_mmtp_connection **out,
        mix3_serverdesc *server,
        int blocking);
/* XXXX What to do about DNS, if we ever do DNS. */

/* Return the server descriptor associated with a connection.
 */
mix3_serverdesc *mix3_mmtp_connection_get_serverdesc(
        mix3_mmtp_connection *conn);

/* Return the filedes associated with a connection. */
int mix3_mmtp_connection_get_socket(mix3_mmtp_connection *conn);

/* Try to connect to an MMTP server and handshake with it. Return
 * MIX3_OK on success, MIX3_WANT* if a nonblocking connection would
 * block.
 */
mix3_status_t mix3_mmtp_connect(mix3_mmtp_connection *conn);

/* Send a packet to a connected MMTP server.  If the operation blocks,
 * it must be called again later with the same arguments.
 *
 * Return MIX3_OK on success, MIX3_WANT* if a nonblocking connection
 * would block.
 */
mix3_status_t mix3_mmtp_send_packet(mix3_mmtp_connection *conn,
                              mix3_packet *packet);

/* Send padding to a connected MMTP server.  If the operation blocks,
 * it must be called again later with the same arguments.
 *
 * Return MIX3_OK on success, MIX3_WANT* if a nonblocking connection
 * would block.
 */
mix3_status_t mix3_mmtp_send_padding(mix3_mmtp_connection *conn,
                               mix3_packet *padding);

/* Renegotiate a key with a connected MMTP server.  Returns as above.
 */
mix3_status_t mix3_mmtp_renegotiate(mix3_mmtp_connection *conn);

/* Shut down an MMTP connection.  Returns as above. */
mix3_status_t mix3_mmtp_close(mix3_mmtp_connection *conn);

void mix3_mmtp_connection_free(mix3_mmtp_connection *conn);

/* ==================== */
/* Decoding packets */
/* ==================== */

/* Opaque structure holding a decoded (but not yet decompressed or
 * reassembled) packet. */
typedef struct mix3_decoded_packet mix3_decoded_packet;

/* Decode a single type III packet.
 *
 * Arguments:
 *    packet_out -- On success, *packet_out holds a freshly allocated
 *        mix3_decoded_packet.
 *    inp -- An input string to read a packet payload from.  Advanced
 *        on success.
 *    inp_len -- The length of the input string.  Decremented on
 *        success.
 *    is_text -- Flag: is the input ascii-armored.
 *    keys -- NULL-terminated array of secret keys to try decrypting with.
 *    secrets -- NULL-terminated array of SURB secrets to try
 *        decrypting with.
 *
 * Allocates: mix3_decoded_packet, which must be freed with
 *     mix3_decoded_packet_free.
 */
mix3_status_t mix3_packet_decode(mix3_decoded_packet **packet_out,
                               const char **inp,
                               int *inp_len,
                               int is_text,
                               RSA **keys,
                               mix3_surb_secret **secrets);

/* Return true iff pkt is a fragment. */
int mix3_decoded_packet_is_fragment(mix3_decoded_packet *pkt);
/* Return true iff packet was unencrypted */
int mix3_decoded_packet_was_plaintext(mix3_decoded_packet *pkt);
/* If pkt was encrypted with a surb, return the index of the identity
 * key among the array of secrets passed to mix3_packet_decode.
 * Otherwise return -1. */
int mix3_decoded_packet_reply_idx(mix3_decoded_packet *pkt);
/* If pkt was encrypted with a public key, return the index of the
 * secret key key among the array of secret keys passed to
 * mix3_packet_decode.  Otherwise return -1. */
int mix3_decoded_packet_key_idx(mix3_decoded_packet *pkt);

/* Struct to hold a message ID for a fragmented message.
 */
typedef struct mix3_fragment_message_id {
  char id[20];
} mix3_fragment_message_id;

/* Identity of a fragment within a fragmented message */
typedef unsigned long mix3_fragment_fragment_id;

/* Return the length of the (compressed) message corresponding to
 * pkt. */
size_t mix3_decoded_packet_get_length(mix3_decoded_packet *pkt);
/* Gets the message id for a fragment in pkt. */
mix3_status_t mix3_decoded_fragment_get_mid(mix3_fragment_message_id *out,
                                          mix3_decoded_packet *pkt);
/* Gets the fragment id for a fragment in pkt. */
mix3_fragment_fragment_id mix3_decoded_fragment_get_fid(
                                          mix3_decoded_packet *pkt);
/* Extracts a message from a singleton packet.
 * XXXX DOCDOC
 */
mix3_status_t mix3_decoded_packet_get_msg(char *message_out,
                                        int message_out_len,
                                        mix3_decoded_packet *pkt);

/* Extracts a message from a set of packets.
 * XXXX DOCDOC
 */
mix3_status_t mix3_decoded_fragments_get_msg(char *message_out,
                                           int message_out_len,
                                           int n_fragments,
                                           mix3_decoded_packet **fragments);

void mix3_free_decoded_packet(mix3_decoded_packet *pkt);

#ifdef __cplusplus
}
#endif

#endif /* _MIX3_H */
