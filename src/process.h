/*
 * This file is part of the GNU Practical Dynamic Group Communication (GPDGC)
 * Copyright (C) 2020, Rütti Olivier <olivier.rutti@opengroupware.ch>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GPDGC_PROCESS_H_INCLUDED
#define GPDGC_PROCESS_H_INCLUDED

#include <glib.h>
#include <gcrypt.h>
#include <sys/socket.h>

#include "message.h"
#include "server.h"

/******************************************************************************
 * process.h provides methods to manage the processes considered by servers
 *****************************************************************************/

/* Client candidate */
typedef struct
{
    struct sockaddr *client;
    gcry_sexp_t key;

    GSList *voters;
    GSList *keys;

    short status;
    unsigned short remaining_ticks;

    void *feedback;
    size_t size;
} gpdgc_client_candidate;

 /* View candidate */
typedef struct
{
    GSList *servers;
    GSList *server_keys;
    GSList *server_seq_numbers;

    GSList *clients;
    GSList *client_keys;
    GSList *client_seq_numbers;

    unsigned long phase;
    unsigned long view_identifier;
    unsigned long trusted_key_identifier;
    gcry_sexp_t trusted_key;

    GSList *voters;
} gpdgc_view_candidate;

/* Free the memory occupied by a client candidate */ 
void gpdgc_free_client_candidate(void *candidate);
/* Free the memory occupied by a view candidate */
void gpdgc_free_view_candidate(void *candidate);

/* Remove from the cache everything that is no more needed to ensure that
 * each honest server in current view eventually delivers the messages sent */
void gpdgc_clean_cache(gpdgc_iserver *server);
/* Compare the specified process */
int gpdgc_cmp_process(gpdgc_process *first, gpdgc_process *second);
/* Create the process corresponding to the specified address */
gpdgc_process *gpdgc_create_process(struct sockaddr *address,
        gpdgc_process_type type, gcry_sexp_t public_key, 
        unsigned long sequence_number);
/* Get the process corresponding to the specified process address */
gpdgc_process *gpdgc_get_process(gpdgc_iserver *server, struct sockaddr *address);
/* Get the process corresponding to the specified process address */
gpdgc_process *gpdgc_get_server(gpdgc_iserver *server, struct sockaddr *address);
/* Find a server that is synchronized with the distributed clock */
gpdgc_process *gpdgc_get_synchronized_server(gpdgc_iserver *server);
/* Build a message with all information about the current view */
gpdgc_message *gpdgc_get_view_info_message(gpdgc_iserver *server);

/* Remove the server with the specified address */
void gpdgc_remove_server(gpdgc_iserver *server, struct sockaddr *address);
/* Remove the client with the specified address */
int gpdgc_remove_client(gpdgc_iserver *server, struct sockaddr *address);

/* Multicast the specified message to clients */
int gpdgc_udp_client_multicast(gpdgc_iserver *server, void *msg, size_t size);
/* Multicast the specified message to other servers */
int gpdgc_udp_server_multicast(gpdgc_iserver *server, void *msg, size_t size);

/* Broadcast client candidate */
int gpdgc_broadcast_client_subscription(gpdgc_iserver *server, 
        gpdgc_client_candidate *candidate);
/* Initiate client candidate */
void gpdgc_initiate_client_candidate(gpdgc_iserver *server,
        gpdgc_message *message, struct sockaddr *sender);
/* Deliver vote for client candidate */
void gpdgc_deliver_client_candidate_vote(gpdgc_iserver *server,
        struct sockaddr *client, gcry_sexp_t key, gpdgc_process *voter);
/* Close client candidate */
void gpdgc_close_client_candidate(gpdgc_iserver *server, struct sockaddr *clt);

/* Apply view change */
void gpdgc_apply_pending_view_changes(gpdgc_iserver *server);
/* Set initial view */
int gpdgc_set_initial_view(gpdgc_iserver *server,
        GSList *servers, GSList *server_pks, GSList *server_sns,
        GSList *clients, GSList *client_pks, GSList *client_sns,
        unsigned long phase, unsigned long view_id);
/* Set expected view */
void gpdgc_set_expected_view(gpdgc_iserver *server, GSList *view);
/* Deliver view candidate */
void gpdgc_deliver_view_candidate(gpdgc_iserver *server, 
        gpdgc_message *message, struct sockaddr *sender);

/* Deliver the phase before which cache can be clean according to a server */
void gpdgc_deliver_clean_cache(gpdgc_iserver *server,
        unsigned long phase, gpdgc_process *origin);
#endif
