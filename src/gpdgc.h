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
#ifndef GPDGC_MAIN_H_INCLUDED
#define GPDGC_MAIN_H_INCLUDED

#include <gcrypt.h>
#include <glib.h>
#include <sys/socket.h>

/******************************************************************************
 * Libgpdgc is a library providing group communication abstractions that are
 *  tolerant to byzanzine faults (e.g., malicious processes).
 *****************************************************************************/

/* The group communication server */
typedef void *gpdgc_server;

/* The group communication client */
typedef void *gpdgc_client;

/* Fault model types */
typedef enum
{
    GPDGC_CRASH_STOP_MODEL = 0,
    GPDGC_BYZANTINE_MODEL  = 1
} gpdgc_process_fault_model;
typedef enum
{
    GPDGC_SECURE_MODEL    = 0,
    GPDGC_CORRUPTED_MODEL = 1
} gpdgc_channel_fault_model;

/* The possible event regarding the group communication system; 
 *  each event corresponding to a specific additionnal informations */
typedef enum
{
    GPDGC_NEW_TRUSTED_KEY = 0,
    GPDGC_OUT_OF_MEMORY   = 1,
    GPDGC_SUSPISCION      = 2,
    GPDGC_VIEW_EXCLUSION  = 3,
    GPDGC_VIEW_INIT       = 4,
    GPDGC_VIEW_UPDATE     = 5,
} gpdgc_event;

/* Consensus validation types */
typedef enum
{
    GPDGC_NO_VALIDATION      = 0,
    GPDGC_AMNESIC_VALIDATION = 1,
    GPDGC_FULL_VALIDATION    = 2
} gpdgc_validation_type;

/* Consensus election types */
typedef enum
{
    GPDGC_ROTATING_COORDINATOR = 0,
    GPDGC_NO_ELECTION          = 1
} gpdgc_election_type;

/* Get the memory required by a server with the specified paramters */
size_t gpdgc_get_server_size(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model,
        gpdgc_validation_type validation, int certified_servers,
        unsigned int max_servers, unsigned int max_clients,
        unsigned short max_slot, unsigned long max_cache,
        unsigned int max_futures, unsigned short max_client_replies,
        size_t max_message_size, unsigned int network_buffer_size);

/* Create a group communication server */
gpdgc_server gpdgc_create_server(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model,
        gpdgc_validation_type validation, gpdgc_election_type election,
        struct sockaddr *self, gcry_sexp_t private_key, gcry_sexp_t public_key,
        unsigned short max_servers, unsigned short max_clients,
        unsigned short max_slot, unsigned long max_cache,
        unsigned short max_retention_cache, unsigned int max_futures,
        unsigned short max_client_replies, size_t max_message_size,
        unsigned int network_buffer_size, unsigned int tick_length,
        unsigned short clock_period, unsigned short clean_cache_period,
        unsigned short minimal_resend_period, unsigned short resend_period,
        unsigned long round_window_initial,
        unsigned long round_window_increment,
        void (*adeliver) (struct sockaddr *origin, unsigned long id,
            void *message, size_t size),
        void (*rdeliver) (struct sockaddr *origin, unsigned long id,
            void *message, size_t size),
        void (*inform) (gpdgc_event event));
/* Close a group communication server */
void gpdgc_close_server(gpdgc_server server);

/* Get the current clients */
GSList *gpdgc_get_current_clients(gpdgc_server server);
/* Get the current view */
GSList *gpdgc_get_current_view(gpdgc_server server);
/* Set the initial view */
int gpdgc_init_view(gpdgc_server server,
        GSList *addresses, GSList *keys, gcry_sexp_t trusted_key);
/* Wait until the server has integrated the view */
int gpdgc_integrate_view(gpdgc_server server, GSList *view);
/* Get the server suspected to be crashed */
GSList *gpdgc_get_byzantine_suspiscions(gpdgc_server server);
/* Get the server suspected to be byzantine */
GSList *gpdgc_get_crash_suspiscions(gpdgc_server server);

/* Send reliable and totally ordered messages from a server */
int gpdgc_atomic_broadcast(gpdgc_server server, void *message, size_t size);
/* Send reliable messages from a server */
int gpdgc_reliable_broadcast(gpdgc_server server, void *message, size_t size);

/* Send a message to a client as a response to the previous request 'id' */
int gpdgc_send_reply_to_client(gpdgc_server server, unsigned long id,
        void *message, size_t size, struct sockaddr *client);


/* Get the memory required by a client with the specified paramters */
size_t gpdgc_get_client_size(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model, int certified_servers,
        unsigned int max_servers, unsigned short max_pending_messages,
        unsigned short max_pending_replies, size_t max_message_size,
        unsigned int network_buffer_size);

/* Create a group communication client */
gpdgc_client gpdgc_create_client(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model,
        gpdgc_validation_type validation, struct sockaddr *self,
        gcry_sexp_t private_key, gcry_sexp_t public_key,
        unsigned short max_servers, unsigned short max_pending_messages,
        unsigned short max_pending_replies, size_t max_message_size,
        unsigned int network_buffer_size, unsigned int tick_length,
        unsigned short resend_period,
        void (*deliver) (unsigned long id, void *message, size_t size),
        void (*inform) (gpdgc_event event));
/* Close a group communication client */
void gpdgc_close_client(gpdgc_client client);

/* Wait until the client has subscribed to the view */
int gpdgc_subscribe_to_view(gpdgc_client client, GSList *servers, GSList *keys);
/* Wait until the client is no more subscribed to the view */
int gpdgc_unsubscribe_from_view(gpdgc_client client);

/* Get the current view */
GSList *gpdgc_get_current_observed_view(gpdgc_client client);
/* Get the client suspected to be crashed */
GSList *gpdgc_get_observed_byzantine_suspiscions(gpdgc_client client);
/* Get the client suspected to be byzantine */
GSList *gpdgc_get_observed_crash_suspiscions(gpdgc_client client);

/* Send reliable and totally ordered messages from a client */
int gpdgc_atomic_multicast(gpdgc_client client,
        void *message, size_t size, unsigned long *reply_id);
/* Send reliable messages from a client */
int gpdgc_reliable_multicast(gpdgc_client client, 
        void *message, size_t size, unsigned long *reply_id);

/* Add process to the current view */
int gpdgc_add_to_view(gpdgc_client client, 
        struct sockaddr *address, gcry_sexp_t key, gcry_sexp_t trusted_key);
/* Remove process from the current view */
int gpdgc_remove_from_view(gpdgc_client client,
        struct sockaddr *address, gcry_sexp_t trusted_key);
/* Update the key trusted by the server */
int gpdgc_update_trusted_key(gpdgc_client client,
        gcry_sexp_t new_key, gcry_sexp_t trusted_key);
#endif
