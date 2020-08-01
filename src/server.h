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
#ifndef GPDGC_SERVER_H_INCLUDED
#define GPDGC_SERVER_H_INCLUDED

#include <gcrypt.h>
#include <glib.h>
#include <sys/socket.h>

#include "common.h"
#include "gpdgc.h"
#include "message.h"

/******************************************************************************
 * server.h defines types and methods internal to the implementation of GPDGC
 *****************************************************************************/

/* Process types */
typedef enum
{
    GPDGC_CLIENT = 0,
    GPDGC_SERVER = 1
} gpdgc_process_type;

/* Process states */
typedef enum
{
    GPDGC_ACTIVE   = 0,
    GPDGC_INACTIVE = 1
} gpdgc_process_state;

/* Heardof messages */
typedef struct
{
    unsigned short flags; 
    gpdgc_message *message;
    gpdgc_message *decision;

    unsigned int counter;
    GSList *votes;
} gpdgc_round;

/* Processes managed by GPDGC servers */
typedef struct
{
    struct sockaddr *address;
    gpdgc_process_type type;
    gpdgc_process_state state;
    char *label;

    gcry_sexp_t public_key;

    unsigned long phase;
    unsigned long round;
    unsigned long step;
    unsigned short suspiscion_flags;

    gpdgc_round *current;
    GSList *futures;
    GSList *replies;

    unsigned long sequence_number;
    GSList *undelivered_containers;
    GSList *delivered_containers;

    unsigned short last_view_aware; 
    unsigned short excluded_from_view;
    unsigned long removal_phase;
} gpdgc_process;

/* Messages broadcasted to GPDGC servers */
typedef struct
{
    gpdgc_process *owner;

    unsigned short flags;
    unsigned short last_container_resend;

    gpdgc_message *content;
    unsigned long phase;
} gpdgc_container_state;
typedef struct
{
    unsigned long sequence_number;
    unsigned short flags;
    
    GSList *states;

    unsigned short remaining_ticks;

    unsigned short content_type;
    gpdgc_message *content;
    unsigned long delivery;

    void *content_cache;
    size_t content_size;

    void *phase_cache;
    size_t phase_size;
} gpdgc_container;

/* Messages corresponding to future rounds Heardof messages */
typedef struct
{
    unsigned long phase;
    unsigned long round;
    unsigned long step;

    gpdgc_message *message;
} gpdgc_future; 

/* Messages send by application to clients */
typedef struct
{
    unsigned long id;
    unsigned short remaining_ticks;

    void *cache;
    size_t size;
} gpdgc_reply;

/* GPDGC servers */
typedef struct 
{
    /* Algorithm configuration */
    gpdgc_process_fault_model process_model;
    gpdgc_channel_fault_model channel_model;
    gpdgc_validation_type validation;
    gpdgc_election_type election;

    /* Limits configuration */
    unsigned short max_clients;
    unsigned short max_client_replies;
    unsigned short max_servers;
    unsigned short max_futures;
    unsigned short max_slot;
    unsigned short max_retention_cache;
    unsigned long max_cache;
    size_t max_message_size;    

    /* Periodic events configuration */
    unsigned int tick_length;
    unsigned short clean_cache_period;
    unsigned short clock_period;
    unsigned short resend_period;
    unsigned short minimal_resend_period;
    unsigned long round_period_initial;
    unsigned long round_period_increment;

    /* State variables */
    unsigned short used_slot;
    unsigned long used_cache;
    gpdgc_state state;
    
    /* Network variables */
    int socket; 
    pthread_t input_thread;
    char *input_buffer;
    int input_length; 
    struct sockaddr *input_address;

    /* Reliability (re-sending messages) variables */
    pthread_t resend_thread; 
        
    unsigned short clean_cache_remaining_ticks;

    void *clock_cache;
    size_t clock_cache_size;
    unsigned short clock_remaining_ticks;

    void *init_view_cache;
    size_t init_view_cache_size;
    unsigned short init_view_remaining_ticks;

    unsigned long view_info_identifier;
    void *view_info_cache;
    size_t view_info_cache_size;
    unsigned short view_info_remaining_ticks;    

    /* Processes variables */
    gpdgc_process *local;
    gcry_sexp_t private_key;
    unsigned long view_identifier;
    gcry_sexp_t trusted_key;
    unsigned long trusted_key_identifier;

    GSList *expected_view;
    GSList *view_candidates;
    GSList *key_candidates;
    GSList *previouses;

    GSList *clients;
    GSList *client_candidates;
    GSList *client_exclusions;
    pthread_t client_thread;

    GSList *servers;
    GSList *server_candidates;
    GSList *server_candidate_keys; 
    GSList *server_exclusions;

    /* Lock variables */
    pthread_mutex_t lock;
    pthread_cond_t client_condition;
    pthread_cond_t input_condition;
    pthread_cond_t output_condition;
    pthread_cond_t slot_condition;
    pthread_cond_t state_condition;
    
    /* Heardof variables */
    unsigned short round_flags;
    unsigned long step_remaining_ticks;

    /* Consensus variables */
    GSList *coordinator;
    unsigned short selection_flags;

    void *vote;
    size_t vote_size;
    unsigned long vote_ts;
    GSList *vote_history;

    GSList *previous_decisions;
    
    /* Broadcast variables */
    unsigned long *current_decision;
    unsigned long next_phase;
    unsigned long next_sequence_number;

    /* Callback methods and variables */
    gpdgc_output *out_of_memory;
    GSList *outputs; 
    pthread_t output_thread;

    void (*adeliver) (struct sockaddr *sender, unsigned long id,
            void *message, size_t size);
    void (*rdeliver) (struct sockaddr *sender, unsigned long id,
            void *message, size_t size);
    void (*inform) (gpdgc_event event); 
} gpdgc_iserver;

/* Return the key that is used to send message over channels */
gcry_sexp_t gpdgc_get_channel_key(gpdgc_iserver *server);
/* Set the trusted key */
int gpdgc_set_trusted_key(gpdgc_iserver *server,
        gcry_sexp_t key, unsigned long identifier);

/* Get the maximum number of byzantine servers that are allowed */
unsigned int gpdgc_get_max_byzantine(gpdgc_iserver *server);
/* Get the maximum number of faulty servers that are allowed */
unsigned int gpdgc_get_max_faulty(gpdgc_iserver *server);

/* Return true if servers may use signatures to prove honesty */
int gpdgc_has_certified_servers(gpdgc_iserver *server);
/* Return true if channels can be corrupted */ 
int gpdgc_has_corrupted_channels(gpdgc_iserver *server);
/* Return true if servers can be byzantine */
int gpdgc_is_byzantine_model(gpdgc_iserver *server);

/* Method being called each time a thread enters the stack */
void gpdgc_enter_stack(gpdgc_iserver *server);
/* Method being called each time a thread sending messages enters the stack */
void gpdgc_enter_stack_when_enough_slot(gpdgc_iserver *server);
/* Method being called each time a thread leaves the stack */
void gpdgc_leave_stack(gpdgc_iserver *server);

/* Reserve the specified amount of message slots */
void gpdgc_reserve_slot(gpdgc_iserver *server, unsigned short nb_slot);
/* Release the specified amount of message slots */
void gpdgc_release_slot(gpdgc_iserver *server, unsigned short nb_slot);

/* Reserve the specified amount of cache */
void gpdgc_reserve_cache(gpdgc_iserver *server, unsigned long amount);
/* Release the specified amount of cache */
void gpdgc_release_cache(gpdgc_iserver *server, unsigned long amount);

/* Signal event to the server */
void gpdgc_signal_event(gpdgc_iserver *server, gpdgc_event event);
/* Method being called each time a lack of memory prevents the stack from
 *  being executed normally */
void gpdgc_signal_lack_of_memory(gpdgc_iserver *server, char *message, ...);

/* Method being called when the local state has been changed */
void gpdgc_signal_state_change(gpdgc_iserver *server, gpdgc_state state);
/* Wait until the local state has been changed */
void gpdgc_wait_state_change(gpdgc_iserver *server, gpdgc_state state);

/* Free the memory occupied by heardof rounds */
void gpdgc_free_round(void *round);
void gpdgc_partial_free_round(void *round);
/* Free the memory occupied by a broadcast messages */ 
void gpdgc_free_container_state(void *state);
void gpdgc_free_container(void *container);
/* Free the memory occupied by a future heardof messages */
void gpdgc_free_future(void *future);
/* Free the memory occupied by information to be delivered to application */
void gpdgc_free_output(void *output);
/* Free the memory occupied by replies to client */
void gpdgc_free_reply(void *reply);
/* Free the memory occupied by a process */
void gpdgc_free_process(void *process);

/* Method to stop internally the server */
void gpdgc_internally_close_server(gpdgc_iserver *server);

/* Deliver a network message to the server */
void gpdgc_deliver_to_server(gpdgc_iserver *server,
        void *buffer, size_t size, struct sockaddr *address);
/* Deliver ordered or non-ordered messages to the server */
void gpdgc_deliver_broadcast_message(gpdgc_iserver *server, unsigned long id, 
        unsigned short type, gpdgc_message *message, gpdgc_process *origin);
#endif
