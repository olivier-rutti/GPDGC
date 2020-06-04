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
#ifndef GPDGC_CLIENT_H_INCLUDED
#define GPDGC_CLIENT_H_INCLUDED

#include <gcrypt.h>
#include <glib.h>
#include <sys/socket.h>

#include "common.h"
#include "gpdgc.h"
#include "message.h"

/******************************************************************************
 * client.h provides methods to interact with a specific group of processes
 *****************************************************************************/

/* Messages issued to servers */
typedef struct
{
    unsigned long sequence_number;

    unsigned short remaining_ticks;
    GSList *remaining_servers;

    void *cache;
    size_t size;
} gpdgc_pending;

/* Servers considered by a client */
typedef struct
{
    struct sockaddr *address;
    gcry_sexp_t public_key;

    unsigned short suspiscion_flags;
} gpdgc_view_server;
typedef struct
{
    struct sockaddr *address;
    gcry_sexp_t public_key;

    unsigned short suspiscion_flags;
    unsigned short nb_crash_suspecters;
    unsigned short nb_byzantine_suspecters;

    unsigned long sequence_number;

    unsigned long view_identifier; 
    GSList *view;

    unsigned long trusted_key_identifier; 
    gcry_sexp_t trusted_key;
} gpdgc_server_info;

/* Server replies */
typedef struct
{
    unsigned long sequence_number;
    unsigned short delivered;

    GSList *voters;
    GSList *contents;
    GSList *sizes;
} gpdgc_server_reply;

/* GPDGC clients */ 
typedef struct
{
    /* Algorithm configuration */
    gpdgc_process_fault_model process_model;
    gpdgc_channel_fault_model channel_model;
    gpdgc_validation_type validation;

    /* Client configuration */
    struct sockaddr *address;
    gcry_sexp_t public_key;
    gcry_sexp_t private_key;

    /* Limits configuration */
    unsigned short max_pending_messages;
    unsigned short max_pending_replies;
    unsigned int max_message_size;

    /* Periodic events configuration */
    unsigned int tick_length;
    unsigned short resend_period;

    /* State variables */
    gpdgc_state state;
    unsigned long view_identifier;
    GSList *infos;
    unsigned short trusted_key_initialised;
    unsigned long trusted_key_identifier; 
    gcry_sexp_t trusted_key;
    GSList *refusings;

    /* Network variables */
    int socket; 
    pthread_t input_thread;
    char *input_buffer;
    int input_length; 
    struct sockaddr *input_address;

    /* Reliability (re-sending messages) variables */
    pthread_t resend_thread; 

    /* Lock variables */
    pthread_mutex_t lock;
    pthread_cond_t input_condition;
    pthread_cond_t output_condition;
    pthread_cond_t pending_condition;
    pthread_cond_t state_condition;

    /* Messages variables */
    unsigned long next_sequence_number;
    GSList *messages;
    GSList *replies;

    /* Callback methods and variables */
    GSList *outputs; 
    pthread_t output_thread;

    void (*deliver) (unsigned long id, void *message, size_t size);
    void (*inform) (gpdgc_event event);
} gpdgc_iclient;

/* Method being called each time a thread enters the client */
void gpdgc_enter_client(gpdgc_iclient *client);
/* Method being called each time a thread sending messages enters the client */
void gpdgc_enter_client_when_few_pending(gpdgc_iclient *client);
/* Method being called each time a thread leaves the client */
void gpdgc_leave_client(gpdgc_iclient *client);

/* Method being called when the local state has been changed */
void gpdgc_signal_client_change(gpdgc_iclient *client, gpdgc_state state);
/* Wait until the local state has been changed */
void gpdgc_wait_client_change(gpdgc_iclient *client, gpdgc_state state);

/* Deliver a network message to the client */
void gpdgc_deliver_to_client(gpdgc_iclient *client, 
        void *buffer, size_t size, struct sockaddr *sender);
#endif
