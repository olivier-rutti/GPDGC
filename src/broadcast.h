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
#ifndef GPDGC_BROADCAST_H_INCLUDED
#define GPDGC_BROADCAST_H_INCLUDED

#include <glib.h>
#include <gcrypt.h>
#include <pthread.h>
#include <sys/socket.h>

#include "message.h"
#include "server.h"

/******************************************************************************
 * broadcast.h implements the general broadcast protocol which allows processes
 *  to broadcast non-ordered or ordered messages to specific group of processes
 *****************************************************************************/

#define GPDGC_READY_STATE_FLAG           1
#define GPDGC_RECEIVED_STATE_FLAG        2
#define GPDGC_COHERENT_STATE_FLAG        4
#define GPDGC_PHASED_STATE_FLAG          8

#define GPDGC_INIT_CONTAINER_FLAG        1 
#define GPDGC_READY_CONTAINER_FLAG       2
#define GPDGC_COHERENT_CONTAINER_FLAG    4
#define GPDGC_ORDERED_CONTAINER_FLAG     8
#define GPDGC_DELIVERED_CONTAINER_FLAG  16

/* Add a state for the specified owner to the specified container */
int gpdgc_add_container_state(gpdgc_container *container, gpdgc_process *owner);
/* Build the buffer corresponding to an empty message */
void *gpdgc_build_empty_message(gpdgc_iserver *server, gpdgc_process *origin, 
        unsigned long sn, unsigned short type, int received, size_t *size);

/* Issue the specified reply to the specified client */
int gpdgc_send_client_reply(gpdgc_iserver *server, unsigned long id,
        void *message, size_t size, gpdgc_process *client);
/* Broadcast message of the specified type (reliable, ordered or view change) */ 
int gpdgc_broadcast_group_message(gpdgc_iserver *server,
        gpdgc_message *message, unsigned short msg_type);

/* Process the specified decision of the specified phase */
void gpdgc_deliver_decision(gpdgc_iserver *server,
        unsigned long phase, unsigned long *values);
/* Deliver a transport message to broadcast protocol */
void gpdgc_deliver_to_broadcast(gpdgc_iserver *server,
        gpdgc_message *message, gpdgc_process *sender);
#endif
