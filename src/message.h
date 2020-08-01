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
#ifndef GPDGC_MESSAGE_H_INCLUDED
#define GPDGC_MESSAGE_H_INCLUDED

#include <glib.h>
#include <gcrypt.h>
#include <sys/socket.h>

/******************************************************************************
 * message.h defines the messages, i.e, any information exchanged between at
 *  least two processes, considered in GPDGC
 *****************************************************************************/

#define GPDGC_RELIABLE_MESSAGE_TYPE            1
#define GPDGC_ATOMIC_MESSAGE_TYPE              2
#define GPDGC_ADD_SERVER_MESSAGE_TYPE          3 
#define GPDGC_REMOVE_SERVER_MESSAGE_TYPE       4
#define GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE  5
#define GPDGC_ADD_CLIENT_MESSAGE_TYPE          6 
#define GPDGC_REMOVE_CLIENT_MESSAGE_TYPE       7
#define GPDGC_ACK_MESSAGE_TYPE                 8 
#define GPDGC_CLEAN_CACHE_MESSAGE_TYPE         9
#define GPDGC_EXCLUDED_MESSAGE_TYPE           10

#define GPDGC_CANDIDATE_MESSAGE_TYPE         100
#define GPDGC_INFORMATION_MESSAGE_TYPE       101
#define GPDGC_ACK_INFORMATION_MESSAGE_TYPE   102
#define GPDGC_SUBSCRIPTION_MESSAGE_TYPE      103
#define GPDGC_ACK_SUBSCRIPTION_MESSAGE_TYPE  104
#define GPDGC_NACK_SUBSCRIPTION_MESSAGE_TYPE 105
#define GPDGC_CLIENT_REPLY_MESSAGE_TYPE      106
#define GPDGC_ACK_CLIENT_REPLY_MESSAGE_TYPE  107

#define GPDGC_HEARDOF_MESSAGE_TYPE           200
#define GPDGC_BROADCAST_MESSAGE_TYPE         201

#define GPDGC_UNKNOWN_MESSAGE_TYPE           999

#define GPDGC_READY_MESSAGE_FLAG               1
#define GPDGC_RECEIVED_MESSAGE_FLAG            2

#define GPDGC_MESSAGE_SIGNATURE_SIZE         546


/* Message */
typedef struct
{
    GSList *contents;
} gpdgc_message;

/* Get the memory cost of a message */
size_t gpdgc_get_message_cost();
/* Get the memory cost of an item in a message */
size_t gpdgc_get_message_item_cost();

/* Create a message */
gpdgc_message *gpdgc_create_message();
/* Clone a message */
gpdgc_message *gpdgc_clone_message(gpdgc_message *msg);
/* Free the memory occupied by the specified message */
void gpdgc_free_message(void *msg);

/* Get the number of contents in a message */
unsigned int gpdgc_get_message_length(gpdgc_message *msg);
/* Get the size of the message in memory */ 
size_t gpdgc_get_message_size(gpdgc_message *msg);

/* Extract a message sent by the specified sender from a buffer */
gpdgc_message *gpdgc_extract_contents(void *buffer, size_t size);
/* Write the contents of the specified message in a buffer */
void *gpdgc_write_contents(gpdgc_message *msg, gcry_sexp_t key, size_t *size);

/* Compare message contents */
int gpdgc_cmp_message(gpdgc_message *first, gpdgc_message *second);

/* Push a copy of the specified content to the specified message */
int gpdgc_push_content(gpdgc_message *msg, void *content, size_t size);
/* Get the size of the i-th content of the specified message */
size_t gpdgc_get_content_size(gpdgc_message *msg, int i);
/* Peek the i-th content (as a sock address) of the specified message */
struct sockaddr *gpdgc_peek_address(gpdgc_message *msg, int position);
/* Pop the first content (as a sock address) of the specified message */
struct sockaddr *gpdgc_pop_address(gpdgc_message *msg);
/* Peek the i-th content of the specified message */
void *gpdgc_peek_content(gpdgc_message *msg, int i, size_t *size); 
/* Pop the first content of the specified message */
void *gpdgc_pop_content(gpdgc_message *msg, size_t *size);

/* Push a copy of the specified S-Expression to the specified message */
int gpdgc_push_gcry_sexp(gpdgc_message *msg, gcry_sexp_t expression);
/* Peek the i-th content (a S-Expression) of the specified message */
gcry_sexp_t gpdgc_peek_gcry_sexp(gpdgc_message *msg, int position);
/* Pop the first content (a S-Expression) of the specified message */
gcry_sexp_t gpdgc_pop_gcry_sexp(gpdgc_message *msg);

/* Sign the specified message with the specified private key; the signature 
 *  being pushed to the message */
int gpdgc_sign_message(gpdgc_message *msg, gcry_sexp_t private_key);
/* Pop the signature from the specified message, and check that 
 *  the signature is valid regarding the message and specified public key */
int gpdgc_unsign_message(gpdgc_message *msg, gcry_sexp_t public_key);
#endif
