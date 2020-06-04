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
#include <unistd.h>

#include "client.h"
#include "message.h"

/* Get the maximum number of faulty servers that are allowed */
unsigned int gpdgc_get_expected_max_faulty(gpdgc_iclient *client)
{
    short is_byzantine = client->process_model == GPDGC_BYZANTINE_MODEL;

    unsigned int divider = 5;
    switch (client->validation)
    {
        case GPDGC_NO_VALIDATION:
            divider = is_byzantine ? 5 : 3;
            break;
        case GPDGC_AMNESIC_VALIDATION:
            divider = is_byzantine ? 4 : 2;
            break;
        case GPDGC_FULL_VALIDATION:
            divider = is_byzantine ? 3 : 2;
            break;
        default:
            g_critical("%-10s: Unknown validation !", "CLIENT");
    }
    return (g_slist_length(client->infos) - 1) / divider; 
}

/* Get the maximum number of byzantine servers that are allowed */
unsigned int gpdgc_get_expected_max_byzantine(gpdgc_iclient *client)
{
    short is_byzantine = client->process_model == GPDGC_BYZANTINE_MODEL;

    return is_byzantine ? gpdgc_get_expected_max_faulty(client) : 0;
}


/* Method being called each time a thread enters the stack */
void gpdgc_enter_client(gpdgc_iclient *client)
{
    pthread_mutex_lock(&client->lock);
}

/* Method being called each time a thread sending messages enters the client */
void gpdgc_do_conditional_enter_client(gpdgc_iclient *client,
        unsigned int max_pending_messages)
{
    gpdgc_enter_client(client);
    while (g_slist_length(client->messages) >= max_pending_messages)
    {
        pthread_cond_wait(&client->pending_condition, &client->lock);
    }
}
void gpdgc_enter_client_when_few_pending(gpdgc_iclient *client)
{
    gpdgc_do_conditional_enter_client(client, client->max_pending_messages);
}
void gpdgc_enter_client_when_no_pending(gpdgc_iclient *client)
{
    gpdgc_do_conditional_enter_client(client, 1);
}

/* Method being called each time a thread generating output enters the client */
void gpdgc_enter_client_when_few_output(gpdgc_iclient *client)
{
    unsigned long max_pending_outputs = client->max_pending_replies * 3;

    gpdgc_enter_client(client);
    while (g_slist_length(client->outputs) >= max_pending_outputs)
    {
        pthread_cond_wait(&client->input_condition, &client->lock);
    }
}

/* Method being called each time a thread leaves the stack */
void gpdgc_leave_client(gpdgc_iclient *client)
{
    pthread_mutex_unlock(&client->lock); 
}


/* Method being called when the local state has been changed */
void gpdgc_signal_client_change(gpdgc_iclient *client, gpdgc_state state)
{
    client->state = state;
    pthread_cond_broadcast(&client->state_condition);
}

/* Wait until the local state has been changed */
void gpdgc_wait_client_done(gpdgc_iclient *client, int expect_also_ready) 
{
    while ((client->state != GPDGC_DONE)
            && ((!expect_also_ready) || (client->state != GPDGC_READY)))
    {
        pthread_cond_wait(&client->state_condition, &client->lock);
    }
}


/* Get the memory/network buffer required using with the specified paramters */
size_t gpdgc_get_client_network_buffer_size(unsigned int nb_servers,
        size_t max_message_size)
{
    size_t reply_size = max_message_size + sizeof(unsigned long) 
        + sizeof(unsigned short) + GPDGC_MESSAGE_SIGNATURE_SIZE
        + 4 * sizeof(size_t);

    size_t ip_cost = gpdgc_get_max_address_size();
    size_t info_size = sizeof(unsigned long) + GPDGC_MAX_KEY_SIZE
        + nb_servers * (ip_cost + GPDGC_MAX_KEY_SIZE + sizeof(unsigned short))
        + sizeof(unsigned short) + GPDGC_MESSAGE_SIGNATURE_SIZE
        + (4 + 3 * nb_servers) * sizeof(size_t);

    return reply_size > info_size ? reply_size : info_size;
}


/* Get the memory required by a client with the specified paramters */
size_t gpdgc_get_client_size(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model, int certified_servers,
        unsigned int max_servers, unsigned short max_pending_messages,
        unsigned short max_pending_replies, size_t max_message_size,
        unsigned int network_buffer_size)
{
    int is_corrupted = channel_model == GPDGC_CORRUPTED_MODEL;
    int is_byzantine = process_model == GPDGC_BYZANTINE_MODEL;
    int requires_key = certified_servers || is_corrupted;

    size_t ip_cost = gpdgc_get_max_address_size();
    size_t key_cost = requires_key ? GPDGC_MAX_KEY_SIZE : 0;
    size_t sig_cost = GPDGC_MESSAGE_SIGNATURE_SIZE;

    /* Infos */
    size_t info_item_size = ip_cost + key_cost + sizeof(gpdgc_view_server);
    size_t info_size = ip_cost + key_cost + sizeof(gpdgc_server_info)
        + GPDGC_MAX_KEY_SIZE + max_servers * (info_item_size + sizeof(GSList));
    size_t infos_size = max_servers * (info_size + sizeof(GSList));

    /* Refusings size */
    size_t refusings_size = max_servers * sizeof(GSList);

    /* Network size */
    size_t network_size =
        3 * network_buffer_size + sizeof(struct sockaddr_storage);

    /* Messages size */
    size_t content_size = max_message_size > ip_cost + key_cost
        ? max_message_size : ip_cost + key_cost;
    size_t cache_size = 3 * sizeof(unsigned short) + sizeof(unsigned long) 
        + ip_cost + content_size + (is_corrupted ? 2 : 1) * sig_cost
        + (is_corrupted ? 9 : 8) * sizeof(size_t);
    size_t message_size = sizeof(gpdgc_pending)
        + max_servers * (ip_cost + sizeof(GSList)) + cache_size;
    size_t messages_size =
        max_pending_messages * (message_size + sizeof(GSList));

    /* Replies size */
    size_t reply_size = sizeof(gpdgc_server_reply);
    if (is_byzantine)
    {
        reply_size += 3 * sizeof(GSList)
            + ip_cost + sizeof(size_t) + max_message_size;
    }
    size_t replies_size = max_pending_replies + (reply_size + sizeof(GSList));

    /* Output size */
    // NB: max_pendings is relatively arbitrarily large to avoid blocking input
    //     too early when replies are not processed by application
    unsigned long max_pending_outputs = max_pending_replies * 5 + 3;
    size_t output_size = sizeof(gpdgc_output);
    size_t outputs_size = max_pending_outputs * (output_size + sizeof(GSList));

    return ip_cost + 2 * key_cost + GPDGC_MAX_KEY_SIZE + infos_size
        + refusings_size + network_size + messages_size + replies_size
        + outputs_size + sizeof(gpdgc_iclient);
}


/* Producing outputs */
void gpdgc_register_client_output(gpdgc_iclient *client, gpdgc_output *output)
{
    client->outputs = g_slist_append(client->outputs, output);
    pthread_cond_broadcast(&client->output_condition);
}
void gpdgc_generate_reply_output(gpdgc_iclient *client,
        unsigned long id, void *content, size_t size)
{
    gpdgc_output *output = gpdgc_create_output(GPDGC_CLIENT_REPLY_MESSAGE_TYPE,
            id, content, size, NULL, GPDGC_SUSPISCION);
    if (output == NULL)
    {
        free(content);
        g_critical("%-10s: Cannot deliver reply '%lu'", "CLIENT", id);
        return; 
    }
    gpdgc_register_client_output(client, output);
}
void gpdgc_generate_event_output(gpdgc_iclient *client, gpdgc_event event)
{
    gpdgc_output *output = gpdgc_create_output(GPDGC_UNKNOWN_MESSAGE_TYPE,
            0, NULL, 0, NULL, event);
    if (output == NULL)
    {
        g_critical("%-10s: Cannot signal event", "CLIENT");
        return; 
    }
    gpdgc_register_client_output(client, output);
}


/* Thread delivering outputs */
void *gpdgc_deliver_client_output(void *argument)
{
    gpdgc_iclient *client = argument;

    gpdgc_enter_client(client);
    while ((client->state != GPDGC_CLOSED) && (client->state != GPDGC_DONE))
    {
        pthread_cond_wait(&client->output_condition, &client->lock);
        while (client->outputs != NULL)
        {
            gpdgc_output *output = client->outputs->data;
            client->outputs = g_slist_remove(client->outputs, output);
            pthread_cond_broadcast(&client->input_condition);
            gpdgc_leave_client(client);

            if (output->type == GPDGC_UNKNOWN_MESSAGE_TYPE)
            {
                client->inform(output->event);
            }
            else if (output->type == GPDGC_CLIENT_REPLY_MESSAGE_TYPE)
            {
                client->deliver(output->id, output->content, output->size);
                output->content = NULL;
            }
            else
            {
                g_error("%-10s: Unexpected output message type '%hu'",
                        "CLIENT", output->type);
            }
            gpdgc_free_output(output);
            gpdgc_enter_client(client);
        }
    }
    gpdgc_leave_client(client);
    return NULL;
}


/* The method listening for incoming messages */
void* gpdgc_listen_client_socket(void* argument)
{
    gpdgc_iclient *client = argument;

    /* Continuously listen on the specified socket */
    size_t recv_len = 0;
    socklen_t sender_length = sizeof(struct sockaddr_storage);
    while ((client->state != GPDGC_CLOSED) && (client->state != GPDGC_DONE))
    {
        memset(client->input_buffer, 0, client->input_length);

        if ((recv_len = recvfrom(client->socket, client->input_buffer,
                        client->input_length, 0, client->input_address,
                        &sender_length)) > 0)
        {
            gpdgc_deliver_to_client(client,
                    client->input_buffer, recv_len, client->input_address);
        }
    }
    return NULL;
}


/* Thread sending periodically messages to ensure reliability */
void *gpdgc_client_periodically_resend(void *argument)
{
    gpdgc_iclient *client = argument;
    gulong tick_period = 1000 * client->tick_length;

    while ((client->state != GPDGC_CLOSED) && (client->state != GPDGC_DONE))
    {
        g_usleep(tick_period);

        gpdgc_enter_client(client);
        if ((client->state != GPDGC_CLOSED) && (client->state != GPDGC_DONE))
        {
            /* Send pending requests to servers */
            GSList *pending_iterator = client->messages;
            while (pending_iterator != NULL)
            {
                gpdgc_pending *pending = pending_iterator->data;
                pending_iterator = pending_iterator->next;

                if (pending->remaining_ticks > 0)
                {
                    pending->remaining_ticks--;
                }
                else 
                {
                    g_debug("%-10s: Resend pending '%ld'",
                            "CLIENT", pending->sequence_number);

                    GSList *dst_iterator = pending->remaining_servers;
                    while (dst_iterator != NULL)
                    {
                        struct sockaddr *dst = dst_iterator->data;
                        dst_iterator = dst_iterator->next;

                        gpdgc_udp_send(client->socket,
                                pending->cache, pending->size, dst);
                    }
                    pending->remaining_ticks = client->resend_period;
                }
            }
        }
        gpdgc_leave_client(client);
    }
    return NULL;
}


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
        void (*inform) (gpdgc_event event))
{
    /* Check memory setting */
    if ((max_pending_messages == 0) || (max_pending_replies == 0))
    {
        g_error("%-10s: The maximum number of pendings must be > 0", "INIT");
    }

    /* Check resend period */
    if (tick_length == 0)
    {
        g_error("%-10s: Increment and tick must be greater than 0", "INIT");
    }
    if (resend_period == 0)
    {
        g_error("%-10s: Periods must be greater than 0", "INIT");
    }
    if (max_message_size == 0)
    {
        g_error("%-10s: Messages without content do not require GPDGC", "INIT");
    }

    /* Check size of network buffer */
    size_t required_network =
        gpdgc_get_client_network_buffer_size(max_servers, max_message_size);
    if (network_buffer_size < required_network)
    {
        g_error("%-10s: The network buffer size is not sufficient for the "
                "specified parameters: %u < %ld",
                "INIT", network_buffer_size, required_network);
    }

    /* Check process signatures */
    if ((channel_model == GPDGC_CORRUPTED_MODEL) && (private_key == NULL))
    {
        g_error("%-10s: Local process must define a private key", "INIT");
    }

    /* Build the group communication server */
    gpdgc_iclient *result = malloc(sizeof(gpdgc_iclient));
    if (result == NULL)
    {
        g_error("%-10s: Cannot create group communication server: "
                "lack of memory", "INIT");
    }

    /* Init client configuration */
    result->address = self;
    result->private_key = private_key;
    result->public_key = public_key;

    /* Init algorithm configuration */
    result->process_model = process_model;
    result->channel_model = channel_model;
    result->validation = validation;

    /* Init limits configuration */
    result->max_pending_messages = max_pending_messages;
    result->max_pending_replies = max_pending_replies;
    result->max_message_size = max_message_size;

    /* Init periodic events configuration */
    result->tick_length = tick_length;
    result->resend_period = resend_period;

    /* Init state variables */
    result->state = GPDGC_CREATED;
    result->trusted_key_initialised = 0;
    result->trusted_key_identifier = 0;
    result->trusted_key = NULL;
    result->view_identifier = 0;
    result->infos = NULL;
    result->refusings = NULL;

    /* Init network variables */
    result->input_thread = 0; 
    result->socket = socket(self->sa_family, SOCK_DGRAM, 0);
    if (result->socket == -1)
    {
        g_error("%-10s: Cannot create socket", "INIT");
    }
    if(bind(result->socket, self, gpdgc_get_address_size(self)) == -1)
    {
        g_error("%-10s: Cannot binding socket", "INIT");
    }
    result->input_length = network_buffer_size;
    result->input_buffer = (char *) malloc(result->input_length);
    if (result->input_buffer == NULL)
    {
        g_error("%-10s: Cannot create input buffer", "INIT");
    }
    result->input_address = malloc(sizeof(struct sockaddr_storage));
    if (result->input_address == NULL)
    {
        g_error("%-10s: Cannot create input sender address", "INIT");
    }

    /* Init reliability (re-sending messages) variables */
    result->resend_thread = 0; 

    /* Init lock variables */
    pthread_mutex_init(&result->lock, NULL);
    pthread_cond_init(&result->input_condition, NULL);
    pthread_cond_init(&result->output_condition, NULL);
    pthread_cond_init(&result->pending_condition, NULL);
    pthread_cond_init(&result->state_condition, NULL);

    /* Init messages variables */
    result->next_sequence_number = 0;
    result->messages = NULL; 
    result->replies = NULL;

    /* Init callback methods and variables */
    result->outputs = NULL;
    result->output_thread = 0;
    result->deliver = deliver;
    result->inform = inform;

    /* Run the thread for re-sending messages */
    if (pthread_create(&result->resend_thread, NULL,
                &gpdgc_client_periodically_resend, result) != 0)
    {
        g_error("%-10s: Cannot start re-sender thread", "INIT");
    }

    /* Run the thread for delivering output */
    if (pthread_create(&result->output_thread, NULL,
                &gpdgc_deliver_client_output, result) != 0)
    {
        g_error("%-10s: Cannot start output deliverer thread", "INIT");
    }

    /* Run the thread listening for udp messages */
    if (pthread_create(&result->input_thread, NULL,
                &gpdgc_listen_client_socket, result) != 0)
    {
        g_error("%-10s: Cannot start input listener thread", "INIT");
    }

    g_debug("%-10s: The client has been initialized", "INIT");
    return result;
}


/* Close a group communication client */
void gpdgc_free_view_server(void *void_server)
{
    gpdgc_view_server *server = void_server;

    if (server->public_key != NULL)
    {
        gcry_sexp_release(server->public_key);
    }
    free(server->address);
    free(server);
}
void gpdgc_free_server_info(void *void_info)
{
    gpdgc_server_info *info = void_info;

    if (info->public_key != NULL)
    {
        gcry_sexp_release(info->public_key);
    }
    if (info->trusted_key != NULL)
    {
        gcry_sexp_release(info->trusted_key);
    }
    g_slist_free_full(info->view, gpdgc_free_view_server);
    free(info->address);
    free(info);
}
void gpdgc_free_pending(void *void_pending)
{
    gpdgc_pending *pending = void_pending;

    g_slist_free(pending->remaining_servers);
    free(pending->cache);
    free(pending);
}
void gpdgc_free_server_reply(void *void_reply)
{
    gpdgc_server_reply *reply = void_reply;

    g_slist_free(reply->voters);
    g_slist_free_full(reply->contents, free);
    g_slist_free_full(reply->sizes, free);
    free(reply);
}
void gpdgc_close_client(gpdgc_client void_client)
{
    gpdgc_message *end = gpdgc_create_message();
    if ((end == NULL) || (!gpdgc_push_content(end, NULL, 0)))
    {
        g_critical("%-10s: Unable to build socket-end message", "CLIENT");
        return;
    }
    size_t size = 0;
    void *buffer = gpdgc_write_contents(end, NULL, &size);
    gpdgc_free_message(end);
    if (buffer == NULL)
    {
        g_critical("%-10s: Unable to buffer socket-end message", "CLIENT");
        return;
    }

    gpdgc_iclient *client = void_client;
    g_debug("%-10s: Close the client", "CLIENT");

    gpdgc_enter_client(client);
    gpdgc_signal_client_change(client, GPDGC_CLOSED);
    g_debug("%-10s: Send closing signals", "CLIENT");
    pthread_cond_broadcast(&client->input_condition);
    pthread_cond_broadcast(&client->output_condition);
    size_t local_size = gpdgc_get_address_size(client->address);
    sendto(client->socket, buffer, size, 0, client->address, local_size);
    free(buffer);
    gpdgc_leave_client(client);

    pthread_join(client->input_thread, NULL);
    g_debug("%-10s: Input thread terminated", "CLIENT");
    pthread_join(client->output_thread, NULL);
    g_debug("%-10s: Output thread terminated", "CLIENT");
    pthread_join(client->resend_thread, NULL);  
    g_debug("%-10s: Resend thread terminated", "CLIENT");

    gpdgc_enter_client(client);
    close(client->socket);
    free(client->input_buffer);
    free(client->input_address);
    gcry_sexp_release(client->private_key);
    gcry_sexp_release(client->public_key);
    free(client->address);
    gpdgc_leave_client(client);

    pthread_mutex_destroy(&client->lock);
    pthread_cond_destroy(&client->input_condition);
    pthread_cond_destroy(&client->output_condition);
    pthread_cond_destroy(&client->pending_condition);
    pthread_cond_destroy(&client->state_condition);

    g_debug("%-10s: Free %d view informations",
            "CLIENT", g_slist_length(client->infos));
    g_slist_free_full(client->infos, gpdgc_free_server_info);
    g_debug("%-10s: Free %d messages",
            "CLIENT", g_slist_length(client->messages));
    g_slist_free_full(client->messages, gpdgc_free_pending);
    g_debug("%-10s: Free %d replies",
            "CLIENT", g_slist_length(client->replies));
    g_slist_free_full(client->replies, gpdgc_free_server_reply);
    g_debug("%-10s: Free %d refusings",
            "CLIENT", g_slist_length(client->refusings));
    g_slist_free(client->refusings);
    free(client);
}


/* Wait until the client has subscribed to the view */
gpdgc_server_info *gpdgc_create_server_info(struct sockaddr *address,
        gcry_sexp_t key, int clone)
{
    gpdgc_server_info *info = malloc(sizeof(gpdgc_server_info));
    if (info != NULL)
    {
        info->address = clone ? gpdgc_clone_address(address) : address;
        info->public_key = clone ? gpdgc_clone_gcry_sexp_t(key) : key;

        info->suspiscion_flags = 0;
        info->nb_crash_suspecters = 0;
        info->nb_byzantine_suspecters = 0;

        info->sequence_number = 0;
        info->view_identifier = 0;
        info->trusted_key_identifier = 0;
        info->trusted_key = NULL;
        info->view = NULL;

        if ((info->address == NULL) 
                || ((key != NULL) && (info->public_key == NULL)))
        {
            gpdgc_free_server_info(info);
            info = NULL;
        }
    }
    return info;
}
gpdgc_pending *gpdgc_create_pending(unsigned long sequence_number,
        unsigned short resend_period)
{
    gpdgc_pending *result = malloc(sizeof(gpdgc_pending));
    if (result != NULL)
    {
        result->sequence_number = sequence_number;
        result->remaining_ticks = resend_period;

        result->remaining_servers = NULL;
        result->cache = NULL;
        result->size = 0;
    }
    return result;
}
gcry_sexp_t gpdgc_get_client_channel_key(gpdgc_iclient *client)
{
    if (client->channel_model == GPDGC_CORRUPTED_MODEL)
    {
        return client->private_key;
    }
    return NULL;
}
int gpdgc_send_client_message(gpdgc_iclient *client, gpdgc_message *message)
{
    /* Create the message buffer that is sent */
    gcry_sexp_t key = gpdgc_get_client_channel_key(client);
    size_t size = 0;
    void *buffer = gpdgc_write_contents(message, key, &size);
    if (buffer == NULL)
    {
        g_critical("%-10s: Unable to buffer subscritpion message", "CLIENT");
        gpdgc_free_message(message);
        return 0;
    }
    gpdgc_free_message(message);

    /* Store the message for possible future resending */
    unsigned long sn = client->next_sequence_number;
    gpdgc_pending *pending = gpdgc_create_pending(sn, client->resend_period);
    if (pending == NULL)
    {
        g_critical("%-10s: Unable to build subscritpion container", "CLIENT");
        free(buffer);
        return 0;
    }
    pending->cache = buffer;
    pending->size = size;
    client->messages = g_slist_append(client->messages, pending);
    client->next_sequence_number++;

    /* Clean server replies that are no more relevant */
    gpdgc_server_reply *reply =
        client->replies != NULL ? client->replies->data : NULL;
    while ((reply != NULL)
            && gpdgc_cmp_counter(client->next_sequence_number,
                reply->sequence_number + client->max_pending_replies) > 0)
    {
        g_debug("%-10s: Remove reply '%lu' from memory",
                "CLIENT", reply->sequence_number);
        client->replies = g_slist_remove(client->replies, reply);
        gpdgc_free_server_reply(reply);

        reply = client->replies != NULL ? client->replies->data : NULL;
    }

    /* Effectively send the message to the known servers */
    GSList *iterator = client->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        gpdgc_udp_send(client->socket, buffer, size, info->address);
        pending->remaining_servers =
            g_slist_append(pending->remaining_servers, info->address);
    }
    return 1;
}
int gpdgc_subscribe_to_view(gpdgc_client void_client,
        GSList *servers, GSList *keys)
{
    if (servers == NULL)
    {
        return 0;
    }

    gpdgc_iclient *client = void_client;
    gpdgc_enter_client(client);
    if (client->state != GPDGC_CREATED)
    {
        g_critical("%-10s: Unable to subscribe to view of the client: "
                "already subscribed to a view ", "CLIENT");
        gpdgc_leave_client(client);
        return 0;
    }

    GSList *iterator = servers;
    GSList *key_iterator = keys;
    while (iterator != NULL)
    {
        struct sockaddr *srv = iterator->data;
        iterator = iterator->next;

        gcry_sexp_t key = key_iterator != NULL ? key_iterator->data: NULL;
        key_iterator = key_iterator != NULL ? key_iterator->next : NULL;

        gpdgc_server_info *info = gpdgc_create_server_info(srv, key, 0);
        if (info == NULL)
        {
            g_critical("%-10s: Unable to create view info container", "CLIENT");
            g_slist_free_full(client->infos, gpdgc_free_server_info);
            client->infos = NULL;
            gpdgc_leave_client(client);
            return 0;
        }
        client->infos = g_slist_append(client->infos, info);
    }

    unsigned short type = GPDGC_SUBSCRIPTION_MESSAGE_TYPE;
    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_gcry_sexp(msg, client->public_key))
            || (!gpdgc_push_content(msg, &type, sizeof(unsigned short))))
    {
        g_critical("%-10s: Unable to build subscritpion message", "CLIENT");
        gpdgc_free_message(msg);
        gpdgc_leave_client(client);
        return 0;
    }

    int result = gpdgc_send_client_message(client, msg);
    if (result)
    {
        gpdgc_signal_client_change(client, GPDGC_WAITING);
        gpdgc_wait_client_done(client, 1);
        result = client->state == GPDGC_READY;
    }
    client->next_sequence_number = 0;
    gpdgc_leave_client(client);
    return result;
}


/* Wait until the client is no more subscribed to the view */
int gpdgc_send_ready_client_message(gpdgc_iclient *client,
        gpdgc_message *message, unsigned short msg_type, gcry_sexp_t key,
        unsigned long *reply_id)
{
    if (client->state != GPDGC_READY)
    {
        g_critical("%-10s: Unable to broadcast client message: "
                "client is not yet initialised", "CLIENT");
        return 0;
    }

    int is_byzantine = client->process_model == GPDGC_BYZANTINE_MODEL;
    unsigned short flag = is_byzantine ? 0 : GPDGC_READY_MESSAGE_FLAG;
    unsigned short type = GPDGC_BROADCAST_MESSAGE_TYPE;
    size_t addr_size = gpdgc_get_address_size(client->address);
    if ((!gpdgc_push_content(message, &msg_type, sizeof(unsigned short)))
            || ((key != NULL) && (!gpdgc_sign_message(message, key)))
            || (!gpdgc_push_content(message, &client->next_sequence_number, 
                    sizeof(unsigned long)))
            || (!gpdgc_push_content(message, (void*)client->address, addr_size))
            || (!gpdgc_push_content(message, &flag, sizeof(unsigned short)))
            || (!gpdgc_push_content(message, &type, sizeof(unsigned short))))
    {
        g_critical("%-10s: Cannot build client message", "CLIENT");
        gpdgc_free_message(message);
        return 0;
    } 
    
    if (reply_id != NULL)
    {
        *reply_id = client->next_sequence_number;
    }

    g_debug("%-10s: Broadcast message '%ld' (type='%u')",
            "CLIENT", client->next_sequence_number, msg_type);
    return gpdgc_send_client_message(client, message);
}
int gpdgc_unsubscribe_from_view(gpdgc_client void_client)
{
    gpdgc_iclient *client = void_client;
    size_t addr_size = gpdgc_get_address_size(client->address);
    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, NULL, 0)) 
            || (!gpdgc_push_content(msg, (void*)client->address, addr_size)))
    {
        g_critical("%-10s: Unable to build unsubscritpion message", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_REMOVE_CLIENT_MESSAGE_TYPE;
    g_debug("%-10s: Wait until no pending message remains", "CLIENT");
    gpdgc_enter_client_when_no_pending(client);
    int result = gpdgc_send_ready_client_message(client, msg, type, NULL, NULL);
    if (result)
    {
        gpdgc_signal_client_change(client, GPDGC_EXITING);
        gpdgc_wait_client_done(client, 0); 
    }
    gpdgc_leave_client(client);
    return result;
}


/* Get the current view */
GSList *gpdgc_get_current_observed_view(gpdgc_client client)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iclient *) client)->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        result = g_slist_append(result, info->address);
    }
    return result;
}


/* Get the client suspected to be crashed */
GSList *gpdgc_get_observed_byzantine_suspiscions(gpdgc_client client)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iclient *) client)->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        if (info->suspiscion_flags & GPDGC_BYZANTINE_FLAG)
        {
            result = g_slist_append(result, info->address);
        }
    }
    return result;
}


/* Get the client suspected to be byzantine */
GSList *gpdgc_get_observed_crash_suspiscions(gpdgc_client client)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iclient *) client)->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        if (info->suspiscion_flags & GPDGC_CRASHED_FLAG)
        {
            result = g_slist_append(result, info->address);
        }
    }
    return result;
}


/* Send reliable and totally ordered messages from a client */
int gpdgc_atomic_multicast(gpdgc_client void_client,
        void *message, size_t size, unsigned long *reply_id)
{
    gpdgc_iclient *client = void_client;
    if (size > client->max_message_size)
    {
        g_critical("%-10s: Unable to a-multicast message: "
                "message is too big %ld > %u",
                "CLIENT", size, client->max_message_size);
        return 0;
    }

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL) || (!gpdgc_push_content(msg, message, size))) 
    {
        g_critical("%-10s: Unable to build a-multicast message", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_ATOMIC_MESSAGE_TYPE;
    gpdgc_enter_client_when_few_pending(client);
    int result =
        gpdgc_send_ready_client_message(client, msg, type, NULL, reply_id);
    gpdgc_leave_client(client);
    return result;
}


/* Send reliable messages from a client */
int gpdgc_reliable_multicast(gpdgc_client void_client,
        void *message, size_t size, unsigned long *reply_id)
{
    gpdgc_iclient *client = void_client;
    if (size > client->max_message_size)
    {
        g_critical("%-10s: Unable to r-multicast message: "
                "message is too big %ld > %u",
                "CLIENT", size, client->max_message_size);
        return 0;
    }

    int is_byzantine = client->process_model == GPDGC_BYZANTINE_MODEL;
    if (is_byzantine && (client->validation == GPDGC_FULL_VALIDATION))
    {
        g_critical("%-10s: Cannot multicast message: rbroadcast is deactivated "
                "with byzantine failure and full consensus validation",
                "CLIENT");
        return 0;
    }

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL) || (!gpdgc_push_content(msg, message, size))) 
    {
        g_critical("%-10s: Unable to build r-multicast message", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_RELIABLE_MESSAGE_TYPE;
    gpdgc_enter_client_when_few_pending(client);
    int result =
        gpdgc_send_ready_client_message(client, msg, type, NULL, reply_id);
    gpdgc_leave_client(client);
    return result;
}


/* Add process to the current view */
int gpdgc_add_to_view(gpdgc_client void_client, 
        struct sockaddr *address, gcry_sexp_t key, gcry_sexp_t trusted_key)
{
    gpdgc_iclient *client = void_client;
    size_t address_size = gpdgc_get_address_size(address);

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_gcry_sexp(msg, key))
            || (!gpdgc_push_content(msg, address, address_size))) 
    {
        g_critical("%-10s: Unable to build message to add server", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_ADD_SERVER_MESSAGE_TYPE;
    gpdgc_enter_client_when_few_pending(client);
    int result =
        gpdgc_send_ready_client_message(client, msg, type, trusted_key, NULL);
    gpdgc_leave_client(client);
    return result;
}


/* Remove process from the current view */
int gpdgc_remove_from_view(gpdgc_client void_client,
        struct sockaddr *address, gcry_sexp_t trusted_key)
{
    gpdgc_iclient *client = void_client;
    size_t address_size = gpdgc_get_address_size(address);

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL)
            || (!gpdgc_push_content(msg, NULL, 0))
            || (!gpdgc_push_content(msg, address, address_size))) 
    {
        g_critical("%-10s: Unable to build message to remove server", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_REMOVE_SERVER_MESSAGE_TYPE;
    gpdgc_enter_client(client);
    int result =
        gpdgc_send_ready_client_message(client, msg, type, trusted_key, NULL);
    gpdgc_leave_client(client);
    return result;
}


/* Update the key trusted by the server */
int gpdgc_update_trusted_key(gpdgc_client void_client,
        gcry_sexp_t new_key, gcry_sexp_t trusted_key)
{
    gpdgc_iclient *client = void_client;

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL) || (!gpdgc_push_gcry_sexp(msg, new_key)))
    {
        g_critical("%-10s: Unable to build message to update key", "CLIENT");
        gpdgc_free_message(msg);
        return 0;
    }

    unsigned short type = GPDGC_UPDATE_TRUSTED_KEY_MESSAGE_TYPE;
    gpdgc_enter_client_when_few_pending(client);
    int result =
        gpdgc_send_ready_client_message(client, msg, type, trusted_key, NULL);
    gpdgc_leave_client(client);
    return result;
}


/* Process update of view informations */
gpdgc_server_info *gpdgc_get_server_info(GSList *infos, 
        struct sockaddr *address)
{
    GSList *iterator = infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        if (gpdgc_cmp_address(info->address, address) == 0)
        {
            return info;
        }
    }
    return NULL;
}
GSList *gpdgc_extract_view_servers(gpdgc_message *message)
{
    GSList *result = NULL;
    struct sockaddr *address = gpdgc_pop_address(message);
    while (address != NULL)
    {
        gcry_sexp_t key = gpdgc_pop_gcry_sexp(message);
        size_t flags_size = 0;
        unsigned short *flags = gpdgc_pop_content(message, &flags_size);
        if (flags_size != sizeof(unsigned short))
        {
            g_slist_free_full(result, gpdgc_free_view_server);
            gpdgc_free_message(message);
            gcry_sexp_release(key);
            free(address);
            free(flags);
            return NULL;
        }

        gpdgc_view_server *server = malloc(sizeof(gpdgc_view_server));
        if (server == NULL)
        {
            g_critical("%-10s: Cannot read info: lack of memory", "CLIENT");
            gpdgc_free_message(message);
            g_slist_free_full(result, gpdgc_free_view_server);
            gcry_sexp_release(key);
            free(address);
            free(flags);
            return NULL;
        }
        server->address = address;
        server->public_key = key;
        server->suspiscion_flags = *flags;
        free(flags);

        result = g_slist_append(result, server);
        address = gpdgc_pop_address(message);
    }
    gpdgc_free_message(message);
    return result;
}
unsigned short gpdgc_count_similar_view(GSList *infos, gpdgc_server_info *ref)
{
    unsigned short counter = 0;
    GSList *iterator = infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        int equals = info->view_identifier == ref->view_identifier;
        GSList *ref_iterator = ref->view;
        GSList *inf_iterator = info->view;
        while ((ref_iterator != NULL) && (inf_iterator != NULL) && equals)
        {
            gpdgc_view_server *ref_server = ref_iterator->data;
            struct sockaddr *ref_process = ref_server->address;
            gcry_sexp_t ref_key = ref_server->public_key;
            ref_iterator = ref_iterator->next;

            gpdgc_view_server *inf_server = inf_iterator->data;
            struct sockaddr *inf_process = inf_server->address;
            gcry_sexp_t inf_key = inf_server->public_key;
            inf_iterator = inf_iterator->next;

            GError *ex = NULL;
            equals = (gpdgc_cmp_address(ref_process, inf_process) == 0) 
                && (gpdgc_cmp_gcry_sexp_t(ref_key, inf_key, &ex) == 0);
            if (ex != NULL)
            {
                g_critical("%-10s: Cannot compare view info", "CLIENT");
            }
        }

        if (equals && (ref_iterator == NULL) && (inf_iterator == NULL))
        {
            counter ++;
        }
    }
    return counter;
}
unsigned short gpdgc_count_similar_key(GSList *infos, gpdgc_server_info *ref)
{
    unsigned short counter = 0;
    GSList *iterator = infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *info = iterator->data;
        iterator = iterator->next;

        if (ref->trusted_key_identifier == info->trusted_key_identifier)
        {
            GError *ex = NULL;
            int cmp =
                gpdgc_cmp_gcry_sexp_t(info->trusted_key, ref->trusted_key, &ex);
            if (ex != NULL)
            {
                return 0;
            }
            counter += (cmp == 0) ? 1 : 0;
        }
    }
    return counter;
}
unsigned short gpdgc_count_similar_votes(void *content, size_t size, 
        GSList *contents, GSList *sizes)
{
    unsigned short counter = 1;
    GSList *content_iterator = contents;
    GSList *size_iterator = sizes;
    while ((content_iterator != NULL) && (size_iterator != NULL))
    {
        void *iterated_content = content_iterator->data;
        content_iterator = content_iterator->next;
        
        size_t *iterated_size = size_iterator->data;
        size_iterator = size_iterator->next;

        if ((*iterated_size == size)
                && (memcmp(content, iterated_content, size) == 0))
        {
            counter++;
        }
    }
    return counter;
}
int gpdgc_update_suspiscion_flags(gpdgc_iclient *client)
{
    /* Reset suspiscion counters */
    GSList *iterator = client->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *iterated = iterator->data;
        iterator = iterator->next;

        iterated->nb_crash_suspecters = 0;
        iterated->nb_byzantine_suspecters = 0;
    }

    /* Compute suspiscion counters */
    iterator = client->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *iterated = iterator->data;
        iterator = iterator->next;

        GSList *server_iterator = iterated->view;
        while (server_iterator != NULL)
        {
            gpdgc_view_server *server = server_iterator->data;
            server_iterator = server_iterator->next;

            gpdgc_server_info *info = NULL;
            if (server->suspiscion_flags != 0)
            {
                info = gpdgc_get_server_info(client->infos, server->address);
            }
            if ((info != NULL)
                    && (server->suspiscion_flags & GPDGC_CRASHED_FLAG))
            {
                info->nb_crash_suspecters++;
            }
            if ((info != NULL)
                    && (server->suspiscion_flags & GPDGC_BYZANTINE_FLAG))
            {
                info->nb_byzantine_suspecters++;
            }
        }
    }

    /* Compute suspiscion flags and check if updated*/
    int updated = 0;
    unsigned short max_byzantine = gpdgc_get_expected_max_byzantine(client); 
    unsigned short nb_servers = g_slist_length(client->infos);
    unsigned short majority = (nb_servers  + max_byzantine) / 2 + 1;
    iterator = client->infos;
    while (iterator != NULL)
    {
        gpdgc_server_info *iterated = iterator->data;
        iterator = iterator->next;

        unsigned short old_flags = iterated->suspiscion_flags;
        iterated->suspiscion_flags = 0;
        if (iterated->nb_crash_suspecters >= majority)
        {
            iterated->suspiscion_flags |= GPDGC_CRASHED_FLAG;
        }
        if (iterated->nb_byzantine_suspecters >= majority)
        {
            iterated->suspiscion_flags |= GPDGC_BYZANTINE_FLAG;
        }
        updated = updated || (iterated->suspiscion_flags != old_flags);
    }
    return updated;
}
void gpdgc_process_view_info(gpdgc_iclient *client, 
        gpdgc_message *message, gpdgc_server_info *info) 
{
    /* Pending messages are relevant only when client is ready or waiting */
    char *label = gpdgc_get_address_label(info->address);
    if ((client->state != GPDGC_WAITING) && (client->state != GPDGC_READY))
    {
        g_info("%-10s: Ignore view info from '%s': "
                "client is not waiting or ready", "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        return;
    }

    /* Get view information */
    size_t sn_size;
    unsigned long *sn = gpdgc_pop_content(message, &sn_size);
    size_t view_id_size;
    unsigned long *view_id = gpdgc_pop_content(message, &view_id_size);
    size_t key_id_size;
    unsigned long *key_id = gpdgc_pop_content(message, &key_id_size);
    gcry_sexp_t trusted_key = gpdgc_pop_gcry_sexp(message);
    GSList *servers = gpdgc_extract_view_servers(message);

    if ((sn_size != sizeof(unsigned long))
            || (view_id_size != sizeof(unsigned long))
            || (key_id_size != sizeof(unsigned long))
            || (servers == NULL))
    {
        g_info("%-10s: Ignore view info from '%s': invalid message",
                "CLIENT", label);
        g_slist_free_full(servers, gpdgc_free_view_server);
        gcry_sexp_release(trusted_key);
        free(view_id);
        free(key_id);
        free(sn);
        free(label);
        return;
    }
    else if ((info->view != NULL)
            && (gpdgc_cmp_counter(info->sequence_number, *sn) >= 0))
    {
        g_info("%-10s: Ignore outdated view info '%ld'<='%ld' from '%s'",
                "CLIENT", *sn, info->sequence_number, label);
        g_slist_free_full(servers, gpdgc_free_view_server);
        gcry_sexp_release(trusted_key);
        free(view_id);
        free(key_id);
        free(sn);
        free(label);
        return;
    }

    /* Update the view considered locally by the sender*/
    g_debug("%-10s: The view info of server '%s' is updated to '%lu'",
            "CLIENT", label, *sn);
    g_slist_free_full(info->view, gpdgc_free_view_server);
    info->view = servers;
    gcry_sexp_release(info->trusted_key);
    info->trusted_key = trusted_key;
    info->sequence_number = *sn;
    info->view_identifier = *view_id;
    info->trusted_key_identifier = *key_id;
    free(view_id);
    free(key_id);
    free(sn);
    free(label);

    /* Recompute the view when a new view has been globally installed */ 
    unsigned short max_byzantine = gpdgc_get_expected_max_byzantine(client); 
    if (((client->state == GPDGC_WAITING)
                || (gpdgc_cmp_counter(info->view_identifier,
                        client->view_identifier) > 0))
            && (gpdgc_count_similar_view(client->infos, info) > max_byzantine))
    {
        GSList *created = NULL;
        GSList *copy = client->infos;
        client->infos = NULL;

        /* Create the data structure related to the new view */
        GSList *iterator = info->view;
        while (iterator != NULL)
        {
            gpdgc_view_server *srv = iterator->data;
            iterator = iterator->next;

            gpdgc_server_info *srv_info =
                gpdgc_get_server_info(copy, srv->address);
            if (srv_info == NULL)
            {
                srv_info =
                    gpdgc_create_server_info(srv->address, srv->public_key, 1);
                if ((srv_info == NULL) && (client->state == GPDGC_READY))
                {
                    g_critical("%-10s: Unable to update global view: "
                            "lack of memory", "CLIENT");
                    client->infos = g_slist_concat(client->infos, copy);
                    return;
                }
                else if (srv_info == NULL)
                {
                    g_critical("%-10s: Unable to init global view: "
                            "lack of memory", "CLIENT");
                    g_slist_free_full(copy, gpdgc_free_server_info);
                    g_slist_free_full(client->infos, gpdgc_free_server_info);
                    client->infos = NULL;
                    gpdgc_signal_client_change(client, GPDGC_DONE);
                    return;
                }
                srv_info->view_identifier = client->view_identifier;
                srv_info->trusted_key_identifier = 
                    client->trusted_key_identifier;
                created = g_slist_append(created, srv_info);
            }
            else
            {
                copy = g_slist_remove(copy, srv_info);
            }
            client->infos = g_slist_append(client->infos, srv_info);
        }
        client->view_identifier = info->view_identifier;

        /* Update the voters of the server replies */
        iterator = client->replies;
        while (iterator != NULL)
        {
            gpdgc_server_reply *reply = iterator->data;
            iterator = iterator->next;

            GSList *rmv_iterator = copy;
            while (rmv_iterator != NULL)
            {
                gpdgc_server_info *rmv = rmv_iterator->data;
                rmv_iterator = rmv_iterator->next;

                reply->voters = g_slist_remove(reply->voters, rmv->address);
            }
        }

        /* Update remaining servers of pending messages */
        int has_removed_message = 0;
        int has_removed_last = 0;
        iterator = client->messages;
        while (iterator != NULL)
        {
            gpdgc_pending *pending = iterator->data;
            iterator = iterator->next;

            GSList *rmv_iterator = copy;
            while (rmv_iterator != NULL)
            {
                gpdgc_server_info *rmv = rmv_iterator->data;
                rmv_iterator = rmv_iterator->next;

                pending->remaining_servers =
                    g_slist_remove(pending->remaining_servers, rmv->address);
            }
            
            GSList *add_iterator = created;
            while (add_iterator != NULL)
            {
                gpdgc_server_info *add = add_iterator->data;
                add_iterator = add_iterator->next;

                pending->remaining_servers =
                    g_slist_append(pending->remaining_servers, add->address);
            }

            unsigned short max_faulty = gpdgc_get_expected_max_faulty(client);
            if (g_slist_length(pending->remaining_servers) <= max_faulty)
            {
                g_debug("%-10s: Message '%lu' is removed from pendings", 
                        "CLIENT", pending->sequence_number);
                client->messages = g_slist_remove(client->messages, pending);
                gpdgc_free_pending(pending);
                has_removed_message = 1;
                has_removed_last = iterator == NULL; 
            }
        }
        g_slist_free_full(copy, gpdgc_free_server_info);
        g_slist_free(created);
        if ((client->state == GPDGC_EXITING) && has_removed_last)
        {
            gpdgc_signal_client_change(client, GPDGC_DONE);
        }
        else if (has_removed_message)
        {
            pthread_cond_broadcast(&client->pending_condition);
        }

        /* Signal the new view (upon first view, signal that client is ready) */
        if (client->state == GPDGC_WAITING)
        {
            g_slist_free_full(client->messages, gpdgc_free_pending);
            client->messages = NULL;
            gpdgc_signal_client_change(client, GPDGC_READY);
        }
        g_debug("%-10s: Install new view '%ld'", 
                "CLIENT", client->view_identifier);
        gpdgc_generate_event_output(client, GPDGC_VIEW_UPDATE);

        /* Re-check whether pending replies can be delivered */
        max_byzantine = gpdgc_get_expected_max_byzantine(client); 
        GSList *reply_iterator = client->replies;
        while (reply_iterator != NULL)
        {
            gpdgc_server_reply *reply = reply_iterator->data;
            reply_iterator = reply_iterator->next;

            if (!reply->delivered)
            {
                int counter = 0;
                GSList *content_iterator = reply->contents;
                GSList *size_iterator = reply->sizes;
                while ((g_slist_length(content_iterator) > max_byzantine) 
                        && (counter <= max_byzantine))
                {
                    void *content = content_iterator->data;
                    size_t *size = size_iterator->data;

                    counter = gpdgc_count_similar_votes(content, *size, 
                            content_iterator->next, size_iterator->next);
                    if (counter <= max_byzantine)
                    {
                        content_iterator = content_iterator->next;
                        size_iterator = size_iterator->next;
                    }
                }

                if (counter > max_byzantine)
                {
                    void *content = content_iterator->data;
                    size_t *size = size_iterator->data;
                    reply->contents = g_slist_remove(reply->contents, content);

                    g_debug("%-10s: Deliver reply '%lu'",
                            "CLIENT", reply->sequence_number);
                    reply->delivered = 1;
                    gpdgc_generate_reply_output(client,
                            reply->sequence_number, content, *size);
                }
            }
        }
    }

    /* Recompute global suspiscions */
    if (gpdgc_update_suspiscion_flags(client))
    {
        gpdgc_generate_event_output(client, GPDGC_SUSPISCION);
    }

    /* Recompute trusted key */
    if (((!client->trusted_key_initialised)
                || (gpdgc_cmp_counter(info->trusted_key_identifier,
                        client->trusted_key_identifier) > 0))
            && (gpdgc_count_similar_key(client->infos, info) > max_byzantine))
    {
        gcry_sexp_t clone = gpdgc_clone_gcry_sexp_t(info->trusted_key);
        if ((info->trusted_key != NULL) && (clone == NULL))
        {
            g_critical("%-10s: Unable to clone trusted key: lack of memory",
                    "CLIENT");
        }
        else
        {
            g_debug("%-10s: Trusted key '%lu' has been set", 
                "CLIENT", info->trusted_key_identifier);
            if (client->trusted_key != NULL)
            {
                gcry_sexp_release(client->trusted_key);
            }
            client->trusted_key_initialised = 1;
            client->trusted_key = clone;
            client->trusted_key_identifier = info->trusted_key_identifier;
            gpdgc_generate_event_output(client, GPDGC_NEW_TRUSTED_KEY);
        }
    }
}


/* Process ack to client messages */
gpdgc_pending *gpdgc_get_pending(gpdgc_iclient *client,
        unsigned long sn, int *is_last)
{
    GSList *iterator = client->messages;
    while (iterator != NULL)
    {
        gpdgc_pending *pending = iterator->data;
        iterator = iterator->next;

        if (pending->sequence_number == sn)
        {
            *is_last = iterator == NULL;
            return pending;
        }
    }
    return NULL;
}
void gpdgc_remove_pending_message(gpdgc_iclient *client, 
        gpdgc_pending *pending, int is_last)
{
    g_debug("%-10s: Message '%lu' is removed from pendings", 
            "CLIENT", pending->sequence_number);
    client->messages = g_slist_remove(client->messages, pending);
    gpdgc_free_pending(pending);

    if ((client->state == GPDGC_EXITING) && is_last)
    {
        gpdgc_signal_client_change(client, GPDGC_DONE);
    }
    else
    {
        pthread_cond_broadcast(&client->pending_condition);
    }
}
void gpdgc_process_pending_message(gpdgc_iclient *client, 
        gpdgc_message *message, struct sockaddr *sender)
{
    /* Pending messages are relevant only when client is ready */
    if ((client->state != GPDGC_READY) && (client->state != GPDGC_EXITING))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message from '%s': client is not ready/waiting",
                "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        return;
    }

    /* Only consider message with the right size */
    unsigned int message_length = gpdgc_get_message_length(message);
    if (message_length != 4)
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message from '%s': invalid length %d",
                "CLIENT", label, message_length);
        gpdgc_free_message(message);
        free(label);
        return;
    }

    size_t flags_size;
    unsigned short *flags = gpdgc_pop_content(message, &flags_size);  

    struct sockaddr *address = gpdgc_pop_address(message);

    size_t sn_size;
    unsigned long *sn = gpdgc_pop_content(message, &sn_size);
    gpdgc_free_message(message);

    /* Only consider well-formed messages */
    if ((flags_size != sizeof(unsigned short))
            || (address == NULL)
            || (sn_size != sizeof(unsigned long)))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message from '%s': invalid content => "
                "flag size %ld!=%ld, address is invalid, or sn size %ld!=%ld",
                "CLIENT", label, flags_size, sizeof(unsigned short),
                sn_size, sizeof(unsigned long));
        free(sn);
        free(address);
        free(flags);
        free(label);
        return;
    }

    /* Only consider message originated by the local client */
    if (gpdgc_cmp_address(address, client->address) != 0)
    {
        char *label = gpdgc_get_address_label(sender);
        char *address_label = gpdgc_get_address_label(address);
        g_info("%-10s: Ignore message from '%s': origin ('%s') is not local",
                "CLIENT", label, address_label);
        free(sn);
        free(address);
        free(flags);
        free(address_label);
        free(label);
        return;
    }
    free(address);

    int is_received = *flags & GPDGC_RECEIVED_MESSAGE_FLAG;
    free(flags);

    /* Only consider message corresponding to pending client message */
    int is_last = 0;
    gpdgc_pending *pending = gpdgc_get_pending(client, *sn, &is_last);
    if (pending == NULL)
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message '%lu' from '%s': not in memory",
                "CLIENT", *sn, label);
        free(label);
        free(sn);
        return;
    }
    free(sn);

    /* Process requiring message */ 
    if (!is_received)
    {
        char *label = gpdgc_get_address_label(sender);
        g_debug("%-10s: Message '%lu' is resend to '%s'", 
                "CLIENT", pending->sequence_number, label);
        free(label);

        gpdgc_udp_send(client->socket, pending->cache, pending->size, sender);
        return;
    }

    /* Process received message */ 
    char *label = gpdgc_get_address_label(sender);
    g_debug("%-10s: Message '%lu' has been received by '%s'", 
            "CLIENT", pending->sequence_number, label);
    free(label);

    unsigned short max_faulty = gpdgc_get_expected_max_faulty(client);
    pending->remaining_servers =
        g_slist_remove(pending->remaining_servers, sender);
    if (g_slist_length(pending->remaining_servers) <= max_faulty)
    {
        gpdgc_remove_pending_message(client, pending, is_last);
    }
}


/* Process ack/nack to client subscriptions */
void gpdgc_process_subscription_ack(gpdgc_iclient *client,
        int is_ack, struct sockaddr *sender)
{
    /* Pending messages are relevant only when client is ready */
    if (client->state != GPDGC_WAITING)
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore subscription ack from '%s': "
                "client is not waiting", "CLIENT", label);
        free(label);
        return;
    }
    g_assert(g_slist_length(client->messages) == 1);

    /* Process subscription ack */
    gpdgc_pending *pending = client->messages->data;
    if (is_ack)
    {
        char *label = gpdgc_get_address_label(sender);
        g_debug("%-10s: Subscription ack has been received by '%s'", 
                "CLIENT", label);
        free(label);

        pending->remaining_servers =
            g_slist_remove(pending->remaining_servers, sender);
        client->refusings =
            g_slist_remove(client->refusings, sender);
        return;
    }

    /* Process subscription nack */
    if (!gpdgc_contains_address(client->refusings, sender))
    {
        char *label = gpdgc_get_address_label(sender);
        g_debug("%-10s: Subscription has been refused by '%s'", 
                "CLIENT", label);
        free(label);

        pending->remaining_servers =
            g_slist_prepend(pending->remaining_servers, sender);
        client->refusings =
            g_slist_prepend(client->refusings, sender);

        unsigned short max_byzantine = gpdgc_get_expected_max_byzantine(client);
        if (g_slist_length(client->refusings) > max_byzantine)
        {
            g_slist_free(client->refusings);
            client->refusings = NULL;
            gpdgc_signal_client_change(client, GPDGC_DONE);
        }
    }
}


/* Process replies to client message */
int gpdgc_cmp_server_reply(const void *first_void, const void *second_void)
{
    const gpdgc_server_reply *first = first_void;
    const gpdgc_server_reply *second = second_void;

    return gpdgc_cmp_counter(first->sequence_number, second->sequence_number);
}
gpdgc_server_reply *gpdgc_get_server_reply(gpdgc_iclient *client,
        unsigned long sequence_number)
{
    GSList *iterator = client->replies;
    while (iterator != NULL)
    {
        gpdgc_server_reply *reply = iterator->data;
        iterator = iterator->next;

        if (reply->sequence_number == sequence_number)
        {
            return reply;
        }
    }

    gpdgc_server_reply *reply = malloc(sizeof(gpdgc_server_reply));
    if (reply != NULL)
    {
        reply->sequence_number = sequence_number;
        reply->delivered = 0;

        reply->voters = NULL;
        reply->contents = NULL;
        reply->sizes = NULL;

        client->replies = g_slist_insert_sorted(client->replies,
                reply, gpdgc_cmp_server_reply);
    }
    return reply;
}
void gpdgc_process_reply(gpdgc_iclient *client, 
        gpdgc_message *message, gpdgc_server_info *info) 
{
    char *label = gpdgc_get_address_label(info->address);

    size_t id_size = 0;
    unsigned long *id = gpdgc_pop_content(message, &id_size);
    if (id_size != sizeof(unsigned long))
    {
        g_info("%-10s: Ignore invalid client reply from '%s'", "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        free(id);
        return;
    }

    /* Send ack to the server issuing the reply */
    unsigned short type = GPDGC_ACK_CLIENT_REPLY_MESSAGE_TYPE;
    gpdgc_message *ack = gpdgc_create_message();
    if ((ack != NULL)
            && gpdgc_push_content(ack, id, id_size)
            && gpdgc_push_content(ack, &type, sizeof(unsigned short)))
    {
        gcry_sexp_t key = gpdgc_get_client_channel_key(client);
        size_t ack_size = 0;
        void *ack_buffer = gpdgc_write_contents(ack, key, &ack_size);
        if (ack_buffer != NULL)
        {
            g_debug("%-10s: Send reply-accept '%lu' to '%s'",
                    "CLIENT", *id, label);
            gpdgc_udp_send(client->socket, ack_buffer, ack_size, info->address);
            free(ack_buffer);
        }
        else
        {
            g_info("%-10s: Cannot buffer reply-accept '%lu' to '%s'",
                    "CLIENT", *id, label);
        }
    }
    else
    {
        g_info("%-10s: Cannot build reply-accept '%lu' to '%s'",
                "CLIENT", *id, label);
    }
    gpdgc_free_message(ack);

    /* Ignore irrelevant replies */
    if (gpdgc_cmp_counter(*id, client->next_sequence_number) >= 0)
    {
        g_info("%-10s: Ignore irrelevant client reply '%lu' from '%s'",
                "CLIENT", *id, label);
        gpdgc_free_message(message);
        free(label);
        free(id);
        return;
    }

    /* Get the reply corresponding to the message sequence number */
    gpdgc_server_reply *reply = gpdgc_get_server_reply(client, *id);
    if ((gpdgc_cmp_counter(*id + client->max_pending_replies,
                    client->next_sequence_number) < 0)
            || ((reply != NULL)
                && (reply->delivered
                    || gpdgc_contains_address(reply->voters, info->address))))
    {
        g_info("%-10s: Ignore already received client reply '%lu' from '%s'",
                "CLIENT", *id, label);
        gpdgc_free_message(message);
        free(label);
        free(id);
        return;
    }
    else if (reply == NULL)
    {
        g_critical("%-10s: Cannot process client reply '%lu' from '%s'",
                "CLIENT", *id, label);
        gpdgc_free_message(message);
        free(label);
        free(id);
        return;
    }
    free(id);

    size_t size = 0;
    void *content = gpdgc_pop_content(message, &size);
    gpdgc_free_message(message);

    /* Check if at least one honest server proposed it */
    unsigned short max_byzantine = gpdgc_get_expected_max_byzantine(client);
    unsigned short counter =
        gpdgc_count_similar_votes(content, size, reply->contents, reply->sizes);
    if (counter > max_byzantine)
    {
        /* Remove the pending corresponding to the reply (if any) */
        int is_last = 0;
        gpdgc_pending *pending =
            gpdgc_get_pending(client, reply->sequence_number, &is_last);
        if (pending != NULL)
        {
            gpdgc_remove_pending_message(client, pending, is_last);
        }

        /* Deliver the reply */
        if (client->state == GPDGC_READY)
        {
            g_debug("%-10s: Deliver reply '%lu'", 
                    "CLIENT", reply->sequence_number);
            reply->delivered = 1;
            gpdgc_generate_reply_output(client,
                    reply->sequence_number, content, size);
        }
        else
        {
            g_debug("%-10s: Ignore reply '%lu': client is not ready", 
                    "CLIENT", reply->sequence_number);
            free(content);
        }
    }
    else
    {
        /* Store the reply */
        size_t *size_pointer = malloc(sizeof(size_t));
        if (size_pointer != NULL)
        {
            *size_pointer = size;

            g_debug("%-10s: Store reply '%lu' from '%s'",
                    "CLIENT", reply->sequence_number, label);
            reply->voters = g_slist_append(reply->voters, info->address);
            reply->contents = g_slist_append(reply->contents, content);
            reply->sizes = g_slist_append(reply->sizes, size_pointer);
        }
        else
        {
            g_critical("%-10s: Cannot store reply '%lu' from '%s'",
                    "CLIENT", reply->sequence_number, label);
            free(content);
        }
    }
    free(label);
}


/* Deliver a network message to the client */
void gpdgc_deliver_to_client(gpdgc_iclient *client, 
        void *buffer, size_t size, struct sockaddr *sender)
{
    char *label = gpdgc_get_address_label(client->input_address);
    g_debug("%-10s: Received message (size=%lu) from '%s'", "UDP", size, label);

    /* Extract message from buffer */
    gpdgc_message *message = gpdgc_extract_contents(buffer, size);
    unsigned int first_size = gpdgc_get_content_size(message, 0);
    if ((message == NULL) || (first_size == 0))
    {
        g_info("%-10s: Cannot read message (size=%lu) from '%s'",
                "CLIENT", size, label);
        gpdgc_free_message(message);
        free(label);
        return;
    }
    free(label);

    gpdgc_enter_client_when_few_output(client);
    if ((client->state == GPDGC_CLOSED) || (client->state == GPDGC_DONE))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message from '%s': client is done",
                "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        gpdgc_leave_client(client);
        return;
    }

    gpdgc_server_info *info = gpdgc_get_server_info(client->infos, sender);
    if (info == NULL)
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message from unknown '%s'", "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        gpdgc_leave_client(client);
        return;
    }

    /* Check message signature if required */
    if ((client->channel_model == GPDGC_CORRUPTED_MODEL)
            && (!gpdgc_unsign_message(message, info->public_key)))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore unsafe message from '%s'", "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
        gpdgc_leave_client(client);
        return;
    }

    size_t type_size;
    unsigned short *type = gpdgc_pop_content(message, &type_size);
    if (type_size != sizeof(unsigned short))
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore invalid message from '%s'", "CLIENT", label);
        gpdgc_free_message(message);
        free(label);
    }
    else if (*type == GPDGC_INFORMATION_MESSAGE_TYPE)
    {
        gpdgc_process_view_info(client, message, info);
    }
    else if (*type == GPDGC_ACK_SUBSCRIPTION_MESSAGE_TYPE)
    {
        gpdgc_free_message(message);
        gpdgc_process_subscription_ack(client, 1, info->address);
    }
    else if (*type == GPDGC_NACK_SUBSCRIPTION_MESSAGE_TYPE)
    {
        gpdgc_free_message(message);
        gpdgc_process_subscription_ack(client, 0, info->address);
    }
    else if (*type == GPDGC_BROADCAST_MESSAGE_TYPE)
    {
        gpdgc_process_pending_message(client, message, info->address);
    }
    else if (*type == GPDGC_CLIENT_REPLY_MESSAGE_TYPE)
    {
        gpdgc_process_reply(client, message, info);
    }
    else
    {
        char *label = gpdgc_get_address_label(sender);
        g_info("%-10s: Ignore message with invalid type '%u' from '%s'",
                "CLIENT", *type, label);
        gpdgc_free_message(message);
        free(label);
    }
    free(type);
    gpdgc_leave_client(client);
}
