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

#include "broadcast.h"
#include "consensus.h"
#include "heardof.h"
#include "message.h"
#include "process.h"
#include "server.h"

/* Return the key that is used to send message over channels */
gcry_sexp_t gpdgc_get_channel_key(gpdgc_iserver *server)
{
    if (server->channel_model == GPDGC_CORRUPTED_MODEL)
    {
        return server->private_key;
    }
    return NULL;
}

/* Set the trusted key */
int gpdgc_set_trusted_key(gpdgc_iserver *server,
        gcry_sexp_t key, unsigned long identifier)
{
    g_debug("%-10s: Trusted key '%lu' has been set", "SERVER", identifier);
    if (server->trusted_key != NULL)
    {
        gcry_sexp_release(server->trusted_key);
    }
    server->trusted_key = key;
    server->trusted_key_identifier = identifier;
    gpdgc_signal_event(server, GPDGC_NEW_TRUSTED_KEY);
    return 1;
}


/* Get the maximum number of byzantine servers that are allowed */
unsigned int gpdgc_get_max_byzantine(gpdgc_iserver *server)
{
    short is_byzantine = server->process_model == GPDGC_BYZANTINE_MODEL;

    return is_byzantine ? gpdgc_get_max_faulty(server) : 0;
}

/* Get the maximum number of faulty servers that are allowed */
unsigned int gpdgc_get_max_faulty(gpdgc_iserver *server)
{
    short is_byzantine = server->process_model == GPDGC_BYZANTINE_MODEL;

    unsigned int divider = 5;
    switch (server->validation)
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
            g_critical("%-10s: Unknown validation !", "CONSENSUS");
    }
    return (g_slist_length(server->servers) - 1) / divider; 
}


/* Return true if servers may use signatures to prove honesty */
int gpdgc_has_certified_servers(gpdgc_iserver *server)
{
    return (server->private_key != NULL);
}

/* Return true if channels can be corrupted */ 
int gpdgc_has_corrupted_channels(gpdgc_iserver *server)
{
    return server->channel_model == GPDGC_CORRUPTED_MODEL;
}

/* Return true if process can be byzantine */
int gpdgc_is_byzantine_model(gpdgc_iserver *server)
{
    return server->process_model == GPDGC_BYZANTINE_MODEL;
}


/* Method being called each time a thread enters the stack */
void gpdgc_enter_stack(gpdgc_iserver *server)
{
    pthread_mutex_lock(&server->lock);
}
int gpdgc_has_stack_enough_slot(gpdgc_iserver *server)
{
    return (server->used_slot < server->max_slot) &&
        (server->used_cache < server->max_cache);
}
void gpdgc_enter_stack_when_enough_slot(gpdgc_iserver *server)
{
    gpdgc_enter_stack(server);
    while (!gpdgc_has_stack_enough_slot(server))
    {
        pthread_cond_wait(&server->slot_condition, &server->lock);
    }
}

/* Method being called each time a thread generating output enters the client */
void gpdgc_enter_stack_when_few_output(gpdgc_iserver *server)
{
    unsigned long max_pending_outputs =
        (server->max_servers + server->max_clients) * server->max_slot * 3;

    gpdgc_enter_stack(server);
    while (g_slist_length(server->outputs) >= max_pending_outputs)
    {
        pthread_cond_wait(&server->input_condition, &server->lock);
    }
}

/* Method being called each time a thread leaves the stack */
void gpdgc_leave_stack(gpdgc_iserver *server)
{
    pthread_mutex_unlock(&server->lock);
}


/* Reserve the specified amount of message slots */
void gpdgc_reserve_slot(gpdgc_iserver *server, unsigned short nb_slot)
{
    server->used_slot += nb_slot;
}

/* Release the specified amount of message slots */
void gpdgc_release_slot(gpdgc_iserver *server, unsigned short nb_slot)
{
    server->used_slot -= nb_slot;
    pthread_cond_broadcast(&server->slot_condition);
}


/* Reserve the specified amount of cache */
void gpdgc_reserve_cache(gpdgc_iserver *server, unsigned long memory_size)
{
    server->used_cache += memory_size;
}

/* Release the specified amount of cache */
void gpdgc_release_cache(gpdgc_iserver *server, unsigned long memory_size)
{
    server->used_cache -= memory_size;
    pthread_cond_broadcast(&server->slot_condition);
}


/* Signal event to the server */
void gpdgc_register_output(gpdgc_iserver *server, gpdgc_output *output)
{
    server->outputs = g_slist_append(server->outputs, output);
    pthread_cond_broadcast(&server->output_condition);
}
void gpdgc_signal_event(gpdgc_iserver *server, gpdgc_event event)
{
    /* Signal the event to the application */
    unsigned short type = GPDGC_UNKNOWN_MESSAGE_TYPE;
    gpdgc_output *output = gpdgc_create_output(type, 0, NULL, 0, NULL, event);
    if (output == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot deliver information to the application", 
                "SERVER");
        return;
    }
    gpdgc_register_output(server, output);

    /* Signal the event to the clients */
    gcry_sexp_t key = gpdgc_get_channel_key(server);
    gpdgc_message *info_message = gpdgc_get_view_info_message(server);
    if (info_message == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot build view information message", "SERVER");
        return;
    }
    free(server->view_info_cache);
    server->view_info_cache = gpdgc_write_contents(info_message, key,
            &server->view_info_cache_size);
    server->view_info_remaining_ticks = server->resend_period;
    gpdgc_free_message(info_message);

    if (server->view_info_cache == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot buffer view information message", "SERVER");
    }
    gpdgc_udp_client_multicast(server, 
            server->view_info_cache, server->view_info_cache_size);
}

/* Method being called each time a lack of memory occurs in the stack */
void gpdgc_signal_lack_of_memory(gpdgc_iserver *server, char *message, ...)
{
    va_list parameters;
    va_start(parameters, message);
    g_logv(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, message, parameters);

    /* Signal the event to the application */
    gpdgc_output *output = server->out_of_memory;
    g_assert(output != NULL);

    gpdgc_register_output(server, output);
}


/* Method being called when the local state has been changed */
void gpdgc_signal_state_change(gpdgc_iserver *server, gpdgc_state state)
{
    server->state = state;
    pthread_cond_broadcast(&server->state_condition);
}

/* Wait until the local state has been changed */
void gpdgc_wait_state_change(gpdgc_iserver *server, gpdgc_state state)
{
    while (server->state != state)
    {
        pthread_cond_wait(&server->state_condition, &server->lock);
    }
}


/* Free the memory occupied by Heardof rounds */
void gpdgc_do_free_round(gpdgc_round *round, int full)
{
    g_slist_free_full(round->votes, gpdgc_free_message);
    if ((round->message != NULL) && full)
    {
        gpdgc_free_message(round->message);
    }
    if ((round->decision != NULL) && full)
    {
        gpdgc_free_message(round->decision);
    }
    free(round);
}
void gpdgc_free_round(void *round)
{
    gpdgc_do_free_round((gpdgc_round *) round, 1);
}
void gpdgc_partial_free_round(void *round)
{
    gpdgc_do_free_round((gpdgc_round *) round, 0);
}

/* Free the memory occupied by a broadcast message */ 
void gpdgc_free_container_state(void *void_state)
{
    gpdgc_container_state *state = void_state;

    gpdgc_free_message(state->content);
    free(state);
}
void gpdgc_free_container(void *void_container)
{
    gpdgc_container *container = void_container;

    g_slist_free_full(container->states, gpdgc_free_container_state);
    gpdgc_free_message(container->content);
    free(container->content_cache);
    free(container->phase_cache);
    free(container);
}

/* Free the memory occupied by a future heardof message */
void gpdgc_free_future(void *void_future)
{
    gpdgc_future *future = (gpdgc_future *) void_future;

    gpdgc_free_message(future->message);
    free(future);
}

/* Free the memory occupied by replies to client */
void gpdgc_free_reply(void *void_reply)
{
    gpdgc_reply *reply = void_reply;

    free(reply->cache);
    free(reply);
}

/* Free the memory occupied by a process */
void gpdgc_free_process(void *void_process)
{
    gpdgc_process *process = void_process;

    g_debug("%-10s: Free %d undelivered containers of '%s'", "SERVER",
            g_slist_length(process->undelivered_containers), process->label);
    g_slist_free_full(process->undelivered_containers, gpdgc_free_container);
    g_debug("%-10s: Free %d delivered containers of '%s'", "SERVER",
            g_slist_length(process->delivered_containers), process->label);
    g_slist_free_full(process->delivered_containers, gpdgc_free_container);
    g_debug("%-10s: Free %d replies of '%s'", "SERVER",
            g_slist_length(process->replies), process->label);
    g_slist_free_full(process->replies, gpdgc_free_reply);
    g_debug("%-10s: Free %d futures of '%s'", "SERVER",
            g_slist_length(process->futures), process->label);
    g_slist_free_full(process->futures, gpdgc_free_future);

    if (process->current != NULL)
    {
        gpdgc_free_round(process->current);
    }
    gcry_sexp_release(process->public_key);
    free(process->label);
    free(process->address);
    free(process);
}


/* Get the memory/network buffer required using with the specified paramters */
size_t gpdgc_get_network_buffer_size(unsigned int nb_servers, 
        unsigned int nb_clients, int certified_servers,
        gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model,
        gpdgc_validation_type validation, size_t max_message_size)
{
    int is_corrupted = channel_model == GPDGC_CORRUPTED_MODEL;
    int is_byzantine = process_model == GPDGC_BYZANTINE_MODEL;
    int requires_key = certified_servers || is_byzantine;

    size_t ip_cost = gpdgc_get_max_address_size();
    size_t item_cost = sizeof(size_t);
    size_t key_cost = requires_key ? GPDGC_MAX_KEY_SIZE : 0;

    size_t change_size = ip_cost + key_cost + item_cost; 
    size_t content_size =
        max_message_size > change_size ? max_message_size : change_size;
    size_t msg_size = content_size + 3 * sizeof(unsigned short) 
        + sizeof(unsigned long) + ip_cost + 6 * item_cost; 

    size_t process_view_size =
        3 * item_cost + sizeof(unsigned long) + GPDGC_MAX_KEY_SIZE + ip_cost;
    size_t init_view_size = 2 * item_cost + sizeof(unsigned long) + key_cost
        + (nb_servers + nb_clients) * process_view_size;

    size_t vote_size = (nb_servers + nb_clients) * sizeof(unsigned long);
    size_t consensus_size = vote_size + item_cost;
    if ((validation == GPDGC_AMNESIC_VALIDATION)
            || (validation == GPDGC_FULL_VALIDATION))
    {
        consensus_size += sizeof(unsigned long) + item_cost;
    }
    if (validation == GPDGC_FULL_VALIDATION)
    {
        consensus_size += 20 * vote_size + item_cost;
    }
    consensus_size += 3 * (sizeof(unsigned long) + item_cost);
    if (certified_servers && is_byzantine)
    {
        consensus_size += 3 * sizeof(unsigned long)
            + GPDGC_MESSAGE_SIGNATURE_SIZE + 4 * item_cost;
    }
    consensus_size *= is_byzantine ? nb_servers : 1;

    size_t result = msg_size;
    if (init_view_size > result)
    {
        result = init_view_size;
    }
    if (consensus_size > result)
    {
        result = consensus_size;
    }
    size_t send_cost = sizeof(unsigned short) + item_cost +
        (is_corrupted ? GPDGC_MESSAGE_SIGNATURE_SIZE + item_cost : 0);
    return result + send_cost;

}
size_t gpdgc_get_server_size(gpdgc_process_fault_model process_model,
        gpdgc_channel_fault_model channel_model,
        gpdgc_validation_type validation, int certified_servers,
        unsigned int max_servers, unsigned int max_clients,
        unsigned short max_slot, unsigned long max_cache,
        unsigned int max_futures, unsigned short max_client_replies,
        size_t max_message_size, unsigned int network_buffer_size)
{
    int is_corrupted = channel_model == GPDGC_CORRUPTED_MODEL;
    int is_byzantine = process_model == GPDGC_BYZANTINE_MODEL;
    int requires_key = certified_servers || is_corrupted;

    size_t ip_cost = gpdgc_get_max_address_size();
    size_t item_cost = gpdgc_get_message_item_cost();
    size_t key_cost = requires_key ? GPDGC_MAX_KEY_SIZE : 0;
    size_t msg_cost = gpdgc_get_message_cost();
    size_t sig_cost =
        is_corrupted ? GPDGC_MESSAGE_SIGNATURE_SIZE + item_cost : 0;
    size_t vote_cost = (max_clients + max_servers) * sizeof(unsigned long);

    /* Broadcast message size */
    size_t change_size = ip_cost + key_cost + 2 * item_cost;
    size_t content_size = sizeof(unsigned short) + 2 * item_cost + msg_cost
        + (max_message_size > change_size ? max_message_size : change_size);
    size_t phase_size = sizeof(unsigned long) + item_cost + msg_cost;
    size_t payback_size =
        sizeof(unsigned short) + sizeof(unsigned long) + ip_cost;
    size_t container_cache_size = content_size + phase_size
        + 2 * (payback_size + 6 * sizeof(size_t) + sig_cost);
    size_t state_size = sizeof(gpdgc_container_state) + content_size;
    size_t container_size = sizeof(gpdgc_container) + container_cache_size
        + max_servers * (state_size + sizeof(GSList));

    /* Heardof message size */
    size_t round_item_size =
        gpdgc_get_proposition_size(max_servers, max_clients, validation);
    if (certified_servers)
    {
        round_item_size += sig_cost + 3 * (item_cost + sizeof(unsigned long));
    }
    size_t round_item_multiplier = is_byzantine ? max_servers : 1;
    size_t round_size = sizeof(gpdgc_round) 
         + round_item_multiplier * (round_item_size + sizeof(GSList));
    size_t future_size = sizeof(gpdgc_future) 
         + round_item_multiplier * (round_item_size + item_cost) + msg_cost;

    /* Client reply size */
    size_t reply_size = sizeof(gpdgc_reply) + max_message_size
         + sizeof(unsigned long) + sizeof(unsigned short) + 3 * item_cost;

    /* Processes size */
    size_t expected_view_size = max_servers * sizeof(GSList);
    size_t view_candidate_size = sizeof(gpdgc_view_candidate) + key_cost
         + (max_servers + max_clients)
         * (ip_cost + sizeof(unsigned long) + key_cost + 4 * sizeof(GSList));
    size_t view_candidates_size = max_servers * view_candidate_size;

    size_t client_candidate_size = sizeof(gpdgc_client_candidate) + ip_cost
        + sizeof (unsigned short) + item_cost 
        + max_servers * (key_cost + 2 * sizeof(GSList));
    unsigned int max_candidates =
        max_clients > max_servers ? max_clients : max_servers;
    size_t client_candidates_size = max_candidates * client_candidate_size;

    size_t server_size = sizeof(gpdgc_process) + ip_cost
        + GPDGC_MAX_PROCESS_LABEL_SIZE + key_cost + round_size
        + 3 * max_slot * (container_size + sizeof(GSList))
        + max_futures * (future_size + sizeof(GSList)); 
    size_t servers_size = max_servers * (server_size + sizeof(GSList));
    
    size_t client_size = sizeof(gpdgc_process) + ip_cost
        + GPDGC_MAX_PROCESS_LABEL_SIZE + key_cost
        + 3 * max_slot * (container_size + 2 * sizeof(GSList))
        + max_client_replies * (reply_size + sizeof(GSList));
    size_t clients_size = max_clients * (client_size + sizeof(GSList));

    /* Cache size */
    size_t clock_size = 3 * sizeof(unsigned long)
        + sizeof(unsigned short) + 4 * sizeof(size_t) + sig_cost;
    size_t process_view_size =
        3 * item_cost + sizeof(unsigned long) + GPDGC_MAX_KEY_SIZE + ip_cost;
    size_t init_view_size = 2 * item_cost + sizeof(unsigned long) + key_cost
        + (max_servers + max_clients) * process_view_size + sig_cost;
    size_t view_info_size = 5 * item_cost + sizeof(unsigned long) + key_cost
        + 3 * sizeof(unsigned short)
        + max_servers * process_view_size + sig_cost;
    size_t cache_size = clock_size + init_view_size + view_info_size;

    /* Network size */
    size_t network_size =
        3 * network_buffer_size + sizeof(struct sockaddr_storage);

    /* Heard-Of size */
    size_t ho_process_list_size = max_servers * sizeof(GSList);

    /* Consensus size */
    size_t vote_history_size = 20 * max_servers
        * (sizeof(GSList) + sizeof(gpdgc_timed_vote) + vote_cost);

    /* Broadcast size */
    size_t decision_size = (max_servers + max_clients) * sizeof(unsigned long);

    /* Output size */
    // NB: max_pendings is relatively arbitrarily large to avoid blocking input
    //     too early when outputs are not processed by application
    unsigned long max_pendings = (max_servers + max_clients) * max_slot * 5;
    size_t output_size = sizeof(gpdgc_output);
    size_t outputs_size = max_pendings * (output_size + sizeof(GSList));

    return 2 * key_cost + expected_view_size + view_candidates_size 
        + client_candidates_size + servers_size + clients_size + cache_size
        + network_size + ho_process_list_size + vote_cost + vote_history_size
        + decision_size + outputs_size + max_cache + sizeof(gpdgc_iserver);
}


/* Thread delivering outputs */
void *gpdgc_deliver_output(void *argument)
{
    gpdgc_iserver *server = argument;

    gpdgc_enter_stack(server);
    while ((server->state != GPDGC_CLOSED) && (server->state != GPDGC_DONE))
    {
        pthread_cond_wait(&server->output_condition, &server->lock);
        while (server->outputs != NULL)
        {
            gpdgc_output *output = server->outputs->data;
            server->outputs = g_slist_remove(server->outputs, output);
            pthread_cond_broadcast(&server->input_condition);
            gpdgc_leave_stack(server);

            if (output->type == GPDGC_ATOMIC_MESSAGE_TYPE)
            {
                server->adeliver(output->sender, output->id,
                        output->content, output->size);
                output->content = NULL;
            }
            else if (output->type == GPDGC_RELIABLE_MESSAGE_TYPE)
            {
                server->rdeliver(output->sender, output->id,
                        output->content, output->size);
                output->content = NULL;
            }
            else if (output->type == GPDGC_UNKNOWN_MESSAGE_TYPE)
            {
                server->inform(output->event);
            }
            else
            {
                g_error("%-10s: Unexpected output message type '%hu'",
                        "SERVER", output->type);
            }
            gpdgc_free_output(output);
            gpdgc_enter_stack(server);
        }
    }
    gpdgc_leave_stack(server);
    return NULL;
}


/* Thread issueing pending client subscriptions */
int gpdgc_any_client_subscription_to_issue(gpdgc_iserver *server)
{
    GSList *iterator = server->client_candidates;
    while (iterator != NULL)
    {
        gpdgc_client_candidate *candidate = iterator->data;
        iterator = iterator->next;

        if (candidate->status < 2)
        {
            return 1;
        }
    }
    return 0;
}
void *gpdgc_issue_client_subscriptions(void *argument)
{
    gpdgc_iserver *server = argument;

    gpdgc_enter_stack(server);
    while ((server->state != GPDGC_CLOSED) && (server->state != GPDGC_DONE))
    {
        pthread_cond_wait(&server->client_condition, &server->lock);
        while (gpdgc_any_client_subscription_to_issue(server))
        {
            gpdgc_leave_stack(server);
            gpdgc_enter_stack_when_enough_slot(server);

            GSList *iterator = server->client_candidates;
            while (iterator != NULL)
            {
                gpdgc_client_candidate *candidate = iterator->data;
                iterator = iterator->next;

                if ((candidate->status < 2)
                        && gpdgc_broadcast_client_subscription(server,
                            candidate))
                {
                    candidate->status = 2;
                    // NB: The iteration must restart to consume slot correctly
                    iterator = NULL;
                }
            }
        }
    }
    gpdgc_leave_stack(server);
    return NULL;
}


/* The method listening for incoming messages */
void* gpdgc_listen_socket(void* argument)
{
    gpdgc_iserver *server = argument;

    /* Continuously listen on the specified socket */
    size_t recv_len = 0;
    socklen_t sender_length = sizeof(struct sockaddr_storage);
    while ((server->state != GPDGC_CLOSED) && (server->state != GPDGC_DONE))
    {
        memset(server->input_buffer, 0, server->input_length);

        if ((recv_len = recvfrom(server->socket, server->input_buffer,
                                 server->input_length, 0, server->input_address,
                                 &sender_length)) > 0)
        {
            gpdgc_deliver_to_server(server,
                    server->input_buffer, recv_len, server->input_address);
        }
    }
    return NULL;
}


/* Thread sending periodically messages to ensure reliability */
void gpdgc_resend_client_candidate(gpdgc_iserver *server,
        gpdgc_client_candidate *candidate)
{
    if (candidate->remaining_ticks > 0)
    {
        candidate->remaining_ticks--;
    }
    else
    {
        char *label = gpdgc_get_address_label(candidate->client);
        g_debug("%-10s: Resend candidate feedback to '%s'", "SERVER", label);
        free(label);

        gpdgc_udp_send(server->socket, candidate->feedback,
                candidate->size, candidate->client);
        candidate->remaining_ticks = server->resend_period;
    }
}
void gpdgc_resend_clock(gpdgc_iserver *server)
{
    if (server->clock_remaining_ticks > 0)
    {
        server->clock_remaining_ticks--;
    }
    else
    {
        gpdgc_process *local = server->local;
        g_debug("%-10s: Resend clock '%lu:%lu:%lu'",
                "SERVER", local->phase, local->round, local->step);

        GSList *dst_iterator = server->servers;
        while (dst_iterator != NULL)
        {
            gpdgc_process *dst = dst_iterator->data;
            dst_iterator = dst_iterator->next;

            if ((gpdgc_cmp_process(dst, local) != 0)
                    && ((gpdgc_cmp_clock(dst->phase, dst->round, dst->step,
                                local->phase, local->round, local->step) <= 0)
                        || (gpdgc_cmp_counter(dst->phase,
                                local->phase + 2) >= 0)))
            {
                gpdgc_udp_send(server->socket, server->clock_cache,
                        server->clock_cache_size, dst->address);
            }
        }
        server->clock_remaining_ticks = server->resend_period;
    }
}
void gpdgc_resend_clean_cache(gpdgc_iserver *server)
{
    if (server->clean_cache_remaining_ticks > 0)
    {
        server->clean_cache_remaining_ticks--;
    }
    // NB: Only send the message when sufficient resources are available
    else if (gpdgc_has_stack_enough_slot(server))
    {
        unsigned long phase = server->local->removal_phase;
        unsigned short type = GPDGC_CLEAN_CACHE_MESSAGE_TYPE; 
        gpdgc_message *msg = gpdgc_create_message();
        if ((msg == NULL)
                || (!gpdgc_push_content(msg, &phase, sizeof(unsigned long))))
        {
            gpdgc_free_message(msg);
            gpdgc_signal_lack_of_memory(server,
                    "%-10s: Cannot build clean-cache", "SERVER");
            return;
        }

        server->clean_cache_remaining_ticks = server->clean_cache_period;
        g_debug("%-10s: The clean-cache '%lu' is broadcasted",
                "SERVER", phase);

        if (!gpdgc_broadcast_group_message(server, msg, type))
        {
            g_warning("%-10s: An error occurs while sending clean-cache",
                    "SERVER");
        }
    }
}
void gpdgc_resend_container(gpdgc_iserver *server,
        gpdgc_process *process, gpdgc_container *container)
{
    g_debug("%-10s: Resend container '%s:%lu'",
            "SERVER", process->label, container->sequence_number);

    int received = container->content != NULL;
    GSList *iterator = container->states;
    while (iterator != NULL)
    {
        gpdgc_container_state *state = iterator->data;
        iterator = iterator->next;

        int is_local = gpdgc_cmp_process(state->owner, server->local) == 0;
        if ((!is_local)
                && (container->content_cache != NULL) 
                && ((container->content == NULL)
                    || (!(state->flags & GPDGC_RECEIVED_STATE_FLAG))))
        {
            gpdgc_udp_send(server->socket, container->content_cache,
                    container->content_size, state->owner->address);
        }
        if ((!is_local)
                && (container->phase_cache != NULL) 
                && (container->content_type == GPDGC_RELIABLE_MESSAGE_TYPE)
                && (!(state->flags & GPDGC_PHASED_STATE_FLAG)))
        {
            gpdgc_udp_send(server->socket, container->phase_cache,
                    container->phase_size, state->owner->address);
        }
        state->last_container_resend = server->resend_period;

        received = received || (is_local && (state->content != NULL));
    }

    if (received && (process->type == GPDGC_CLIENT))
    {
        g_debug("%-10s: Resend received for client message '%s:%lu'",
                "BROADCAST", process->label, container->sequence_number);

        size_t buffer_size = 0;
        void *buffer = gpdgc_build_empty_message(server, process,
                container->sequence_number, container->content_type,
                1, &buffer_size);
        gpdgc_udp_send(server->socket, buffer, buffer_size, process->address);
        free(buffer);
    }
    else if ((!received) 
            && (process->type == GPDGC_CLIENT)
            && (container->content_cache != NULL))
    {
        g_debug("%-10s: Resend request for missing client message '%s:%lu'",
                "BROADCAST", process->label, container->sequence_number);
        gpdgc_udp_send(server->socket, container->content_cache,
                container->content_size, process->address);
    }
}
void gpdgc_resend_containers(gpdgc_iserver *server, gpdgc_process *process)
{
    GSList *container_iterator = process->undelivered_containers;
    while (container_iterator != NULL)
    {
        gpdgc_container *container = container_iterator->data;
        container_iterator = container_iterator->next;

        if (container->remaining_ticks > 0)
        {
            container->remaining_ticks--;
        }
        else
        {
            gpdgc_resend_container(server, process, container);
            container->remaining_ticks = server->resend_period;
        }
    }
    container_iterator = process->delivered_containers;
    while (container_iterator != NULL)
    {
        gpdgc_container *container = container_iterator->data;
        container_iterator = container_iterator->next;

        if (container->remaining_ticks > 0)
        {
            container->remaining_ticks--;
        }
        else
        {
            gpdgc_resend_container(server, process, container);
            container->remaining_ticks = server->resend_period;
        }
    }
}
void gpdgc_resend_init_view(gpdgc_iserver *server)
{
    if (server->init_view_remaining_ticks > 0)
    {
        server->init_view_remaining_ticks--;
    }
    else
    {
        GSList *dst_iterator = server->servers;
        while (dst_iterator != NULL)
        {
            gpdgc_process *dst = dst_iterator->data;
            dst_iterator = dst_iterator->next;

            if (!dst->last_view_aware)
            {
                g_debug("%-10s: Resend initial view to '%s'",
                        "SERVER", dst->label);

                gpdgc_udp_send(server->socket, server->init_view_cache,
                        server->init_view_cache_size, dst->address);
            }
        }
        server->init_view_remaining_ticks = server->resend_period;
    }
}
void gpdgc_resend_view_info(gpdgc_iserver *server)
{
    if (server->view_info_remaining_ticks > 0)
    {
        server->view_info_remaining_ticks--;
    }
    else
    {
        GSList *dst_iterator = server->clients;
        while (dst_iterator != NULL)
        {
            gpdgc_process *dst = dst_iterator->data;
            dst_iterator = dst_iterator->next;

            if (!dst->last_view_aware)
            {
                g_debug("%-10s: Resend view info to '%s'",
                        "SERVER", dst->label);

                gpdgc_udp_send(server->socket, server->view_info_cache,
                        server->view_info_cache_size, dst->address);
            }
        }
        server->view_info_remaining_ticks = server->resend_period;
    }
}
void gpdgc_resend_replies(gpdgc_iserver *server, gpdgc_process *process)
{
    GSList *reply_iterator = process->replies; 
    while (reply_iterator != NULL)
    {
        gpdgc_reply *reply = reply_iterator->data;
        reply_iterator = reply_iterator->next;

        if (reply->remaining_ticks > 0)
        {
            reply->remaining_ticks--;
        }
        else
        {
            g_debug("%-10s: Resend reply '%lu' to '%s'",
                    "SERVER", reply->id, process->label);

            gpdgc_udp_send(server->socket,
                    reply->cache, reply->size, process->address);
            reply->remaining_ticks = server->resend_period;
        }
    }
}
void *gpdgc_periodically_resend(void *argument)
{
    gpdgc_iserver *server = argument;
    gulong tick_period = 1000 * server->tick_length;

    while ((server->state != GPDGC_CLOSED) && (server->state != GPDGC_DONE))
    {
        g_usleep(tick_period);

        gpdgc_enter_stack(server);
        if ((server->state != GPDGC_CLOSED) && (server->state != GPDGC_DONE))
        {
            /* Send clock to the 
             * (1) servers that are later than local process, or
             * (2) servers that have 2 consensus decisions in advances */
            if (server->clock_cache != NULL)
            {
                gpdgc_resend_clock(server);
            }

            /* Send the clean cache mmessage */
            if (server->previouses != NULL)
            {
                gpdgc_resend_clean_cache(server);
            }
            
            /* Check end of round step */
            if (server->round_flags & GPDGC_ROUND_PENDING_FLAG) 
            {
                if (server->step_remaining_ticks > 0)
                {
                    server->step_remaining_ticks--;
                }
                else
                {
                    gpdgc_leave_stack(server);
                    gpdgc_enter_stack_when_few_output(server);
                    gpdgc_check_end_of_heardof_step(server, 1);
                }
            }

            /* Send view information to servers */
            if (server->init_view_cache != NULL)
            {
                gpdgc_resend_init_view(server);
            }

            /* Send view information to clients */
            if (server->view_info_cache != NULL)
            {
                gpdgc_resend_view_info(server);
            }

            /* Send server broadcasts */
            GSList *server_iterator = server->servers;
            while (server_iterator != NULL)
            {
                gpdgc_process *proc = server_iterator->data;
                server_iterator = server_iterator->next;

                gpdgc_resend_containers(server, proc);
            }

            /* Send client broadcasts and replies */
            GSList *client_iterator = server->clients;
            while (client_iterator != NULL)
            {
                gpdgc_process *client = client_iterator->data;
                client_iterator = client_iterator->next;

                gpdgc_resend_containers(server, client);
                gpdgc_resend_replies(server, client);
            }

            /* Send client feedbacks */
            GSList *candidate_iterator = server->client_candidates;
            while (candidate_iterator != NULL)
            {
                gpdgc_client_candidate *candidate = candidate_iterator->data;
                candidate_iterator = candidate_iterator->next;

                gpdgc_resend_client_candidate(server, candidate);
            }
        }
        gpdgc_leave_stack(server);
    }
    return NULL;
}


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
        void (*inform) (gpdgc_event event))
{
    /* Check memory setting */
    if (max_slot == 0)
    {
        g_error("%-10s: The maximum number of local slot must be > 0", "INIT");
    }

    /* Check resend period */
    if ((tick_length == 0) || (round_window_increment == 0))
    {
        g_error("%-10s: Increment and tick must be greater than 0", "INIT");
    }
    if ((clean_cache_period == 0)
            || (resend_period == 0) || (clock_period == 0))
    {
        g_error("%-10s: Periods must be greater than 0", "INIT");
    }
    if (max_message_size == 0)
    {
        g_error("%-10s: Messages without content do not require GPDGC", "INIT");
    }
    if (max_client_replies == 0)
    {
        g_error("%-10s: At least one client replies must be allowed", "INIT");
    }
    if (minimal_resend_period > resend_period)
    {
        g_error("%-10s: The minimal resend period (%u) must be smaller or "
                "equal to resend period (%u)",
                "INIT", minimal_resend_period, resend_period); 
    }

    /* Check size of network buffer */
    size_t required_network = gpdgc_get_network_buffer_size(max_servers, 
            max_clients, private_key != NULL, process_model, channel_model,
            validation, max_message_size);
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
    gpdgc_iserver *result = malloc(sizeof(gpdgc_iserver));
    if (result == NULL)
    {
        g_error("%-10s: Cannot create group communication server: "
                "lack of memory", "INIT");
    }
    
    /* Init algorithm configuration */
    result->process_model = process_model;
    result->channel_model = channel_model;
    result->validation = validation;
    result->election = election;

    /* Init limits configuration */
    result->max_clients = max_clients;
    result->max_servers = max_servers;
    result->max_futures = max_futures;
    result->max_slot = max_slot;
    result->max_retention_cache = max_retention_cache;
    result->max_cache = max_cache;
    result->max_message_size = max_message_size;
    result->max_client_replies = max_client_replies;

    /* Init periodic events configuration */
    result->tick_length = tick_length;
    result->clean_cache_period = clean_cache_period;
    result->clock_period = clock_period;
    result->minimal_resend_period = minimal_resend_period;
    result->resend_period = resend_period;
    result->round_period_initial = round_window_initial;
    result->round_period_increment = round_window_increment;

    /* Init state variables */
    result->used_slot = 0;
    result->used_cache = 0;
    result->state = GPDGC_CREATED;
    
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
    result->init_view_cache = NULL;
    result->init_view_cache_size = 0;
    result->init_view_remaining_ticks = 0;
    result->view_info_identifier = 0;
    result->view_info_cache = NULL;
    result->view_info_cache_size = 0;
    result->view_info_remaining_ticks = 0;
    result->clock_cache = NULL;
    result->clock_cache_size = 0;
    result->clock_remaining_ticks = 0;
    result->clean_cache_remaining_ticks = clean_cache_period;

    /* Init processes variables */
    result->local = gpdgc_create_process(self, GPDGC_SERVER, public_key, 0);
    result->private_key = private_key;
    result->view_identifier = 0;
    result->trusted_key = NULL;
    result->trusted_key_identifier = 0;
    result->expected_view = NULL;
    result->view_candidates = NULL;
    result->key_candidates = NULL;
    result->previouses = NULL;
    result->clients = NULL;
    result->client_candidates = NULL;
    result->client_exclusions = NULL;
    result->client_thread = 0;
    result->servers = NULL;
    result->server_candidates = NULL;
    result->server_candidate_keys = NULL;
    result->server_exclusions = NULL;

    /* Init lock variables */
    pthread_mutex_init(&result->lock, NULL);
    pthread_cond_init(&result->client_condition, NULL);
    pthread_cond_init(&result->input_condition, NULL);
    pthread_cond_init(&result->output_condition, NULL);
    pthread_cond_init(&result->slot_condition, NULL);
    pthread_cond_init(&result->state_condition, NULL);
    
    /* Init heardof variables */
    result->round_flags = 0;
    result->step_remaining_ticks = 0;
    
    /* Init consensus variables */
    result->coordinator = NULL;
    result->selection_flags = 0;
    result->vote = NULL;
    result->vote_size = 0;
    result->vote_ts = 0;
    result->vote_history = NULL;
    result->previous_decisions = NULL;
    
    /* Init broadcast variables */
    result->current_decision = NULL;
    result->next_phase = 0;
    result->next_sequence_number = 0;

    /* Init callback methods and variables */
    result->output_thread = 0;
    result->outputs = NULL;
    result->adeliver = adeliver;
    result->rdeliver = rdeliver;
    result->inform = inform;

    /* Create the event signaling out of memory */
    unsigned short out_type = GPDGC_UNKNOWN_MESSAGE_TYPE;
    result->out_of_memory =
        gpdgc_create_output(out_type, 0, NULL, 0, NULL, GPDGC_OUT_OF_MEMORY);
    if (result->out_of_memory == NULL)
    {
        g_error("%-10s: Cannot create the group communication server: "
                "lack of memory", "INIT");
    }

    /* Run the thread for re-sending messages */
    if (pthread_create(&result->resend_thread, NULL,
                &gpdgc_periodically_resend, result) != 0)
    {
        g_error("%-10s: Cannot start re-sender thread", "INIT");
    }

    /* Run the thread for delivering output */
    if (pthread_create(&result->output_thread, NULL,
                &gpdgc_deliver_output, result) != 0)
    {
        g_error("%-10s: Cannot start output deliverer thread", "INIT");
    }

    /* Run the thread for issuing client subscriptions */
    if (pthread_create(&result->client_thread, NULL,
                &gpdgc_issue_client_subscriptions, result) != 0)
    {
        g_error("%-10s: Cannot start client subscriptions thread", "INIT");
    }

    /* Run the thread listening for udp messages */
    if (pthread_create(&result->input_thread, NULL,
                &gpdgc_listen_socket, result) != 0)
    {
        g_error("%-10s: Cannot start input listener thread", "INIT");
    }

    g_debug("%-10s: The server has been initialized", "INIT");
    return result;
}


/* Method to stop internally the server */
void gpdgc_internally_close_server(gpdgc_iserver *server)
{
    /* Clean cache */
    free(server->init_view_cache);
    server->init_view_cache = NULL;
    free(server->view_info_cache);
    server->view_info_cache = NULL;
    free(server->clock_cache);
    server->clock_cache = NULL;

    /* Clean process variables */
    g_debug("%-10s: Free %d address in expected view",
            "SERVER", g_slist_length(server->expected_view));
    g_slist_free_full(server->expected_view, free);
    server->expected_view = NULL;
    g_debug("%-10s: Free %d view candidates",
            "SERVER", g_slist_length(server->view_candidates));
    g_slist_free_full(server->view_candidates, gpdgc_free_view_candidate);
    server->view_candidates = NULL;
    g_debug("%-10s: Free %d key candidates",
            "SERVER", g_slist_length(server->key_candidates));
    g_slist_free_full(server->key_candidates, gpdgc_free_message);
    server->key_candidates = NULL;

    g_debug("%-10s: Remove %d clients",
            "SERVER", g_slist_length(server->clients));
    while (server->clients != NULL)
    {
        gpdgc_process *client = server->clients->data;
        gpdgc_remove_client(server, client->address);
    }
    g_debug("%-10s: Free %d client candidates",
            "SERVER", g_slist_length(server->client_candidates));
    g_slist_free_full(server->client_candidates, gpdgc_free_client_candidate);
    server->client_candidates = NULL;
    g_debug("%-10s: Free %d client exclusions",
            "SERVER", g_slist_length(server->client_exclusions));
    g_slist_free_full(server->client_exclusions, free);
    server->client_exclusions = NULL;

    g_debug("%-10s: Remove %d servers",
            "SERVER", g_slist_length(server->servers));
    while (server->servers != NULL)
    {
        gpdgc_process *srv = server->servers->data;
        gpdgc_remove_server(server, srv->address);
    }
    g_debug("%-10s: Free %d server candidates",
            "SERVER", g_slist_length(server->server_candidates));
    g_slist_free_full(server->server_candidates, free); 
    server->server_candidates = NULL;
    g_debug("%-10s: Free %d server key candidates",
            "SERVER", g_slist_length(server->server_candidate_keys));
    g_slist_free_full(server->server_candidate_keys, free); 
    server->server_candidate_keys = NULL;
    g_debug("%-10s: Free %d server exclusions",
            "SERVER", g_slist_length(server->server_exclusions));
    g_slist_free_full(server->server_exclusions, free);
    server->server_exclusions = NULL;

    /* Clean consensus variables */
    free(server->vote);
    server->vote = NULL;
    g_slist_free_full(server->vote_history, gpdgc_free_timed_vote);
    server->vote_history = NULL;
    g_debug("%-10s: Free %d previous decisions",
            "SERVER", g_slist_length(server->previous_decisions));
    g_slist_free_full(server->previous_decisions, gpdgc_free_timed_vote);
    server->previous_decisions = NULL;

    /* Clean broadcast variables */
    free(server->current_decision);
    server->current_decision = NULL;

    gpdgc_release_slot(server, server->used_slot);
    gpdgc_release_cache(server, server->used_cache);

    /* Signal state change */
    gpdgc_signal_state_change(server, GPDGC_DONE);
}

/* Close a group communication server */
void gpdgc_close_server(gpdgc_server void_server)
{
    gpdgc_iserver *server = void_server;
    gpdgc_message *end = gpdgc_create_message();
    if ((end == NULL) || (!gpdgc_push_content(end, NULL, 0)))
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to build socket-end message", "SERVER");
        return;
    }
    size_t size = 0;
    void *buffer = gpdgc_write_contents(end, NULL, &size);
    gpdgc_free_message(end);
    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to buffer socket-end message", "SERVER");
        return;
    }

    g_debug("%-10s: Close the server", "SERVER");

    gpdgc_enter_stack(server);
    gpdgc_internally_close_server(server);
    gpdgc_signal_state_change(server, GPDGC_CLOSED);
    g_debug("%-10s: Send closing signals", "SERVER");
    pthread_cond_broadcast(&server->client_condition);
    pthread_cond_broadcast(&server->input_condition);
    pthread_cond_broadcast(&server->output_condition);
    size_t local_size = gpdgc_get_address_size(server->local->address);
    sendto(server->socket, buffer, size, 0, server->local->address, local_size);
    free(buffer);
    gpdgc_leave_stack(server);

    pthread_join(server->input_thread, NULL);
    g_debug("%-10s: Input thread terminated", "SERVER");
    pthread_join(server->client_thread, NULL);
    g_debug("%-10s: Client thread terminated", "SERVER");
    pthread_join(server->output_thread, NULL);
    g_debug("%-10s: Output thread terminated", "SERVER");
    pthread_join(server->resend_thread, NULL);  
    g_debug("%-10s: Resend thread terminated", "SERVER");

    gpdgc_enter_stack(server);
    close(server->socket);
    free(server->input_buffer);
    free(server->input_address);
    gcry_sexp_release(server->trusted_key);
    gcry_sexp_release(server->private_key);
    gpdgc_leave_stack(server);

    pthread_mutex_destroy(&server->lock);
    pthread_cond_destroy(&server->client_condition);
    pthread_cond_destroy(&server->input_condition);
    pthread_cond_destroy(&server->output_condition);
    pthread_cond_destroy(&server->slot_condition);
    pthread_cond_destroy(&server->state_condition);

    g_debug("%-10s: Free %d previous processes",
            "SERVER", g_slist_length(server->previouses));
    g_slist_free_full(server->previouses, gpdgc_free_process);
    g_debug("%-10s: Free %d outputs",
            "SERVER", g_slist_length(server->outputs));
    g_slist_free_full(server->outputs, gpdgc_free_output);
    free(server->out_of_memory);
    free(server);
}


/* Get the current clients */
GSList *gpdgc_get_current_clients(gpdgc_server server)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iserver *) server)->clients;
    while (iterator != NULL)
    {
        gpdgc_process *client = iterator->data;
        iterator = iterator->next;

        result = g_slist_append(result, client->address);
    }
    return result;
}

/* Get the current view */
GSList *gpdgc_get_current_view(gpdgc_server server)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iserver *) server)->servers;
    while (iterator != NULL)
    {
        gpdgc_process *server = iterator->data;
        iterator = iterator->next;

        result = g_slist_append(result, server->address);
    }
    return result;
}

/* Get the server suspected to be crashed */
GSList *gpdgc_get_byzantine_suspiscions(gpdgc_server server)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iserver *) server)->servers;
    while (iterator != NULL)
    {
        gpdgc_process *server = iterator->data;
        iterator = iterator->next;

        if (server->suspiscion_flags & GPDGC_BYZANTINE_FLAG)
        {
            result = g_slist_append(result, server->address);
        }
    }
    return result;
}

/* Get the server suspected to be byzantine */
GSList *gpdgc_get_crash_suspiscions(gpdgc_server server)
{
    GSList *result = NULL;
    GSList *iterator = ((gpdgc_iserver *) server)->servers;
    while (iterator != NULL)
    {
        gpdgc_process *server = iterator->data;
        iterator = iterator->next;

        if (server->suspiscion_flags & GPDGC_CRASHED_FLAG)
        {
            result = g_slist_append(result, server->address);
        }
    }
    return result;
}


/* Set the initial view */
int gpdgc_init_view(gpdgc_server void_server,
        GSList *addresses, GSList *keys, gcry_sexp_t trusted_key)
{
    gpdgc_iserver *server = void_server;
    if (!gpdgc_contains_address(addresses, server->local->address))
    {
        g_critical("%-10s: Unable to init the view of the server: "
                "the local process is not part of the view", "SERVER");
        return 0;
    }
    if (g_slist_length(addresses) > server->max_servers)
    {
        g_critical("%-10s: Unable to init the view of the server: "
                "invalid number of servers (%u > %u)", "SERVER", 
                g_slist_length(addresses), server->max_servers);
        return 0;
    }

    gpdgc_enter_stack(server);
    if (server->state != GPDGC_CREATED)
    {
        g_critical("%-10s: Unable to init the view of the server: "
                "a view has already been initialised", "SERVER");
        gpdgc_leave_stack(server);
        return 0;
    }
    int result = gpdgc_set_initial_view(server, addresses, keys,
            NULL, NULL, NULL, NULL, 0, 0)
        && gpdgc_set_trusted_key(server, trusted_key, 0);
    gpdgc_leave_stack(server);
    return result;
}


/* Wait until the server has integrated the view */
int gpdgc_integrate_view(gpdgc_server void_server, GSList *view)
{
    if (view == NULL)
    {
        return 0;
    }

    gpdgc_iserver *server = void_server;
    if (g_slist_length(view) > server->max_servers)
    {
        g_critical("%-10s: Unable to init the view of the server: "
                "invalid number of servers (%u > %u)", "SERVER", 
                g_slist_length(view), server->max_servers);
        return 0;
    }

    gpdgc_enter_stack(server);
    if (server->state != GPDGC_CREATED)
    {
        g_critical("%-10s: Unable to init the view of the server: "
                "a view has already been initialised", "SERVER");
        gpdgc_leave_stack(server);
        return 0;
    }
    gpdgc_set_expected_view(server, view);

    gpdgc_wait_state_change(server, GPDGC_READY);
    gpdgc_leave_stack(server);
    return 1;
}


/* Send reliable and totally ordered messages */
int gpdgc_atomic_broadcast(gpdgc_server void_server, void *content, size_t size)
{
    gpdgc_iserver *server = void_server;
    if (size > server->max_message_size)
    {
        g_critical("%-10s: Unable to a-broadcast message: message is too big "
                "%lu > %lu", "SERVER", size, server->max_message_size);
        return 0;
    }

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL) || (!gpdgc_push_content(msg, content, size))) 
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to a-broadcast message", "SERVER");
        gpdgc_free_message(msg);
        return 0;
    }

    gpdgc_enter_stack_when_enough_slot(server);
    if (server->state != GPDGC_READY)
    {
        g_warning("%-10s: Unable to a-broadcsat message: "
                "no view has been initialised", "SERVER");
        gpdgc_free_message(msg);
        gpdgc_leave_stack(server);
        return 0;
    }
    int result =
        gpdgc_broadcast_group_message(server, msg, GPDGC_ATOMIC_MESSAGE_TYPE);
    gpdgc_leave_stack(server);
    return result;
}


/* Send reliable messages */
int gpdgc_reliable_broadcast(gpdgc_server v_server, void *content, size_t size)
{
    gpdgc_iserver *server = v_server;
    if (size > server->max_message_size)
    {
        g_critical("%-10s: Unable to r-broadcast message: message is too big "
                "%lu > %lu", "SERVER", size, server->max_message_size);
        return 0;
    }

    gpdgc_message *msg = gpdgc_create_message();
    if ((msg == NULL) || (!gpdgc_push_content(msg, content, size))) 
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Unable to r-broadcast message", "SERVER");
        gpdgc_free_message(msg);
        return 0;
    }

    gpdgc_enter_stack_when_enough_slot(server);
    if (server->state != GPDGC_READY)
    {
        g_warning("%-10s: Unable to r-broadcast message: "
                "no view has been initialised", "SERVER");
        gpdgc_free_message(msg);
        gpdgc_leave_stack(server);
        return 0;
    }
    int result =
        gpdgc_broadcast_group_message(server, msg, GPDGC_RELIABLE_MESSAGE_TYPE);
    gpdgc_leave_stack(server);
    return result;
}


/* Send a message to a client as a response to the previous request 'id' */
int gpdgc_send_reply_to_client(gpdgc_server void_server, unsigned long id,
        void *message, size_t size, struct sockaddr *address)
{
    gpdgc_iserver *server = void_server;
    if (size > server->max_message_size)
    {
        g_critical("%-10s: Unable to issue client reply: message is too big "
                "%lu > %lu", "SERVER", size, server->max_message_size);
        return 0;
    }

    gpdgc_enter_stack(server);
    if (server->state != GPDGC_READY)
    {
        g_warning("%-10s: Unable to issue client reply: "
                "no view has been initialised", "SERVER");
        gpdgc_leave_stack(server);
        return 0;
    }

    gpdgc_process *client = gpdgc_get_process(server, address);
    if ((client == NULL) || (client->type == GPDGC_SERVER))
    {
        char *label = gpdgc_get_address_label(address);
        g_warning("%-10s: Unable to issue client reply: client '%s' is unknown",
                "SERVER", label);
        gpdgc_leave_stack(server);
        free(label);
        return 0;
    }

    int result = gpdgc_send_client_reply(server, id, message, size, client);
    gpdgc_leave_stack(server);
    return result;
}


/* Deliver a network message to the server */
void gpdgc_deliver_to_server_from_known(gpdgc_iserver *server,
        gpdgc_message *message, gpdgc_process *sender)
{
    /* Check message signature if required */
    if (gpdgc_has_corrupted_channels(server)
            && (!gpdgc_unsign_message(message, sender->public_key)))
    {
        g_info("%-10s: Ignore unsafe message from '%s'",
                "SERVER", sender->label);
        gpdgc_free_message(message);
        return;
    }

    /* Extract the message type and process the message accordingly */
    size_t size;
    unsigned short *type = gpdgc_pop_content(message, &size);    
    if (size != sizeof(unsigned short))
    {
        g_info("%-10s: Ignore invalid message from '%s'",
                "SERVER", sender->label);
        gpdgc_free_message(message);
    }
    else if ((sender->type == GPDGC_SERVER)
            && (*type == GPDGC_HEARDOF_MESSAGE_TYPE))
    {
        g_debug("%-10s: Deliver a message from '%s' to heard-of",
                "SERVER", sender->label);
        gpdgc_deliver_to_heardof(server, message, sender);
    }
    else if (*type == GPDGC_BROADCAST_MESSAGE_TYPE)
    {
        g_debug("%-10s: Deliver a message from '%s' to broadcast",
                "SERVER", sender->label);
        gpdgc_deliver_to_broadcast(server, message, sender);
    }
    else if ((sender->type == GPDGC_CLIENT)
            && (*type == GPDGC_ACK_INFORMATION_MESSAGE_TYPE))
    {
        size_t sn_size;
        unsigned long *sn = gpdgc_pop_content(message, &sn_size);
        gpdgc_free_message(message);
        if (sn_size != sizeof(unsigned long))
        {
            g_info("%-10s: Invalid info-accept from client '%s' is ignored",
                    "SERVER", sender->label);
            free(type);
            free(sn);
            return;
        }

        if ((*sn == server->view_info_identifier) && (!sender->last_view_aware))
        {
            g_debug("%-10s: Close client candidate '%s'",
                    "SERVER", sender->label);
            sender->last_view_aware = 1;
            gpdgc_close_client_candidate(server, sender->address);
        }
        free(sn);
    }
    else if ((sender->type == GPDGC_CLIENT)
            && (*type == GPDGC_ACK_CLIENT_REPLY_MESSAGE_TYPE))
    {
        size_t sn_size;
        unsigned long *sn = gpdgc_pop_content(message, &sn_size);
        gpdgc_free_message(message);
        if (sn_size != sizeof(unsigned long))
        {
            g_info("%-10s: Invalid reply-accept from client '%s' is ignored",
                    "SERVER", sender->label);
            free(type);
            free(sn);
        }

        GSList *reply_iterator = sender->replies;
        while (reply_iterator != NULL)
        {
            gpdgc_reply *reply = reply_iterator->data;
            reply_iterator = reply_iterator->next;

            if (reply->id == *sn)
            {
                g_debug("%-10s: Remove reply '%s:%ld': client received it",
                        "SERVER", sender->label, reply->id);
                sender->replies = g_slist_remove(sender->replies, reply);
                gpdgc_free_reply(reply);
            }
        }
        free(sn);
    }
    else
    {
        g_info("%-10s: Ignore '%u' message from '%s' of type '%d'",
                "SERVER", *type, sender->label, sender->type);
        gpdgc_free_message(message);
    }
    free(type);
}
void gpdgc_deliver_to_server_from_unknown(gpdgc_iserver *server,
        gpdgc_message *message, struct sockaddr *address)
{
    char *label = gpdgc_get_address_label(address);
    size_t size;
    unsigned short *type = gpdgc_pop_content(message, &size);
    if (size != sizeof(unsigned short))
    {
        g_info("%-10s: Ignore invalid message from '%s'", "SERVER", label);
        gpdgc_free_message(message);
    }
    else if (*type == GPDGC_CANDIDATE_MESSAGE_TYPE)
    {
        if ((server->state != GPDGC_WAITING)
                && (server->state != GPDGC_CREATED))
        {
            g_info("%-10s: The candidate from '%s' is ignored: "
                    "a view is already locally installed", "SERVER", label);
            gpdgc_free_message(message);
        }
        else
        {
            g_debug("%-10s: Deliver a view candidate from '%s'",
                    "SERVER", label);
            gpdgc_deliver_view_candidate(server, message, address);
        }
    }
    else if (*type == GPDGC_SUBSCRIPTION_MESSAGE_TYPE)
    {
        if (server->state != GPDGC_READY)
        {
            g_info("%-10s: Ignore message from '%s': server is not ready",
                    "SERVER", label);
            gpdgc_free_message(message);
        }
        else
        {
            g_debug("%-10s: Deliver a client candidate from '%s'",
                    "SERVER", label);
            gpdgc_initiate_client_candidate(server, message, address);
        }
    }
    else
    {
        g_info("%-10s: Ignore '%u' message from unknown process '%s'",
                "SERVER", *type, label);
        gpdgc_free_message(message);
    }
    free(label);
    free(type);
}
void gpdgc_deliver_to_server(gpdgc_iserver *server,
        void *buffer, size_t size, struct sockaddr *address)
{
    char *label = gpdgc_get_address_label(address);
    g_debug("%-10s: Received message (size=%lu) from '%s'", "UDP", size, label);

    /* Extract message from buffer */
    gpdgc_message *message = gpdgc_extract_contents(buffer, size);
    unsigned int first_size = gpdgc_get_content_size(message, 0);
    if ((message == NULL) || (first_size == 0))
    {
        g_info("%-10s: Cannot read message (size=%lu) from '%s'",
                "SERVER", size, label);
        gpdgc_free_message(message);
        free(label);
        return;
    }
    free(label);

    gpdgc_enter_stack_when_few_output(server);
    gpdgc_process *sender = gpdgc_get_process(server, address);

    /* Process message from unknown sources: view or client candidates */
    if (sender == NULL)
    {
        gpdgc_deliver_to_server_from_unknown(server, message, address);
        gpdgc_leave_stack(server);
        return;
    }
    else if (server->state != GPDGC_READY)
    {
        g_info("%-10s: Ignore message from '%s': server is not ready",
                "SERVER", sender->label);
        gpdgc_free_message(message);
        gpdgc_leave_stack(server);
        return;
    }

    gpdgc_deliver_to_server_from_known(server, message, sender);
    gpdgc_leave_stack(server);
}


/* Deliver ordered or non-ordered messages to the server */
void gpdgc_deliver_broadcast_message(gpdgc_iserver *server, unsigned long id, 
        unsigned short type, gpdgc_message *message, gpdgc_process *origin)
{
    size_t size = 0;
    void *content = gpdgc_pop_content(message, &size);
    gpdgc_free_message(message);

    gpdgc_output *output = gpdgc_create_output(type, id, content, size,
            origin->address, GPDGC_SUSPISCION);
    if (output == NULL)
    {
        free(content);
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Cannot deliver broadcast message", "SERVER");
        return; 
    }
    gpdgc_register_output(server, output);
}
