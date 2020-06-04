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
#define _GNU_SOURCE

#include <common.h>
#include <consensus.h>
#include <heardof.h>
#include <process.h>
#include <server.h>
#include <dlfcn.h>

gpdgc_message *gpdgc_build_fake_decision_message(void *vote, size_t vote_size,
        gpdgc_validation_type validation)
{
    gpdgc_message *msg = gpdgc_create_message();
    if (msg != NULL) 
    {
        if (validation == GPDGC_FULL_VALIDATION)
        {
            int push_result = gpdgc_push_content(msg, NULL, 0);
            if (!push_result)
            {
                gpdgc_free_message(msg);
                return NULL;
            }
        }

        unsigned long ts = 0;
        if ((((validation == GPDGC_FULL_VALIDATION)
                        || (validation == GPDGC_AMNESIC_VALIDATION))
                    && (!gpdgc_push_content(msg, &ts, sizeof(unsigned long))))
                || (!gpdgc_push_content(msg, vote, vote_size))) 
        {
            gpdgc_free_message(msg);
            return NULL;
        }
    }
    return msg;
}
void gpdgc_deliver_heardof_round(gpdgc_iserver *server, 
        unsigned long phase, unsigned long round)
{
    /* Prepare a fake decision */
    unsigned int nb_processes =
        g_slist_length(server->servers) + g_slist_length(server->clients);
    size_t decision_size = nb_processes * sizeof(unsigned long); 
    unsigned long *decision = malloc(decision_size);
    for (unsigned int i=0; i<nb_processes; i++)
    {
        decision[i] = rand() % 1000; 
    }
    gpdgc_message *fixed = gpdgc_build_fake_decision_message(decision,
            decision_size, server->validation);

    /* Buffer the fake decision */
    gcry_sexp_t key = gpdgc_get_channel_key(server);
    size_t size = 0;
    void *buffer = gpdgc_write_contents(fixed, key, &size);
    gpdgc_free_message(fixed);
    free(decision);

    if (buffer == NULL)
    {
        gpdgc_signal_lack_of_memory(server,
                "%-10s: Decision '%lu:%lu:%d' cannot be buffered",
                "HEARD_OF", phase, 0, GPDGC_FIXED_STEP);
        free(buffer);
        return;
    }

    /* Send the fake decision to other servers */
    g_debug("%-10s: Send fake decision '%lu:0:%d'", 
            "HEARD_OF", phase, GPDGC_FIXED_STEP);
    gpdgc_udp_server_multicast(server, buffer, size);
    free(buffer);

    /* Call original function */
    static void (*func)();
    if(!func)
    {
        func = (void (*)()) dlsym(RTLD_NEXT, "gpdgc_deliver_heardof_round");
    }
    func(server, phase, round);
}
