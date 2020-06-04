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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "message.h"

#define GPDGC_HASH_ALGORITHM GCRY_MD_SHA256

/* Message content: definitions and methods */
typedef struct
{
    void *content;
    size_t size;
} gpdgc_content;

void gpdgc_free_content(void *void_content)
{
    gpdgc_content *content = void_content;
    
    free(content->content);
    free(content);
}
gpdgc_content *gpdgc_clone_content(const gpdgc_content *content, void *userdata)
{
    UNUSED(userdata);

    gpdgc_content *result = malloc(sizeof(gpdgc_content));
    if (result == NULL)
    {
        return result;      
    }

    result->size = content->size;
    result->content = result->size > 0 ? malloc(result->size) : NULL;
    if (result->size > 0)
    {
        if (result->content  == NULL)
        {
            free(result);
            return NULL;
        }
        memcpy(result->content, content->content, content->size);
    }
    return result;
}
int gpdgc_cmp_content(gpdgc_content *first, gpdgc_content *second)
{
    size_t min_size = first->size > second->size ? second->size : first->size;
    int cmp_content = memcmp(first->content, second->content, min_size);
    if (cmp_content == 0)
    {
        if (first->size > second->size)
        {
            return 1;
        }
        if (first->size < second->size)
        {
            return -1;
        }
        return 0;
    }
    return cmp_content;
}


/* Get the memory cost of a message */
size_t gpdgc_get_message_cost()
{
    return sizeof(gpdgc_message) + gpdgc_get_max_address_size();
}
/* Get the memory cost of an item in a message */
size_t gpdgc_get_message_item_cost()
{
    return sizeof(GSList) + sizeof(gpdgc_content);
}


/* Create a message */
gpdgc_message *gpdgc_create_message()
{
    gpdgc_message *result = malloc(sizeof(gpdgc_message));
    if (result != NULL)
    {
        result->contents = NULL;
    }
    return result;
}

/* Clone a message */
gpdgc_message *gpdgc_clone_message(gpdgc_message *msg)
{
    gpdgc_message *result = gpdgc_create_message();
    if (result == NULL)
    {
        return NULL;
    }
    result->contents = g_slist_copy_deep(msg->contents,
            (void * (*)(const void *, void *)) gpdgc_clone_content, NULL);

    /* Check that all contents has been correctly cloned */
    GSList *iterator = result->contents;
    while (iterator != NULL)
    {
        if (iterator->data == NULL)
        {
            /* An error occured during the clone => free memory */
            gpdgc_free_message(result);
            return NULL;
        }
        iterator = iterator->next;
    }  
    return result;
}

/* Free the memory occupied by the specified message */
void gpdgc_free_message(void *void_message)
{
    gpdgc_message *message = void_message;
    if (message != NULL)
    {
        g_slist_free_full(message->contents, gpdgc_free_content);
        free(message);
    }
}


/* Get the number of contents in a message */
unsigned int gpdgc_get_message_length(gpdgc_message *msg)
{
    return g_slist_length(msg->contents);
}

/* Get the size of the message in memory */ 
size_t gpdgc_get_message_size(gpdgc_message *msg)
{
    size_t result = sizeof(gpdgc_message);

    GSList *iterator = msg->contents;
    while (iterator != NULL)
    {
        gpdgc_content *content = (gpdgc_content *) iterator->data;

        result += gpdgc_get_message_item_cost() + content->size; 
        iterator = iterator->next; 
    }
    return result;
}


/* Extract a message from a buffer */
GSList *gpdgc_do_extract_contents(void *buffer, size_t size)
{
    GSList *result = NULL;

    /* Read the buffer */ 
    size_t read_size = 0;
    while ((read_size < size) && (size - read_size >= sizeof(size_t)))
    {
        gpdgc_content *item = malloc(sizeof(gpdgc_content));
        if (item == NULL)
        {
            g_slist_free_full(result, gpdgc_free_content);
            return NULL;
        }

        /* Extract the size of the content */
        memcpy(&item->size, ((char *) buffer) + read_size, sizeof(size_t));
        read_size += sizeof(size_t);
        if ((read_size + item->size > size) || (item->size & ~(SIZE_MAX >> 1)))
        {
            free(item);
            g_slist_free_full(result, gpdgc_free_content);
            return NULL;	  
        }

        /* Extract the content */
        item->content = NULL;
        if (item->size > 0)
        {
            item->content = malloc(item->size);
            if (item->content == NULL)
            {
                free(item->content);
                free(item);
                g_slist_free_full(result, gpdgc_free_content);
                return NULL;	  
            }
            memcpy(item->content, ((char *) buffer) + read_size, item->size);
        }
        read_size += item->size;

        /* Add the content to the result message */
        result = g_slist_append(result, item);
    }

    /* The amount of read data should be equal to the buffer size */
    if (size != read_size)
    {
        g_slist_free_full(result, gpdgc_free_content);
        return NULL;
    }
    return result;
}
gpdgc_message *gpdgc_extract_contents(void *buffer, size_t size)
{
    gpdgc_message *result = gpdgc_create_message();
    if (result == NULL)
    {
        return NULL;
    }

    result->contents = gpdgc_do_extract_contents(buffer, size);
    if (result->contents == NULL)
    {
        gpdgc_free_message(result);
        return NULL;
    }
    return result;
}

/* Write the specified message in a buffer */
void *gpdgc_write_contents(gpdgc_message *msg, gcry_sexp_t key, size_t *size)
{
    char *buffer = NULL;
    *size = 0;
    if ((key == NULL) || gpdgc_sign_message(msg, key))
    {
        GSList *iterator = msg->contents;
        while (iterator != NULL)
        {
            gpdgc_content *content = iterator->data;
            iterator = iterator->next;

            /* Memory allocation */
            void *tmp = realloc(buffer, *size + sizeof(size_t) + content->size);
            if (tmp == NULL)
            {
                *size = 0;
                free(buffer);
                return NULL;
            }
            buffer = tmp;

            /* Write the size of content in the buffer */
            memcpy(buffer + *size, &content->size, sizeof(size_t));
            *size += sizeof(size_t);

            /* Write the content itself in the buffer */
            if (content->size > 0)
            {
                memcpy(buffer + *size, content->content, content->size);
                *size += content->size;
            }
        }
        if (key != NULL)
        {
            gpdgc_pop_content(msg, NULL);
        }
    }
    return buffer;
}


/* Compare messages */
int gpdgc_cmp_message(gpdgc_message *first, gpdgc_message *second)
{
    GSList *first_iterator = first->contents;
    GSList *second_iterator = second->contents;
    while (first_iterator != NULL)
    {
        if (second_iterator == NULL)
        {
            return 1;
        }

        gpdgc_content *first_content = first_iterator->data;
        gpdgc_content *second_content = second_iterator->data;
        int cmp_content = gpdgc_cmp_content(first_content, second_content);
        if (cmp_content != 0)
        {
            return cmp_content;
        }

        first_iterator = first_iterator->next;
        second_iterator = second_iterator->next;
    }
    return second_iterator == NULL ? 0 : -1;
}


/* Push a copy of the specified content to the specified message */
int gpdgc_push_content(gpdgc_message *msg, void *content, size_t size)
{
    /* Check that the message is non null */
    if (msg == NULL)
    {
        return 0;
    }

    /* Prepare memory for the content */
    gpdgc_content *gc_content = malloc(sizeof(gpdgc_content));
    if (gc_content == NULL)
    {
        return 0;
    }

    /* Copy the content to the memory */
    gc_content->size = size;
    gc_content->content = size > 0 ? malloc(size) : NULL;
    if (size > 0)
    {
        if (gc_content->content == NULL)
        {
            free(gc_content);
            return 0;
        }
        memcpy(gc_content->content, content, size);
    }

    /* Add the content to the message */
    GSList *contents = g_slist_prepend(msg->contents, gc_content);
    if (contents == NULL)
    {
        free(gc_content);
        return 0;
    }
    msg->contents = contents;
    return 1;
}

/* Get the size of the i-th content of the specified message */
size_t gpdgc_get_content_size(gpdgc_message *msg, int i)
{
    GSList *iterator = msg != NULL ? msg->contents : NULL;
    while ((iterator != NULL) && (i > 0))
    {
        iterator = iterator->next;
        i--;
    }
    
    gpdgc_content *gc_content = iterator != NULL ? iterator->data : NULL;
    return gc_content != NULL ? gc_content->size : 0;
}

/* Generic access to the i-th content of the specified message */
void *gpdgc_do_access_content_from_message(gpdgc_message *msg,
        int i, int remove, size_t *size)
{
    GSList *iterator = msg != NULL ? msg->contents : NULL;
    while ((iterator != NULL) && (i > 0))
    {
        iterator = iterator->next;
        i--;
    }

    void *result = NULL;
    gpdgc_content *gc_content = iterator != NULL ? iterator->data : NULL;
    if (size != NULL)
    {
        result = gc_content != NULL ? gc_content->content : NULL;
        *size = gc_content != NULL ? gc_content->size : 0;
    }

    if (remove && (gc_content != NULL))
    {
        msg->contents = g_slist_remove(msg->contents, gc_content);
        if (size == NULL)
        {
            free(gc_content->content);
        }
        free(gc_content);
    }
    return result;
}

/* Peek the i-th content (as a sock address) of the specified message */
struct sockaddr *gpdgc_peek_address(gpdgc_message *msg, int position)
{
    size_t size;
    struct sockaddr *ip = gpdgc_peek_content(msg, position, &size);

    if (!gpdgc_is_address(ip, size))
    {
        ip = NULL;
    }
    return ip;
}

/* Pop the first content (as a sock address) of the specified message */
struct sockaddr *gpdgc_pop_address(gpdgc_message *msg)
{
    size_t size;
    struct sockaddr *ip = gpdgc_pop_content(msg, &size);

    if (!gpdgc_is_address(ip, size))
    {
        free(ip);
        ip = NULL;
    }
    return ip;
}

/* Peek the i-th content of the specified message */
void *gpdgc_peek_content(gpdgc_message *msg, int i, size_t *size)
{
    return gpdgc_do_access_content_from_message(msg, i, 0, size);
}

/* Pop the first content of the specified message */
void* gpdgc_pop_content(gpdgc_message *msg, size_t *size)
{
    return gpdgc_do_access_content_from_message(msg, 0, 1, size);
}

/* Push a copy of the specified S-Expression to the specified message */
int gpdgc_push_gcry_sexp(gpdgc_message *msg, gcry_sexp_t expr)
{
    if (expr == NULL)
    {
        return gpdgc_push_content(msg, NULL, 0);
    }

    size_t size = 0;
    void *buf = gpdgc_get_gcry_sexp_t_as_buffer(expr, &size);
    if (buf == NULL)
    {
        return 0;
    }

    int result = gpdgc_push_content(msg, buf, size);
    free(buf);
    return result;
}

/* Peek the i-th content (a S-Expression) of the specified message */
gcry_sexp_t gpdgc_peek_gcry_sexp(gpdgc_message *msg, int position)
{
    size_t key_buffer_size;
    void *key_buffer = gpdgc_peek_content(msg, position, &key_buffer_size);
    if (key_buffer == NULL)
    {
        return NULL;
    }

    gcry_sexp_t key;
    int failure = gcry_sexp_new(&key, key_buffer, key_buffer_size, 0);
    return failure ? NULL : key;
}

/* Pop the first content (a S-Expression) of the specified message */
gcry_sexp_t gpdgc_pop_gcry_sexp(gpdgc_message *msg)
{
    size_t key_buffer_size;
    void *key_buffer = gpdgc_pop_content(msg, &key_buffer_size);
    if (key_buffer == NULL)
    {
        return NULL;
    }

    gcry_sexp_t key;
    int failure = gcry_sexp_new(&key, key_buffer, key_buffer_size, 0);
    free(key_buffer);
    return failure ? NULL : key;
}


/* Sign the specified message with the specified private key; the signature 
 *  being pushed to the message */
gcry_sexp_t gpdgc_sign_buffer(void *buffer, size_t size, 
        gcry_sexp_t private_key)
{
    size_t hash_size = gcry_md_get_algo_dlen(GPDGC_HASH_ALGORITHM);
    void *hash = malloc(hash_size);
    if (hash == NULL)
    {
        return NULL; 
    }
    gcry_md_hash_buffer(GPDGC_HASH_ALGORITHM, hash, buffer, size);

    gcry_mpi_t hash_mpi; 
    gcry_error_t error = gcry_mpi_scan(&hash_mpi, GCRYMPI_FMT_USG,
            hash, hash_size, NULL); 
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Sign buffer: cannot scan mpi: %s", gcry_strerror(error));
        }
        free(hash);
        return NULL;
    }

    gcry_sexp_t hash_data;
    error = gcry_sexp_build(&hash_data, NULL,
            "(data (flags raw) (value %m))", hash_mpi);
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Sign buffer: cannot build S-Exp from the scanned mpi: %s",
                    gcry_strerror(error));
        }
        free(hash);
        gcry_mpi_release(hash_mpi);
        return NULL;
    }

    gcry_sexp_t signature;
    error = gcry_pk_sign(&signature, hash_data, private_key);
    gcry_sexp_release(hash_data);
    gcry_mpi_release(hash_mpi);
    free(hash);

    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Sign buffer: cannot sign: %s", gcry_strerror(error));
        }
        gcry_sexp_release(signature);
        return NULL;
    }
    return signature;
}
int gpdgc_sign_message(gpdgc_message *msg, gcry_sexp_t private_key)
{
    /* Write message contents to buffer */
    size_t size;
    void *buffer = gpdgc_write_contents(msg, NULL, &size);
    if (buffer == NULL)
    {
        return 0;
    }

    /* Sign the buffer */
    gcry_sexp_t signature = gpdgc_sign_buffer(buffer, size, private_key);
    free(buffer);
    if (signature == NULL)
    {
        return 0;
    }

    /* Add signature to the contents */
    int result = gpdgc_push_gcry_sexp(msg, signature);
    gcry_sexp_release(signature);
    return result;
}

/* Pop the signature from the specified message, and check that 
 *  the signature is valid regarding the message and specified public key */
int gpdgc_check_signed_buffer(void *buffer, size_t size, 
        gcry_sexp_t public_key, gcry_sexp_t signature)
{
    size_t hash_size = gcry_md_get_algo_dlen(GPDGC_HASH_ALGORITHM);
    void *hash = malloc(hash_size);
    if (hash == NULL)
    {
        return 0;    
    }
    gcry_md_hash_buffer(GPDGC_HASH_ALGORITHM, hash, buffer, size);

    gcry_mpi_t hash_mpi; 
    gcry_error_t error = gcry_mpi_scan(&hash_mpi, GCRYMPI_FMT_USG,
            hash, hash_size, NULL);
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Check signature: cannot scan mpi: %s",
                    gcry_strerror(error));
        }
        free(hash);
        return 0;
    }

    gcry_sexp_t hash_data;
    error = gcry_sexp_build(&hash_data, NULL,
            "(data (flags raw) (value %m))", hash_mpi);
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Check signature: cannot build S-Exp from scanned mpi: %s",
                    gcry_strerror(error));
        }
        gcry_mpi_release(hash_mpi);
        free(hash);
        return 0;
    }

    int result = gcry_pk_verify(signature, hash_data, public_key) == 0;
    gcry_sexp_release(hash_data);
    gcry_mpi_release(hash_mpi);
    free(hash);
    return result;
}
int gpdgc_unsign_message(gpdgc_message *msg, gcry_sexp_t public_key)
{
    /* Extract the signature */
    size_t signature_size;
    char *signature_content = gpdgc_pop_content(msg, &signature_size);

    gcry_sexp_t signature;
    if (gcry_sexp_sscan(&signature, NULL, signature_content, signature_size))
    {
        free(signature_content);
        return 0;
    }

    /* Write message contents to buffer */
    size_t size;
    void *buffer = gpdgc_write_contents(msg, NULL, &size);
    if (buffer == NULL)
    {
        gcry_sexp_release(signature);
        free(signature_content);
        return 0;
    }

    /* Verify the buffer with the signature */
    int result = gpdgc_check_signed_buffer(buffer, size, public_key, signature);
    gcry_sexp_release(signature);
    free(signature_content);
    free(buffer);
    return result; 
}
