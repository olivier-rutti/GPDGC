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
#define _XOPEN_SOURCE

#include <gcrypt.h>
#include <glib.h>
#include <unistd.h>

void gpdgc_encrypt_rsa_key(void *buffer, size_t size, char *pwd, GError **ex)
{
    if ((ex != NULL) && (*ex != NULL))
    {
        g_error("Generate RSA Keys: the parameter 'ex' is not correctly set");
    }

    size_t pwd_length = pwd != NULL ? strlen(pwd) : 0;
    if (pwd_length == 0)
    {
        return;
    }

    gcry_cipher_hd_t hd;
    gcry_error_t error = gcry_cipher_open(&hd, GCRY_CIPHER_AES128, 
            GCRY_CIPHER_MODE_CFB, 0);
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot create AES cipher");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return;
    }

    const size_t keylen = 16;
    void *pwd_hash = malloc(keylen);
    gcry_md_hash_buffer(GCRY_MD_MD5, pwd_hash, pwd, pwd_length);
    error = gcry_cipher_setkey(hd, pwd_hash, keylen);
    if (error)
    {
        free(pwd_hash);
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot set AES key");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return;
    }

    error = gcry_cipher_setiv(hd, pwd_hash, keylen);
    if (error)
    {
        free(pwd_hash);
        gcry_cipher_close(hd);
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot set AES init vector");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return;
    }

    error = gcry_cipher_encrypt(hd, (unsigned char*) buffer, size, NULL, 0);
    if (error)
    {
        free(pwd_hash);
        gcry_cipher_close(hd);
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot crypt public key buffer");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return;
    }
    free(pwd_hash);
    gcry_cipher_close(hd);
}
void gpdgc_store_rsa_key(gcry_sexp_t key, char *file, char *pwd, GError **ex)
{
    if ((ex != NULL) && (*ex != NULL))
    {
        g_error("Generate RSA Keys: the parameter 'ex' is not correctly set");
    }

    size_t buf_size = gcry_sexp_sprint(key, GCRYSEXP_FMT_CANON, NULL, 0);
    void *buf = malloc(buf_size);
    if (buf == NULL)
    {
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return;
    }

    size_t size = gcry_sexp_sprint(key, GCRYSEXP_FMT_CANON, buf, buf_size);
    if ((size == 0) || (buf_size < size))
    {
        g_error("Generate RSA Keys: invalid buffer size for public key; "
                "expected=%ld used=%ld", buf_size, size);
    }

    GError *encrypt_ex = NULL;
    gpdgc_encrypt_rsa_key(buf, size, pwd, &encrypt_ex);
    if (encrypt_ex != NULL)
    {
        free(buf);
        g_propagate_error(ex, encrypt_ex);
        return;
    }

    FILE* store_file = fopen(file, "wb");
    if (!store_file)
    {
        free(buf);
        g_set_error(ex, G_FILE_ERROR, G_FILE_ERROR_ACCES,
                "Cannot open file '%s'", file);
        return;
    }
    if (fwrite(buf, size, 1, store_file) != 1)
    {
        free(buf);
        fclose(store_file);
        g_set_error(ex, G_FILE_ERROR, G_FILE_ERROR_PERM,
                "Cannot write to file '%s'", file);
        return;
    }
    free(buf);
    fclose(store_file);
}
int gpdgc_generate_rsa_keys(char *private_key_file, char *public_key_file,
        char *password, GError **ex)
{
    if ((ex != NULL) && (*ex != NULL))
    {
        g_error("Generate RSA Keys: the parameter 'ex' is not correctly set");
    }

    gcry_sexp_t rsa_params;
    gcry_error_t error = gcry_sexp_build(&rsa_params, NULL,
            "(genkey (rsa (nbits 4:2048)))");
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot generate rsa parameters");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return -1;
    }

    gcry_sexp_t rsa_keypair;
    error = gcry_pk_genkey(&rsa_keypair, rsa_params);
    gcry_sexp_release(rsa_params);
    if (error)
    {
        if (gcry_err_code(error) != GPG_ERR_ENOMEM)
        {
            g_error("Generate RSA Keys: cannot create key pair (SIGNATURE)");
        }
        g_set_error_literal(ex, G_FILE_ERROR, G_FILE_ERROR_NOMEM, "No Memory");
        return -1;
    }

    GError *store_ex = NULL;
    gcry_sexp_t public = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    gpdgc_store_rsa_key(public, public_key_file, password, &store_ex);
    if (store_ex != NULL)
    {
        gcry_sexp_release(rsa_keypair);
        gcry_sexp_release(public);
        g_propagate_error(ex, store_ex);
        return -1;
    }

    gcry_sexp_t private = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    gpdgc_store_rsa_key(private, private_key_file, password, &store_ex);
    if (store_ex != NULL)
    {
        gcry_sexp_release(rsa_keypair);
        gcry_sexp_release(public);
        gcry_sexp_release(private);
        g_propagate_error(ex, store_ex);
        return -1;
    }

    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(public);
    gcry_sexp_release(private);
    return 0;
}


int main(int argc, char** argv)
{
    if ((argc != 3) && (argc != 4))
    {      
        fprintf(stderr, "Usage: %s [-e] <rsa-private> <rsa-public>\n", argv[0]);
        fprintf(stderr, "Invalid arguments.\n");
        exit(1);
    }

    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fprintf(stderr, "gcrypt: invalid library version.\n");
        exit(1);
    }

    /* Init the gcrypt library */
    gcry_error_t err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err)
    {
        fprintf(stderr, "gcrypt: initialization failed.\n");
        exit(1);
    }

    /* Get password if required and generate the key pair */
    char* passwd = (argc == 4) && (strcmp("-e", argv[1]) == 0)
        ? getpass("Please enter a password to encrypt the keys: ") : NULL;
    gpdgc_generate_rsa_keys(argc == 3 ? argv[1] : argv[2],
            argc == 3 ? argv[2] : argv[3], passwd, NULL);
    return 0;
}
