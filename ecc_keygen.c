#include "picoclient.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/x509.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pem.h"

size_t len;

void handle_error(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    printf("ERR: %s\n", error_buf);
}

void generate_ecc_keypair(char *org, unsigned char *csr_buf, size_t csr_buf_size) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    mbedtls_x509write_csr req;
    mbedtls_aes_context aes;
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_mpi d;

    const char *pers = "csr_generation";

    unsigned char enc_key[32];
    unsigned char hint[RAND_SIZE];
    unsigned char enc_priv_key_buf[512];
    int loop = 10000;
    size_t len;  

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);
    mbedtls_x509write_csr_init(&req);
    mbedtls_mpi_init(&d);
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_md_init(&md_ctx);
    mbedtls_aes_init(&aes);
    mbedtls_md_setup(&md_ctx, md_info, 1);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    }

    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    }

    // printf("STATUS:Generating KEYS and CSR\n");
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    }
    const mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk);
    ret = mbedtls_mpi_copy(&d, &ec_key->d);  // d = private key
    if (ret != 0) {
        printf("Failed to copy private key\n");
        handle_error(ret);
        goto exit;
    }

    char buffer[KEY_SIZE];
    // printf("Private key (d) in hexadecimal:\n");
    ret = mbedtls_mpi_write_string(&d, 16, buffer, sizeof(buffer), &len);
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    } else {
        buffer[len]='\0';
        // printf("%s\n", buffer);
    }

    // printf("STATUS:Keys Generated Successfully\n");

    // mbedtls_x509write_csr_set_key_usage(&req, 0);
    // mbedtls_x509write_csr_set_ns_cert_type(&req, 0);

    char subject_name[100];
    snprintf(subject_name, sizeof(subject_name), "CN=%s,O=%s,C=IN", get_unique_id(), org);
    ret = mbedtls_x509write_csr_set_subject_name(&req, subject_name);
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    }

    mbedtls_x509write_csr_set_key(&req, &pk);

    unsigned char temp_csr_buf[512];
    memset(temp_csr_buf, 0, sizeof(temp_csr_buf));

    ret = mbedtls_x509write_csr_pem(&req, temp_csr_buf, sizeof(temp_csr_buf), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        handle_error(ret);
        goto exit;
    }

    memset(csr_buf,0,sizeof(csr_buf));
    if (strlen((char *)temp_csr_buf) + 1 > csr_buf_size) {
        printf("ERR: Provided CSR buffer is too small\n");
        goto exit;
    }
    strcpy((char *)csr_buf, (char *)temp_csr_buf);

    // printf("STATUS:CSR Generated Successfully\n");
    printf("UID:%s,CSR:%s\n",get_unique_id(), csr_buf);
/********************************************************************************************************************/
    // const char *enc_pass = get_unique_id();

    // ret = mbedtls_ctr_drbg_random(&ctr_drbg, hint, sizeof(hint));
    // if (ret != 0) {
    //     printf("Failed to generate random data - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("Hint is : %d\n",hint);

    // flash_range_program(FLASH_TARGET_OFFSET, hint, RAND_SIZE);


    // //&mbedtls_sha256_info
    // ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (unsigned char *)enc_pass, strlen(enc_pass), hint, sizeof(hint), loop, sizeof(enc_key), enc_key);
    // if (ret != 0) {
    //     printf("Failed to generate key - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("im here");

    // ret = mbedtls_aes_setkey_enc(&aes, enc_key, 256);
    // if (ret != 0) {
    //     printf("Failed to setting key - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("im here");

    // ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, strlen(priv_key_buf), hint, priv_key_buf, enc_priv_key_buf);
    // if (ret != 0) {
    //     printf("Failed to encrypt - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("im here");

    // flash_range_program(FLASH_TARGET_OFFSET + RAND_SIZE, enc_priv_key_buf, (2*KEY_SIZE));
/**************************************************************************************************************************************/

    // const char *enc_pass = get_unique_id();

    // ret = mbedtls_ctr_drbg_random(&ctr_drbg, hint, sizeof(hint));
    // if (ret != 0) {
    //     printf("Failed to generate random data - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("Hint generated successfully\n%s\n%d\n",hint,strlen(hint));

    // // Generate encryption key using PBKDF2-HMAC-SHA256
    // ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (unsigned char *)enc_pass, strlen(enc_pass), 
    //                                 hint, sizeof(hint), loop, sizeof(enc_key), enc_key);
    // if (ret != 0) {
    //     printf("Failed to generate key - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("Encryption key generated successfully\n");

    // // Set the encryption key
    // ret = mbedtls_aes_setkey_enc(&aes, enc_key, 256);
    // if (ret != 0) {
    //     printf("Failed to set encryption key - Error: %d\n", ret);
    //     goto exit;
    // }

    // // Encrypt the private key
    // ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, strlen(buffer), 
    //                             hint, (unsigned char*)buffer, enc_priv_key_buf);
    // if (ret != 0) {
    //     printf("Failed to encrypt - Error: %d\n", ret);
    //     goto exit;
    // }
    // printf("Encryption successful \n %s\n",enc_priv_key_buf);
    // printf("Size of encrp %d\n",strlen(enc_priv_key_buf));

    // uint32_t ints = save_and_disable_interrupts();
    // flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
    // flash_range_program(FLASH_TARGET_OFFSET, hint, sizeof(hint));
    // flash_range_program(FLASH_TARGET_OFFSET + RAND_SIZE, enc_priv_key_buf, strlen(enc_priv_key_buf));
    // restore_interrupts(ints);
    // printf("Data written to flash successfully\n");
/********************************************************************************************************************************************/
exit:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509write_csr_free(&req);
}

// int pem_to_der(const char *pem_cert, unsigned char **der_cert, size_t *der_cert_len) {
//     int ret;
//     mbedtls_x509_crt cert;
//     mbedtls_x509_crt_init(&cert);

//     // Parse the PEM certificate into an mbedtls_x509_crt structure
//     ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)pem_cert, strlen(pem_cert) + 1);
//     if (ret != 0) {
//         char error_buf[100];
//         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
//         printf("Failed to parse certificate: %s\n", error_buf);
//         return ret;
//     }

//     // Extract the DER-encoded certificate from the parsed structure
//     *der_cert = cert.raw.p;  // DER data pointer
//     *der_cert_len = cert.raw.len; // DER data length

//     // Note: You should ensure that the lifetime of cert is handled properly.
//     // cert.raw.p (der_cert) will be valid until you call mbedtls_x509_crt_free on 'cert'.
//     // Therefore, you can either use it immediately or copy it to another buffer.

//     // Free the mbedtls_x509_crt structure resources
//     // mbedtls_x509_crt_free should be called after using the DER data
//     mbedtls_x509_crt_free(&cert);

//     return 0; // Success
// }

// int pem_to_der(const char *pem_cert, unsigned char **der_cert, size_t *der_cert_len) {
//     int ret;
//     mbedtls_x509_crt cert;
//     mbedtls_x509_crt_init(&cert);

//     // Parse the PEM certificate into an mbedtls_x509_crt structure
//     ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)pem_cert, strlen(pem_cert) + 1);
//     if (ret != 0) {
//         char error_buf[100];
//         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
//         printf("Failed to parse certificate: %s\n", error_buf);
//         mbedtls_x509_crt_free(&cert);
//         return ret;
//     }

//     // Allocate memory for the DER-encoded certificate
//     *der_cert_len = cert.raw.len;
//     *der_cert = (unsigned char *)malloc(*der_cert_len);
//     if (*der_cert == NULL) {
//         printf("Memory allocation failed\n");
//         mbedtls_x509_crt_free(&cert);
//         return -1;  // Memory allocation failure
//     }

//     // Copy the DER-encoded certificate
//     memcpy(*der_cert, cert.raw.p, *der_cert_len);

//     // Clean up
//     mbedtls_x509_crt_free(&cert);

//     return 0;  // Success
// }


// int pem_to_der(const char *pem_cert) {
//     int ret;
//     mbedtls_x509_crt cert;
//     mbedtls_x509_crt_init(&cert);

//     // Parse the PEM certificate into an mbedtls_x509_crt structure
//     ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)pem_cert, strlen(pem_cert) + 1);
//     if (ret != 0) {
//         char error_buf[100];
//         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
//         printf("Failed to parse certificate: %s\n", error_buf);
//         mbedtls_x509_crt_free(&cert);
//         return ret;
//     }

//     // Extract the DER-encoded certificate from the parsed structure
//     unsigned char *der_cert = cert.raw.p;
//     size_t der_cert_len = cert.raw.len;

//     printf("DER-encoded certificate length: %zu bytes\n", der_cert_len);

//     if (der_cert_len > MAX_CERT_SIZE) {
//         printf("Error: Certificate too large for available flash space.\n");
//         mbedtls_x509_crt_free(&cert);
//         return -1;
//     }

//     // Prepare buffer for flash
//     uint8_t buffer[MAX_CERT_SIZE];
//     memset(buffer, 0xFF, sizeof(buffer));
//     // memcpy(buffer, &der_cert_len, sizeof(size_t));  // Store length at the beginning
//     memcpy(buffer + sizeof(size_t), der_cert, der_cert_len);

//     // Disable interrupts, erase flash, and program with the DER certificate
//     uint32_t ints = save_and_disable_interrupts();
//     flash_range_program(FLASH_TARGET_OFFSET + KEY_SIZE, buffer, MAX_CERT_SIZE);
//     restore_interrupts(ints);
//     mbedtls_x509_crt_free(&cert);
    
//     printf("Certificate successfully written to flash.\n");
//     return 0; // Success
// }
