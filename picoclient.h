
#include "lwip/pbuf.h"
// #include "lwip/apps/altcp_tls_mbedtls_opts.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
// #include "lwip/priv/altcp_priv.h"
#include "altcp_tls/altcp_tls_mbedtls_structs.h"
#include "altcp_tls/altcp_tls_mbedtls_mem.h"
#include "lwip/dns.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/uart.h"
#include "pico/cyw43_arch.h"
#include "cert.h"
#include "mbedtls/base64.h"

#define RECV_BUFF_MAX_LEN   1024
#define FLASH_TARGET_OFFSET (1792*1024)
#define KEY_SIZE 320
#define CERT_SIZE 1024
#define RAND_SIZE 64
#define CON_SIZE 32
#define BUFFER_SIZE 100
#define MAX_RESPONSE_SIZE 2048
#define MAX_JSON_PAYLOAD_SIZE 1024
#define MAX_HTTP_REQUEST_SIZE 1600
#define MAX_CERT_SIZE 2048


#define TCP_POLL_INTERVAL   10

// #define WIFI_SSID           "TP-LINK 8841"
// #define WIFI_PASSWORD       "Sanapple@1424"
// #define SERVER_IP           "172.24.18.130"
// #define SERVER_PORT         8000

typedef struct {
    struct altcp_pcb *tpcb;
    ip_addr_t server_addr;
    bool connected;
    bool dns_found;
    uint8_t recv_buff[RECV_BUFF_MAX_LEN+1];
} TLS_CLIENT_T;

char *get_unique_id();

void send_data(const char *def, const char *data);

int wifissl(char *ssid, char *password);

int connect_to_server();

void generate_ecc_keypair(char *org,unsigned char *csr_buf, size_t csr_buf_size);

void handle_error(int ret);

// int pem_to_der(const char *pem_cert, unsigned char **der_cert, size_t *der_cert_len);

int pem_to_der(const char *pem_cert, unsigned char **der_cert, size_t *der_cert_len);