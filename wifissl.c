#include "picoclient.h"

  // Adjust based on your requirements
static size_t total_len = 0; // Global or static variable to track total received length
//static char res_buf[MAX_RESPONSE_SIZE]; // Static buffer to accumulate response


static struct altcp_tls_config *tls_config = NULL;
char board_id_str[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 1];
const uint8_t *flash_target_contents = (const uint8_t *) (XIP_BASE + FLASH_TARGET_OFFSET);

unsigned char pub_key_buf[KEY_SIZE];
unsigned char priv_key_buf[KEY_SIZE];
unsigned char csr_buf[CERT_SIZE];
char pico_cert[MAX_CERT_SIZE];
size_t buffer_index = 0; 
uint8_t buffer[BUFFER_SIZE];

int status = 0;
char ssid[RAND_SIZE];

TLS_CLIENT_T* tls_client = NULL;
char server_ip[CON_SIZE];
char port[6];

int flag = 0;
int flag1 = 0;
int count = 0;
char res_buf[MAX_RESPONSE_SIZE];

void debugg(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;  // Unused parameter
    printf("%s:%04d: %s", file, line, str); // Print debug messages to console
}

err_t tcp_connect_close(TLS_CLIENT_T *tls_client) {
    if (tls_client && tls_client->tpcb) {
        tls_client->connected = false;
        tls_client->dns_found = false;
        return altcp_close(tls_client->tpcb);
    }
    return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err) {
    TLS_CLIENT_T *tls_client = (TLS_CLIENT_T*)arg;

    if (!p) {
        // printf("ERR:pbuf null\n");
        // printf("STATUS:Closing....\n");
        // return tcp_connect_close(tls_client);
        return ERR_OK;
        // return altcp_close(tls_client->tpcb);
    }
    if (p->tot_len > 0) {
        altcp_recved(tpcb, p->tot_len);
        
        // Ensure we don't overflow res_buf
        size_t available_space = MAX_RESPONSE_SIZE - strlen(res_buf) - 1;
        size_t copy_len = p->tot_len < available_space ? p->tot_len : available_space;
        
        strncat(res_buf, (char *)p->payload, copy_len);
        res_buf[strlen(res_buf)] = '\0';  // Ensure null-termination

        // strncat(res_buf, (char *)p->payload, p->tot_len);
        // res_buf[strlen(res_buf)] = '\0';
        // printf("Response: \n%s\n", res_buf);
        
        // count++;
        // if (count != 2) {
        //     pbuf_free(p);
        //     return ERR_OK;
        // }

        // count = 0;

        // printf("Response: \n%s\n", res_buf);

        // if (strstr(res_buf, "\"message\": \"Not Authenticated\"")) {
        //     printf("STATUS:Closing connection\n");
        //     altcp_close(tls_client->tpcb);
        //     memset(res_buf, 0, sizeof(res_buf));
        //     pbuf_free(p);
        //     return ERR_OK;
        // }

        // if (strstr(res_buf, "Custom-Message: Certificate generated and transferred successfully")) {
        const char *cert_start = strstr(res_buf, "-----BEGIN CERTIFICATE-----");
        // const char *cert_end = strstr(res_buf, "-----END CERTIFICATE-----");

        // printf("cert start \n%s\n",cert_start);
        // printf("cert start \n%s\n",cert_start);
        // printf("cert end \n%s\n",cert_end);
            
            if (cert_start != NULL) {
                // cert_start += 4;

                // char *content_length_header = strstr(res_buf, "Content-Length: ");
                // if (content_length_header) {
                // int content_length = atoi(content_length_header + 16);
                // if (total_len >= content_length + (body_start - res_buf)) {
                //     printf("Response Body: \n%s\n", body_start);  // Print the response body
                //     // Reset for next response
                //     total_len = 0; 
                // } 

                size_t cert_length = strnlen(cert_start, MAX_RESPONSE_SIZE - (cert_start - res_buf));
                // size_t cert_length = cert_end + strlen("-----END CERTIFICATE-----") - cert_start;

                // printf("cert_start (after strstr): %p\nsize is %d\n", (void*)cert_start, (int)cert_length);

                if (cert_length > 0 && cert_length <= MAX_CERT_SIZE) {
                    printf("%.*s", (int)cert_length, cert_start);
                    // printf("%s",cert_start);

                    // unsigned char *der_cert = NULL;  
                    // size_t der_cert_len = 0;         

                    // int ret = pem_to_der(cert_start, &der_cert, &der_cert_len);  
                    // if (ret != 0) {
                    //     printf("Failed to convert PEM to DER, error code: %d\n", ret);
                    // } else {
                        // printf("DER-encoded certificate length: %zu bytes\n", der_cert_len);
                        // printf("DER-encoded certificate (in hex):\n");
                        // for (size_t i = 0; i < der_cert_len; i++) {
                        //     printf("%02X", der_cert[i]);  // Print each byte in hex format
                        //     if (i % 16 == 15) {
                        //         printf("\n");  // Break line every 16 bytes for better readability
                        //     }
                        // }
                        // printf("\n");
                        // size_t write_size = (der_cert_len + 3) & ~3;  // Round up to nearest 4 bytes
                        // if (write_size <= FLASH_SECTOR_SIZE - (2*KEY_SIZE)) {
                        //     uint32_t ints = save_and_disable_interrupts();
                        //     flash_range_program(FLASH_TARGET_OFFSET + RAND_SIZE + KEY_SIZE, der_cert, write_size);
                        //     restore_interrupts(ints);
                        //     // printf("STATUS:Certificate saved to flash.\n");
                        // } else {
                        //     printf("ERR:Error in flashing \n");
                        // }

                    //     free(der_cert);
                    // }
                    // Ensure we're not writing beyond the flash sector size
                    size_t write_size = (cert_length + 3) & ~3;  // Round up to nearest 4 bytes
                    if (write_size <= FLASH_SECTOR_SIZE - (2*KEY_SIZE)) {
                        uint32_t ints = save_and_disable_interrupts();
                        flash_range_program(FLASH_TARGET_OFFSET, (const uint8_t*)cert_start, write_size);
                        restore_interrupts(ints);
                        // printf("STATUS:Certificate saved to flash.\n");
                    } //else {
                    //     printf("ERR:Error in flashing \n");
                    // }
                } //else {
                //     printf("ERR:Not enough space \n");
                // }
            // } else {
            //     printf("STATUS:Certificate not found\n");
            }
            memset(res_buf, 0, sizeof(res_buf));
        // }
    }
    //memset(csr_buf, 0, sizeof(csr_buf));  
    pbuf_free(p);
    return ERR_OK;
}

/*************************************************************************************************************************************/
// static char response_buffer[MAX_RESPONSE_SIZE];
// static int response_len = 0;
// static bool headers_received = false;

// void tcp_recv_cb(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err) {
//     if (p == NULL) {
//         // Connection closed
//         return;
//     }

//     // Accumulate response data
//     memcpy(response_buffer + response_len, p->payload, p->len);
//     response_len += p->len;

//     // Check if headers are fully received
//     if (!headers_received) {
//         char *header_end = strstr(response_buffer, "\r\n\r\n");
//         if (header_end != NULL) {
//             headers_received = true;
//             // Process headers
//             int header_length = header_end - response_buffer + 4; // +4 for "\r\n\r\n"
//             // You can separate headers from the body if needed
//             // For example, process headers here

//             // If there's body data, process it
//             if (header_length < response_len) {
//                 // Handle body data
//                 int body_length = response_len - header_length;
//                 // Process the body here
//             }
//         }
//     } else {
//         // We already received headers, so just process the body
//         // Process the body here
//     }

//     // Free the pbuf after processing
//     pbuf_free(p);
// }

/**********************************************************************************************************************************************/
// signed char tcp_recv_cb(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, signed char err) {
//     if (err != ERR_OK || p == NULL) {
//         // Handle connection close or error
//         return ERR_ABRT; // Abort if there's an error
//     }

//     // Append the received data to the buffer
//     if (total_len + p->len < MAX_RESPONSE_SIZE) {
//         memcpy(res_buf + total_len, p->payload, p->len);
//         total_len += p->len;
//         res_buf[total_len] = '\0'; // Null-terminate the buffer for string operations
//         printf("response:%s\n",res_buf);
//     } else {
//         printf("Buffer overflow, received data too large.\n");
//         pbuf_free(p);
//         return ERR_ABRT; // Abort if buffer is too small
//     }

//     // Check for the end of the headers
//     const char *cert_start = strstr(res_buf, "\r\n\r\n");
//     if (cert_start != NULL) {
//         cert_start += 4;  // Move past the headers

//         // Check for Content-Length header
//         char *content_length_header = strstr(res_buf, "Content-Length: ");
//         if (content_length_header) {
//             int content_length = atoi(content_length_header + 16);
//             if (total_len >= content_length + (cert_start - res_buf)) {
//                 printf("Response Body: \n%s\n", cert_start);  // Print the response body
//                 // Reset for next response
//                 total_len = 0; 
//             } else {
//                 printf("Received data is incomplete. Expected length: %d, received: %lu\n", content_length, total_len);
//             }
//         }
//     }

//     // Free the received pbuf
//     pbuf_free(p);
//     return ERR_OK; // Return success
// }
/*********************************************************************************************************************************************/


err_t tcp_sent_cb(void *arg, struct altcp_pcb *tpcb, u16_t len) {
    return ERR_OK;
}

err_t tcp_poll_cb(void *arg, struct altcp_pcb *tpcb) {
    return tcp_connect_close((TLS_CLIENT_T*)arg);
}

void tcp_err_cb(void *arg, err_t err) {
    printf("ERR:tcp error: %d\n", err);
    tcp_connect_close(arg);
}

err_t tcp_connected_cb(void *arg, struct altcp_pcb *tpcb, err_t err) {
    TLS_CLIENT_T *tls_client = (TLS_CLIENT_T *)arg;
    if (err == ERR_OK) {
        // printf("STATUS:TLS Server Connected\n");
        tls_client->connected = true;
    }
    return err;
}

void tls_client_dns_found(const char *name, const ip_addr_t *ipaddr, void *callback_arg) {
    TLS_CLIENT_T *tls_client = (TLS_CLIENT_T*)callback_arg;
    if (ipaddr) {
        // printf("DNS resolving complete\n");
        tls_client->dns_found = true;
        memcpy(&tls_client->server_addr, ipaddr, sizeof(ip_addr_t));
        // tls_client->server_addr = *ipaddr;
        // printf("Resolved IP immediately: %s\n", ipaddr_ntoa(&tls_client->server_addr));
    } else {
        printf("error resolving hostname %s\n", name);
        tls_client->dns_found = false;
    }
}

void cleanup_connection() {
    if (tls_client) {
        if (tls_client->tpcb) {
            tcp_connect_close(tls_client);
        }
        free(tls_client);
        tls_client = NULL;
    }
    
    // Clear response buffer
    memset(res_buf, 0, sizeof(res_buf));
}


char *get_unique_id() {
    pico_unique_board_id_t board_id;
    pico_get_unique_board_id(&board_id);

    for (int i = 0; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++) {
        sprintf(&board_id_str[i * 2], "%02x", board_id.id[i]);
    }
    board_id_str[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2] = '\0';

    return board_id_str;
}

void send_data(const char *def, const char *data) {
    // char json_payload[MAX_JSON_PAYLOAD_SIZE];
    // memset(json_payload, 0, sizeof(json_payload));
    // snprintf(json_payload, sizeof(json_payload), "{\"%s\":\"%s\"}", def, data);

    char http_request[MAX_HTTP_REQUEST_SIZE];
    memset(http_request, 0, sizeof(http_request));
    snprintf(http_request, sizeof(http_request),
             "POST /%s/ HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %zu\r\n"
             "\r\n"
             "%s", def, server_ip, strlen(data), data);

    err_t err = altcp_write(tls_client->tpcb, http_request, strlen(http_request), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        printf("ERR:TCP write failed\t %d\n", err);
        handle_error(err);
        altcp_close(tls_client->tpcb);
        return;
    }
    // printf("STATUS:HTTP POST request sent\n");
    // altcp_recv(tls_client->tpcb, tcp_recv_cb);
} 


int wifissl(char *ssid,char *password) {
    // int wifi_stat;
    // err_t tcp_stat;
    // printf("STATUS: Starting \n");
    // if (cyw43_arch_init()) {
    //     printf("STATUS:cyw43 init error\n");
    //     return 0;
    // }

    // // Connect to WiFi
    // cyw43_arch_enable_sta_mode();
    // wifi_stat = cyw43_arch_wifi_connect_timeout_ms((const char *)ssid, (const char *)password, CYW43_AUTH_WPA2_AES_PSK, 30000);
    // if (wifi_stat) {
    //     printf("STATUS:wifi connect error:%d\n", wifi_stat);
    //     return 0;
    // }
    // printf("STATUS:Wifi connected\n");

//************************************************************************************************/
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_INDIA)){  
	    return 1;  
    }
    cyw43_arch_enable_sta_mode();  
    if (cyw43_arch_wifi_connect_async(ssid, password, CYW43_AUTH_WPA2_MIXED_PSK)) {  
        return 2;  
    }  
    // int flashrate = 1000;  
    int new_status;
    status = CYW43_LINK_UP + 1;
    printf("STATUS:Waiting for connection...\n");
    while (status >= 0 && status != CYW43_LINK_UP){
        new_status = cyw43_tcpip_link_status(&cyw43_state,  CYW43_ITF_STA);
        // printf("%d\t%d\n",status,new_status);
        // if (new_status != status){
            status = new_status;
            // flashrate = flashrate/ (status + 1);
            //printf("STATUS:connect status: %d %d\n", status, flashrate);
        // }
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
        sleep_ms(500);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
        sleep_ms(500);
    }

    return status;
/************************************************************************************************************************/
}

int connect_to_server()
{
    cleanup_connection();

    tls_client = (TLS_CLIENT_T*)calloc(1, sizeof(TLS_CLIENT_T));
    if (!tls_client) {
        printf("ERR: Failed to allocate TLS client\n");
        return 0;
    }

    err_t dns_stat, tcp_stat;
    tls_config = altcp_tls_create_config_client(ca_cert, sizeof(ca_cert));
    assert(tls_config);

    tls_client->tpcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
    altcp_arg(tls_client->tpcb, tls_client);
    altcp_sent(tls_client->tpcb, tcp_sent_cb);
    altcp_recv(tls_client->tpcb, tcp_recv_cb);
    altcp_poll(tls_client->tpcb, tcp_poll_cb, TCP_POLL_INTERVAL);
    altcp_err(tls_client->tpcb, tcp_err_cb);

    tls_client->connected = false;
    tls_client->dns_found = false;

    dns_stat = dns_gethostbyname(server_ip, &tls_client->server_addr, tls_client_dns_found, tls_client);
    if (dns_stat == ERR_OK) {
        // DNS result was immediately available
        tls_client->dns_found = true;
        // printf("DNS resolved immediately: %s\n", ipaddr_ntoa(&tls_client->server_addr));
    } 
    // ipaddr_aton(server_ip, &tls_client->server_addr);

    absolute_time_t dns_timeout = make_timeout_time_ms(20000);
    while (!tls_client->dns_found && absolute_time_diff_us(get_absolute_time(), dns_timeout) > 0) {
        // printf(".");
        // cyw43_arch_poll();
        sleep_ms(10);
    }

    if (!tls_client->dns_found) {
        printf("ERR: DNS resolution timeout\n");
        return 0;
    }
    
    // tls_client->connected = false;
    tcp_stat = altcp_connect(tls_client->tpcb, &tls_client->server_addr, (u16_t)atoi(port) , tcp_connected_cb);
    
    if (tcp_stat != ERR_OK) {
        printf("ERR:connect TCP server error: %d\n", tcp_stat);
        return 0;
    }

    absolute_time_t conn_timeout = make_timeout_time_ms(20000); // 20 second timeout
    while (!tls_client->connected && absolute_time_diff_us(get_absolute_time(), conn_timeout) > 0) {
        // cyw43_arch_poll();
        sleep_ms(10);
    }
    // printf("\n");

    if (!tls_client->connected) {
        printf("ERR:Connection timeout\n");
        free(tls_client);
        return 0;
    }

    return 1;  // Return 1 for success

    // altcp_recv(tls_client->tpcb, tcp_recv_cb);
}

void check_wifi(int status){
    if (status > 0) {
        printf("STATUS:WiFi Connected\n");
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
    } else if (status <= 0) {
        printf("STATUS:Failed to connect WiFi\n");
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    } else {
        printf("STATUS:Waiting for connection...\n");
    }
}


// void receive_data_from_usb() {
//     while (buffer_index < BUFFER_SIZE) {
//         int bytes_to_read = CHUNK_SIZE;
//         if (buffer_index + CHUNK_SIZE > BUFFER_SIZE) {
//             // Avoid reading beyond buffer size
//             bytes_to_read = BUFFER_SIZE - buffer_index;
//         }

//         int bytes_read = tud_cdc_read(&buffer[buffer_index], bytes_to_read);
//         if (bytes_read > 0) {
//             buffer_index += bytes_read;
//             printf("Received %d bytes, total received: %d\n", bytes_read, buffer_index);
//         }
//     }

//     printf("Data fully received\n");
// }


void func_command(const char* cmd) {
    //checking network status
    if (strncmp(cmd, "GNS", 3)==0){
        status = cyw43_tcpip_link_status(&cyw43_state,  CYW43_ITF_STA);
        check_wifi(status);
    }

    //wifi credentials
    if (strncmp(cmd, "CONNECT:", 8) == 0) {
        char password[RAND_SIZE];
        memset(ssid,0,sizeof(ssid));
        memset(password,0,sizeof(password));
        sscanf(cmd + 8, "%[^,],%[^,],%[^,],%s", ssid, password, server_ip, port);
        // *port = (u16_t)atoi(port_str);
        status=wifissl(ssid,password);
        check_wifi(status);
    }

    if (strncmp(cmd, "GKC:", 4)==0){
        char org[BUFFER_SIZE];
        sscanf(cmd + 4, "%s", org);
        generate_ecc_keypair(org,csr_buf,CERT_SIZE);
    }

    if (strncmp(cmd, "GI", 2)==0){
        uint8_t mac[6];
        cyw43_hal_get_mac(CYW43_HAL_MAC_WLAN0, &mac[0]);
        printf("Chip Model:Raspberry Pi Pico W,MAC Address:%02X:%02X:%02X:%02X:%02X:%02X,IP Address:%s,UID:%s\n",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],ip4addr_ntoa( &(netif_default->ip_addr)),get_unique_id());
    }

    if (strncmp(cmd, "PKC", 3)==0){
        // char hint[64];
        // memcpy(hint, flash_target_contents, RAND_SIZE);
        // memcpy(priv_key_buf, flash_target_contents + RAND_SIZE, KEY_SIZE);
        memcpy(pico_cert, flash_target_contents, MAX_CERT_SIZE);

        // for (size_t i = 0; i < strlen(pico_cert); i++) {
        //     printf("%02X", pico_cert[i]);
        //     if ((i + 1) % 16 == 0) {
        //         printf("\n");
        //     } else {
        //         printf(" ");
        //     }
        // }
        // printf("\n");
        // printf("\nhint is \n%s\n",hint);
        // printf("\nprivate key is \n%s\n",priv_key_buf);
        // // printf("Cert Size %d\t%d\n",sizeof(pico_cert),strlen(pico_cert));
        printf("\nCertificate is \n%s\n",pico_cert);

        // pem_to_der((const char *)pico_cert);
    }

    if (strncmp(cmd, "GDC", 3)==0){
        char csr[]="generate_certificate";
        int ret=connect_to_server();
        if(csr_buf != NULL && ret != 0){
            // char csr_body[600];
            // char encoded_csr[600];
            // const char *start = strstr(csr_buf, "-----BEGIN CERTIFICATE REQUEST-----");
            // const char *end = strstr(csr_buf, "-----END CERTIFICATE REQUEST-----");

            // if (start && end) {
            //     start += strlen("-----BEGIN CERTIFICATE REQUEST-----");
            //     size_t len = end - start;
            //     memcpy(csr_body, start, len);
            //     csr_body[len] = '\0';

            //     char *p = csr_body;
            //     while ((p = strchr(p, '\n')) != NULL) {
            //         *p = ' ';
            //     }

            //     size_t encoded_len = 0;
            //     int ret= mbedtls_base64_encode( encoded_csr, sizeof(encoded_csr), &encoded_len, (unsigned char *)csr_body, strlen(csr_body));
            //     if ( ret != 0) {
            //         printf("ERR:Base64 encoding failed\n");
            //         handle_error(ret);
            //     }
            // }
            send_data(csr, csr_buf);

            // Wait for response
            absolute_time_t response_timeout = make_timeout_time_ms(10000);
            while (absolute_time_diff_us(get_absolute_time(), response_timeout) > 0) {
                sleep_ms(10);
            }
            
            // Cleanup after sending/receiving data
            cleanup_connection();

            // memset(csr_buf,0,sizeof(csr_buf));
            // for (int i=0; i<100; i++){
            //     cyw43_arch_poll();
            //     cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
            // }
        }
        else{
            printf("ERR:CSR not Generated\n");
        }
    }
}

int main() {
    stdio_init_all();  
    char cmd[BUFFER_SIZE]={0};
    int cmd_index=0;
    char c;

    
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);

    // while(1){
    //    if (stdio_usb_connected() && getchar_timeout_us(0) != PICO_ERROR_TIMEOUT) {
    //         char c = getchar(); 
    //             if (c == '\n' || c == '\r') {
    //                 if (cmd_index > 0) {
    //                     cmd[cmd_index] = '\0';  // Null-terminate the string
    //                     func_cmd(tls_client,cmd);   // Process the received cmd
    //                     cmd_index = 0;          // Reset for the next cmd
    //                 }
    //             } else if (cmd_index < 30) {
    //                 cmd[cmd_index++] = c;  // Store the received character
    //             }
    //         }
    //     }
    while (stdio_usb_connected() && getchar_timeout_us(0) != PICO_ERROR_TIMEOUT) {
        // Empty loop to clear the buffer
    }

    while(1) {
        if (stdio_usb_connected()) {
            c = getchar();
            if (c != PICO_ERROR_TIMEOUT) {
                if (c == '\n' || c == '\r') {
                    if (cmd_index > 0) {
                        cmd[cmd_index] = '\0';
                        func_command(cmd);
                        cmd_index = 0;
                    }
                } else if (cmd_index < BUFFER_SIZE - 1) {
                    cmd[cmd_index++] = c;
                }
            }
        }
    }
        // if (getvalue == 'a') {
        //     if(flag1==0){
        //         printf("Authenticating device\n");
        //         char dev_id[]="data-id";
        //         send_data(tls_client,dev_id,get_unique_id());
        //     }
        //     else{
        //         printf("Authenticated device\n");
        //     }
        // }

        // if(getvalue == 'k'){

            // uint32_t ints = save_and_disable_interrupts();
            // flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
            // restore_interrupts(ints);

        //     // memcpy(pub_key_buf, flash_target_contents, KEY_SIZE);
        //     // printf("\n\npublic key is \n%s\n",pub_key_buf);
        //     memcpy(priv_key_buf, flash_target_contents, KEY_SIZE);
        //     // printf("\n\nprivate key is \n%s\n",priv_key_buf);

        //     if(priv_key_buf[0]==0xFF){
        //         printf("\n\nGenerating key pairs\n");
        //         generate_ecc_keypair(tls_client, pub_key_buf, priv_key_buf);
        //     }
        //     else{
        //         printf("\n\nprivate key is \n%s\n",priv_key_buf);
        //     }
        // }

        // if (getvalue == 'p') {
        //     // memcpy(pub_key_buf, flash_target_contents, KEY_SIZE);
            // memcpy(priv_key_buf, flash_target_contents + KEY_SIZE, KEY_SIZE);
            // memcpy(pico_cert, flash_target_contents + (2*KEY_SIZE), CERT_SIZE);

        //     // printf("\n\npublic key is \n%s\n",pub_key_buf);
            // printf("\n\nprivate key is \n%s\n",priv_key_buf);
            // printf("\n\nCertificate is \n%s\n",pico_cert);

        //     // memset(pub_key_buf,0,KEY_SIZE);
        //     memset(priv_key_buf,0,KEY_SIZE);
        //     memset(pico_cert,0,CERT_SIZE);
        // }

        // for (int i=0; i<100; i++){
        //     cyw43_arch_poll();
        //     cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
        // }

// mutual:
//     altcp_close(tls_client->tpcb);
//     free(tls_client);
//     cyw43_arch_deinit();

//     flag=1;
//     if (wifissl(tls_client,flag)) {
//         char dev_id[] = "data-id";
//         send_data(tls_client, dev_id, get_unique_id());
//     }

//     uint8_t buff[100];
//     uint32_t idx=0;
//     while(1) {
//         sprintf(buff, "test from PicoW:%020d", idx++);
//         altcp_write(tls_client->tpcb, buff, strlen(buff), TCP_WRITE_FLAG_COPY);
//         cyw43_arch_poll();
//         cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
//         //sleep_ms(50);
//     }

    return 0;
}
