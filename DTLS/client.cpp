#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "../ChaCha20-Poly1305.h"
#include "common.h"
#include "tls_utils.h"
#include "helpers.h"

#include <vector>
#include <string>

using std::vector;
using std::string;

int main(int argc, char** argv) {
    const char* host = APP_HOST_DEFAULT;
    const char* port = APP_PORT_DEFAULT;
    const char* filename = (argc > 1) ? argv[1] : NULL;
    const char* ca = "../certs/server.crt.pem";

    if(filename == NULL) {
        fprintf(stderr, "Missing file to transfer, run as\n\t %s <filename>\n", argv[0]);
        return 1;
    }

    int tls_fd;
    mbedtls_ssl_context ssl;
    fprintf(stderr, "Connecting to %s:%s via TLS...\n", host, port);
    if(tls_client_connect(host, port, ca, &tls_fd, &ssl) != 0) {
        fprintf(stderr, "TLS client connect failed\n");
        return 1;
    }
    fprintf(stderr, "Connected to server via TLS\n");

    vector<uint8_t> key;
    vector<uint8_t> ad;
    vector<uint8_t> nonce;
    vector<uint8_t> client_message;
    struct sockaddr_in server_addr;
    vector<uint8_t> resp(MAX_LINE);
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);
    int n = 0;
    int sent = 0;
    int udp_fd = -1;
    int udp_port = 0;
    bool is_file_mode = (filename != NULL);

    key = derive_key(&ssl, "udp_encryption");
    if(key.empty()) {
        fprintf(stderr, "Key derivation failed\n");
        goto cleanup;
    }

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_fd < 0) {
        perror("UDP socket creation failed");
        goto cleanup;
    }

    udp_port = atoi(port) + 1;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(udp_port);

    if(inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", host);
        goto cleanup;
    }
    
    //send file to server
    if(is_file_mode) {
        fprintf(stderr, "Sending file via UDP...\n");
        if(send_file(udp_fd, (struct sockaddr*)&server_addr,
                        sizeof(server_addr), key, ad, filename) != 0) {
            fprintf(stderr, "File transfer failed\n");
            goto cleanup;
        }
        
        fprintf(stderr, "File transfer complete!\n");
    }

    //server echo
    else {
        nonce = generate_nonce();
        client_message = build_message("Hello world!");
        printf("Sent message: ");
        print_message(client_message, client_message.size());

        sent = udp_send_line(udp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr), 
                             key, nonce, client_message, ad);
        
        if(sent < 28) {
            fprintf(stderr, "UDP send failed\n");
            goto cleanup;
        }

        n = udp_recv_line(udp_fd, (struct sockaddr*)&src_addr, &src_len,
                          key, ad, resp, MAX_LINE);
        
        if(n <= 0) { 
            fprintf(stderr, "UDP recv failed\n"); 
            goto cleanup; 
        }

        printf("Server responded: ");
        print_message(resp, n);
    }

cleanup:
    if(udp_fd >= 0) close(udp_fd);
    mbedtls_ssl_close_notify(&ssl);
    close(tls_fd);
    mbedtls_ssl_free(&ssl);
    return 0;
}