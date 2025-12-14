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
#include <iostream>

using std::vector;
using std::string;
using std::cout;

int main(int argc, char** argv) 
{
    const char* bind_ip = APP_HOST_DEFAULT;
    const char* port = APP_PORT_DEFAULT;
    const char* cert = "../certs/server.crt.pem";
    const char* keyfile = "../certs/server.key.pem";

    int tls_lfd;
    if(tls_server_listen(bind_ip, port, cert, keyfile, &tls_lfd) != 0) {
        fprintf(stderr, "TLS server listen failed\n");
        return 1;
    }
    fprintf(stderr, "TLS on %s:%s\n", bind_ip, port);
    
    //create UDP socket
    int udp_port = atoi(port) + 1;
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_fd < 0) {
        perror("UDP socket creation failed");
        return 1;
    }
    
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = inet_addr(bind_ip);
    udp_addr.sin_port = htons(udp_port);
    
    if(bind(udp_fd, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_fd);
        return 1;
    }
    fprintf(stderr, "UDP on port %d\n", udp_port);
    
    while(1) {
        mbedtls_ssl_context ssl;
        int tls_fd;
        if(tls_server_accept(tls_lfd, &ssl, &tls_fd) != 0) { 
            continue; 
        }
        cout << "Client connected via TLS\n";

        vector<uint8_t> key;
        vector<uint8_t> ad;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        key = derive_key(&ssl, "udp_encryption");
        if (key.empty()) {
            fprintf(stderr, "Key derivation failed\n");
            goto cleanup;
        }
        fprintf(stderr, "Tranferring file...\n");

        if(recv_file(udp_fd, (struct sockaddr*)&client_addr,
                        &client_len, key, ad, "./server_files") != 0) {
            fprintf(stderr, "File receive failed\n");
            goto cleanup;
        }
        fprintf(stderr, "File transfer complete!\n");

    cleanup:
        mbedtls_ssl_close_notify(&ssl);
        close(tls_fd);
        mbedtls_ssl_free(&ssl);
    }
    
    close(udp_fd);
    return 0;
}