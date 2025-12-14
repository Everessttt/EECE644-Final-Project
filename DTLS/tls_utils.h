
#pragma once
#include <mbedtls/ssl.h>
#include <vector>

int udp_send_line(int fd, const struct sockaddr* dest_addr, socklen_t addrlen, 
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ad);
int udp_recv_line(int fd, struct sockaddr* src_addr, socklen_t* addrlen,
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& ad, std::vector<uint8_t>& plaintext, size_t buflen);
std::vector<uint8_t> derive_key(mbedtls_ssl_context* ssl, const char* label, size_t key_length = 32);

int tls_client_connect(const char* host, const char* port,
                       const char* ca_pem_path,
                       int* out_fd, mbedtls_ssl_context* out_ssl);

int tls_server_listen(const char* bind_ip, const char* port,
                      const char* cert_path, const char* key_path,
                      int* out_listen_fd);

int tls_server_accept(int listen_fd, mbedtls_ssl_context* out_ssl, int* out_client_fd);

// Robust line I/O
int tls_send_all(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len);
int tls_send_line(mbedtls_ssl_context* ssl, const char* line);
int tls_recv_line(mbedtls_ssl_context* ssl, char* buf, size_t buflen);
