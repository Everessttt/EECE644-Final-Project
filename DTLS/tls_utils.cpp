
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/md.h>
#include <mbedtls/ssl_ciphersuites.h>

#include "common.h"
#include "tls_utils.h"

#include "../ChaCha20-Poly1305.h"
#include <vector>
#include <string>
using std::vector;
using std::string;

//UDP send & recv using custom encryption
int udp_send_line(int fd, const struct sockaddr* dest_addr, socklen_t addrlen, 
    const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& plaintext, const vector<uint8_t>& ad)
{
    //encrypt data
    AEAD_encrypt AEAD = ChaCha20_Poly1305_encrypt(key, nonce, plaintext, ad);
    
    //create buffer: nonce || ciphertext || tag
    vector<uint8_t> buf;
    buf.reserve(nonce.size() + AEAD.ciphertext.size() + AEAD.tag.size());
    buf.insert(buf.end(), nonce.begin(), nonce.end());
    buf.insert(buf.end(), AEAD.ciphertext.begin(), AEAD.ciphertext.end());
    buf.insert(buf.end(), AEAD.tag.begin(), AEAD.tag.end());
    
    //send via UDP
    ssize_t sent = sendto(fd, buf.data(), buf.size(), 0, dest_addr, addrlen);

    return (sent < 0) ? -1 : static_cast<int>(sent);
}

int udp_recv_line(int fd, struct sockaddr* src_addr, socklen_t* addrlen,
    const vector<uint8_t>& key, const vector<uint8_t>& ad, vector<uint8_t>& plaintext, size_t buflen)
{
    //receive data via UDP
    vector<uint8_t> buf(buflen);
    ssize_t received = recvfrom(fd, buf.data(), buf.size(), 0, src_addr, addrlen);

    if(received < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return -1;
    }
    else if(received < 28) {
        return -1;
    }
    
    buf.resize(received);

    //parse received message: nonce || ciphertext || tag
    vector<uint8_t> nonce(buf.begin(), buf.begin() + 12);
    vector<uint8_t> ciphertext(buf.begin() + 12, buf.end() - 16);
    vector<uint8_t> received_tag(buf.end() - 16, buf.end());

    //decrypt data and verify tag
    AEAD_decrypt AEAD = ChaCha20_Poly1305_decrypt(key, nonce, ciphertext, ad, received_tag);
    if(!AEAD.is_valid) {
        printf("Tag mismatch\n");
        return -1;
    }
    
    plaintext = AEAD.plaintext;
    return static_cast<int>(plaintext.size());
}

vector<uint8_t> derive_key(mbedtls_ssl_context* ssl, const char* label, size_t key_length)
{
    vector<uint8_t> key(key_length);
    
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info = 
        mbedtls_ssl_ciphersuite_from_id(ssl->session->ciphersuite);
    
    if(ciphersuite_info == NULL) {
        fprintf(stderr, "Failed to get ciphersuite info\n");
        return vector<uint8_t>();
    }
    
    mbedtls_tls_prf_types prf_type;
    mbedtls_md_type_t mac = ciphersuite_info->mac;
    
    if(mac == MBEDTLS_MD_SHA384) {
        prf_type = MBEDTLS_SSL_TLS_PRF_SHA384;
    } else {
        prf_type = MBEDTLS_SSL_TLS_PRF_SHA256;
    }
    
    const unsigned char* context = ssl->session->id;
    size_t context_len = ssl->session->id_len;
    
    int ret = mbedtls_ssl_tls_prf(
        prf_type,
        ssl->session->master,
        48,
        label,
        context,
        context_len,
        key.data(),
        key.size()
    );
    
    if(ret != 0) {
        fprintf(stderr, "Key derivation failed: -0x%04x\n", -ret);
        return vector<uint8_t>();
    }
    
    return key;
}

// TCP helpers
static void die_mbed(const char* context, int error_code) {
    char error_buf[100];
    mbedtls_strerror(error_code, error_buf, sizeof(error_buf));
    fprintf(stderr, "mbedTLS error in %s: -0x%04x - %s\n", context, -error_code, error_buf);
}

static int ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    int fd = *((int*)ctx);
    ssize_t ret = send(fd, buf, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(ret);
}

static int ssl_recv(void* ctx, unsigned char* buf, size_t len) {
    int fd = *((int*)ctx);
    ssize_t ret = recv(fd, buf, len, 0);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (ret == 0) {
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    return static_cast<int>(ret);
}

static int tcp_connect(const char* host, const char* port) {
    struct addrinfo hints, *res=NULL, *rp=NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err)); return -1; }
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int tcp_listen(const char* ip, const char* port) {
    struct addrinfo hints, *res=NULL, *rp=NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int err = getaddrinfo(ip, port, &hints, &res);
    if (err) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err)); return -1; }
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;
        int opt=1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(fd, rp->ai_addr, rp->ai_addrlen)==0 && listen(fd, 5)==0) break;
        close(fd); fd=-1;
    }
    freeaddrinfo(res);
    return fd;
}

// Robust line I/O
int tls_send_all(mbedtls_ssl_context* ssl, const unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int ret = mbedtls_ssl_write(ssl, buf + off, len - off);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) return ret;
        off += (size_t)ret;
    }
    return 0;
}

int tls_send_line(mbedtls_ssl_context* ssl, const char* line) {
    size_t len = strlen(line);
    char *tmp = (char*)malloc(len + 2);
    if (!tmp) return -1;
    memcpy(tmp, line, len);
    tmp[len] = '\n';
    tmp[len+1] = '\0';
    int rc = tls_send_all(ssl, (const unsigned char*)tmp, len + 1);
    free(tmp);
    return rc;
}

int tls_recv_line(mbedtls_ssl_context* ssl, char* buf, size_t buflen) {
    size_t pos = 0;
    while (pos + 1 < buflen) {
        unsigned char c;
        int ret = mbedtls_ssl_read(ssl, &c, 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            if (pos > 0) { buf[pos] = '\0'; return (int)pos; }
            return ret;
        }
        if (ret <= 0) return ret;
        if (c == '\n') { buf[pos] = '\0'; return (int)pos; }
        buf[pos++] = (char)c;
    }
    return -1;
}

// Client setup
int tls_client_connect(const char* host, const char* port,
                       const char* ca_pem_path,
                       int* out_fd, mbedtls_ssl_context* out_ssl) {
    int ret = 0;
    int fd = tcp_connect(host, port);
    if (fd < 0) { perror("tcp_connect"); return -1; }

    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt cacert;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_entropy_context entropy;
    static int inited = 0;

    if (!inited) {
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        const char* pers = "client";
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char*)pers, strlen(pers))) != 0) {
            die_mbed("ctr_drbg_seed", ret); close(fd); return -1;
        }
        if ((ret = mbedtls_x509_crt_parse_file(&cacert, ca_pem_path)) < 0) {
            die_mbed("x509_crt_parse_file(ca)", ret); close(fd); return -1;
        }
        if ((ret = mbedtls_ssl_config_defaults(&conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            die_mbed("ssl_config_defaults", ret); close(fd); return -1;
        }
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        inited = 1;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { die_mbed("ssl_setup", ret); close(fd); return -1; }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, APP_SERVER_NAME)) != 0) { die_mbed("ssl_set_hostname", ret); close(fd); return -1; }
    mbedtls_ssl_set_bio(&ssl, &fd, ssl_send, ssl_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            die_mbed("ssl_handshake", ret); close(fd); return -1;
        }
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[256];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof vrfy_buf, "  ! ", flags);
        fprintf(stderr, "Certificate verification failed:\n%s\n", vrfy_buf);
        close(fd);
        return -1;
    }

    // Rebind BIO ctx to caller-owned fd address to avoid dangling pointer
    *out_fd = fd;
    mbedtls_ssl_set_bio(&ssl, out_fd, ssl_send, ssl_recv, NULL);
    *out_ssl = ssl;
    return 0;
}


// Server setup
int tls_server_listen(const char* bind_ip, const char* port,
                      const char* cert_path, const char* key_path,
                      int* out_listen_fd) {
    (void)cert_path; (void)key_path;
    int fd = tcp_listen(bind_ip, port);
    if (fd < 0) { perror("tcp_listen"); return -1; }
    *out_listen_fd = fd;
    return 0;
}

int tls_server_accept(int listen_fd, mbedtls_ssl_context* out_ssl, int* out_client_fd) {
    struct sockaddr_storage ss; socklen_t slen = sizeof(ss);
    int cfd = accept(listen_fd, (struct sockaddr*)&ss, &slen);
    if (cfd < 0) { perror("accept"); return -1; }

    int ret;
    static mbedtls_ssl_config conf;
    static mbedtls_x509_crt srvcert;
    static mbedtls_pk_context pkey;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_entropy_context entropy;
    static int inited = 0;

    if (!inited) {
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&srvcert);
        mbedtls_pk_init(&pkey);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        const char* pers = "server";
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char*)pers, strlen(pers))) != 0) {
            die_mbed("server ctr_drbg_seed", ret); close(cfd); return -1;
        }

        if ((ret = mbedtls_x509_crt_parse_file(&srvcert, "../certs/server.crt.pem")) < 0) {
            die_mbed("x509_crt_parse_file(server)", ret); close(cfd); return -1;
        }
        if ((ret = mbedtls_pk_parse_keyfile(&pkey, "../certs/server.key.pem", NULL)) < 0) {
            die_mbed("pk_parse_keyfile(server)", ret); close(cfd); return -1;
        }

        if ((ret = mbedtls_ssl_config_defaults(&conf,
                                               MBEDTLS_SSL_IS_SERVER,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            die_mbed("server ssl_config_defaults", ret); close(cfd); return -1;
        }
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
            die_mbed("ssl_conf_own_cert", ret); close(cfd); return -1;
        }
        inited = 1;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { die_mbed("server ssl_setup", ret); close(cfd); return -1; }
    mbedtls_ssl_set_bio(&ssl, &cfd, ssl_send, ssl_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            die_mbed("server ssl_handshake", ret); close(cfd); return -1;
        }
    }

    // Rebind BIO ctx to caller-owned fd address to avoid dangling pointer
    *out_client_fd = cfd;
    mbedtls_ssl_set_bio(&ssl, out_client_fd, ssl_send, ssl_recv, NULL);
    *out_ssl = ssl;
    return 0;
}
