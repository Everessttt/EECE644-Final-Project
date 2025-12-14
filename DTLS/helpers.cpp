#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <vector>
#include <cstring>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <sys/stat.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "helpers.h"
#include "tls_utils.h"
#include "../ChaCha20-Poly1305.h"

using namespace std;

#define MAX_LINE 65536
#define MAX_PACKET_SIZE 8192
#define MAX_RETRIES 5
#define RECV_TIMEOUT_SEC 2

vector<uint8_t> build_message(const char* message) {
    vector<uint8_t> line;
    size_t len = strlen(message);
    line.assign(message, message + len);
    
    return line;
}

void print_message(const vector<uint8_t>& message, size_t len)
{
    for(size_t i = 0; i < len && i < message.size(); i++) {
        printf("%c", message[i]);
    }
    printf("\n");
}

vector<uint8_t> generate_nonce(size_t nonce_size) 
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    const char* pers = "nonce_generation";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    
    vector<uint8_t> nonce(nonce_size);
    mbedtls_ctr_drbg_random(&ctr_drbg, nonce.data(), nonce_size);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return nonce;
}

string get_filename(const char* path) {
    char* path_copy = strdup(path);
    char* base = basename(path_copy);
    string result(base);
    free(path_copy);
    return result;
}

long get_file_size(const char* filename) {
    struct stat st;
    if(stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

int send_file(int fd, const struct sockaddr* dest_addr, socklen_t addrlen,
                const vector<uint8_t>& key, const vector<uint8_t>& ad, const char* filename)
{
    ifstream file(filename, ios::binary);
    if(!file.is_open()) {
        fprintf(stderr, "Failed to open file\n");
        return -1;
    }

    uint64_t file_size = get_file_size(filename);
    if(file_size <= 0) return -1;

    string fname = get_filename(filename);
    size_t max_data = MAX_PACKET_SIZE - sizeof(PacketHeader);

    {
        PacketHeader hdr{};
        hdr.type = PACKET_FILE_START;
        hdr.seq_num = 0;
        hdr.total_size = file_size;

        vector<uint8_t> payload(sizeof(PacketHeader) + fname.size());
        memcpy(payload.data(), &hdr, sizeof(hdr));
        memcpy(payload.data() + sizeof(hdr), fname.data(), fname.size());

        vector<uint8_t> nonce = generate_nonce();
        vector<uint8_t> packet(nonce);
        packet.insert(packet.end(), payload.begin(), payload.end());

        udp_send_line(fd, dest_addr, addrlen, key, nonce, payload, ad);

        vector<uint8_t> buf(MAX_LINE);
        struct sockaddr_in src{};
        socklen_t sl = sizeof(src);

        int n = udp_recv_line(fd, (sockaddr*)&src, &sl, key, ad, buf, MAX_LINE);
        if (n < (int)sizeof(AckHeader)) return -1;

        AckHeader ack;
        memcpy(&ack, buf.data(), sizeof(ack));
        if (ack.type != PACKET_ACK || ack.seq_num != 0) return -1;
    }

    uint32_t seq = 1;
    uint64_t offset = 0;
    vector<uint8_t> buffer(max_data);

    while(offset < file_size) {
        file.seekg(offset);
        file.read((char*)buffer.data(), max_data);
        size_t read_bytes = file.gcount();

        PacketHeader hdr{};
        hdr.type = PACKET_FILE_DATA;
        hdr.seq_num = seq;
        hdr.total_size = read_bytes;

        vector<uint8_t> payload(sizeof(PacketHeader) + read_bytes);
        memcpy(payload.data(), &hdr, sizeof(hdr));
        memcpy(payload.data() + sizeof(hdr), buffer.data(), read_bytes);

        int retries = 0;
        bool acked = false;

        while(retries < MAX_RETRIES && !acked) {
            vector<uint8_t> nonce = generate_nonce();
            udp_send_line(fd, dest_addr, addrlen, key, nonce, payload, ad);

            struct timeval tv{RECV_TIMEOUT_SEC, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            vector<uint8_t> buf(MAX_LINE);
            struct sockaddr_in src{};
            socklen_t sl = sizeof(src);

            int n = udp_recv_line(fd, (sockaddr*)&src, &sl, key, ad, buf, MAX_LINE);
            if(n >= (int)sizeof(AckHeader)) {
                AckHeader ack;
                memcpy(&ack, buf.data(), sizeof(ack));
                if(ack.type == PACKET_ACK && ack.seq_num == seq) {
                    acked = true;
                }
            }

            retries++;
        }

        if(!acked) {
            fprintf(stderr, "Packet %u failed\n", seq);
            return -1;
        }

        offset += read_bytes;
        seq++;
    }

    {
        PacketHeader hdr{};
        hdr.type = PACKET_FILE_END;
        hdr.seq_num = seq;
        hdr.total_size = offset;

        vector<uint8_t> payload(sizeof(hdr));
        memcpy(payload.data(), &hdr, sizeof(hdr));

        vector<uint8_t> nonce = generate_nonce();
        udp_send_line(fd, dest_addr, addrlen, key, nonce, payload, ad);
    }

    return 0;
}

int recv_file(int fd, struct sockaddr* src_addr, socklen_t* addrlen,
                const vector<uint8_t>& key, const vector<uint8_t>& ad, const char* output_dir)
{
    ofstream out;
    uint64_t expected_size = 0;
    uint64_t received = 0;
    uint32_t expected_seq = 1;
    string filename;
    string full_path;
    bool transfer_started = false;
    
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while(true) {
        vector<uint8_t> buf(MAX_LINE);
        int n = udp_recv_line(fd, src_addr, addrlen, key, ad, buf, MAX_LINE);
        
        if(n < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Timeout: Client disconnected\n");
                
                if(out.is_open()) {
                    out.close();
                    if(!full_path.empty()) {
                        fprintf(stderr, "Removing incomplete file: %s\n", full_path.c_str());
                        unlink(full_path.c_str());
                    }
                }
                return -1;
            }
            fprintf(stderr, "Receive error: %s\n", strerror(errno));
            if(out.is_open()) {
                out.close();
                if(!full_path.empty()) unlink(full_path.c_str());
            }
            return -1;
        }
        
        if(n < (int)sizeof(PacketHeader)) continue;

        PacketHeader hdr;
        memcpy(&hdr, buf.data(), sizeof(hdr));

        if(hdr.type == PACKET_FILE_START) {
            filename.assign((char*)buf.data() + sizeof(hdr),
                            n - sizeof(hdr));

            if(filename.find('/') != string::npos) {
                fprintf(stderr, "Invalid filename (contains path separator)\n");
                return -1;
            }

            expected_size = hdr.total_size;
            received = 0;
            expected_seq = 1;
            transfer_started = true;

            full_path = string(output_dir) + "/" + filename;
            out.open(full_path, ios::binary);
            
            if(!out.is_open()) {
                fprintf(stderr, "Failed to create output file: %s\n", full_path.c_str());
                return -1;
            }
            
            AckHeader ack{PACKET_ACK, 0};
            vector<uint8_t> nonce = generate_nonce();
            udp_send_line(fd, src_addr, *addrlen, key, nonce,
                          vector<uint8_t>((uint8_t*)&ack,
                          (uint8_t*)&ack + sizeof(ack)), ad);
        }

        else if(hdr.type == PACKET_FILE_DATA) {
            if(!transfer_started) {
                fprintf(stderr, "Received data packet before FILE_START\n");
                continue;
            }
            
            if(hdr.seq_num != expected_seq) {
                fprintf(stderr, "Sequence mismatch: expected %u, got %u\n", 
                        expected_seq, hdr.seq_num);
                continue;
            }

            size_t data_len = hdr.total_size;

            if(received + data_len > expected_size) {
                fprintf(stderr, "Received more data than expected\n");
                out.close();
                if (!full_path.empty()) unlink(full_path.c_str());
                return -1;
            }

            out.write((char*)buf.data() + sizeof(hdr), data_len);
            if (!out.good()) {
                fprintf(stderr, "File write error\n");
                out.close();
                if (!full_path.empty()) unlink(full_path.c_str());
                return -1;
            }
            
            received += data_len;
            expected_seq++;
            
            if(expected_seq % 100 == 0 || received == expected_size) {
                fprintf(stderr, "\rProgress: %lu/%lu bytes (%.1f%%)", 
                        received, expected_size, 
                        (received * 100.0) / expected_size);
                fflush(stderr);
            }

            AckHeader ack{PACKET_ACK, hdr.seq_num};
            vector<uint8_t> nonce = generate_nonce();
            udp_send_line(fd, src_addr, *addrlen, key, nonce,
                          vector<uint8_t>((uint8_t*)&ack,
                          (uint8_t*)&ack + sizeof(ack)), ad);
        }

        else if(hdr.type == PACKET_FILE_END) {
            fprintf(stderr, "\n");
            out.close();

            if(received != expected_size || received != hdr.total_size) {
                fprintf(stderr,
                    "Size mismatch: expected=%lu received=%lu end=%u\n",
                    expected_size, received, hdr.total_size);

                        
                if (!full_path.empty()) unlink(full_path.c_str());
                return -1;
            }

            return 0;
        }
    }
}