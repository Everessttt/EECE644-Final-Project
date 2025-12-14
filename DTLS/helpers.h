#pragma once

#include <vector>
#include <cstdint>

using namespace std;

struct AckHeader {
    uint8_t type;
    uint32_t seq_num;
};

enum PacketType {
    PACKET_FILE_START = 1,
    PACKET_FILE_DATA = 2,
    PACKET_FILE_END = 3,
    PACKET_ACK = 4
};

struct PacketHeader {
    uint8_t type;
    uint32_t seq_num;
    uint32_t total_size;
};

std::vector<uint8_t> build_message(const char* message);
void print_message(const std::vector<uint8_t>& message, size_t len);
std::vector<uint8_t> generate_nonce(size_t nonce_size = 12);
int send_file(int fd, const struct sockaddr* dest_addr, socklen_t addrlen,
                const std::vector<uint8_t>& key, const std::vector<uint8_t>& ad, const char* filename);
int recv_file(int fd, struct sockaddr* src_addr, socklen_t* addrlen,
                const std::vector<uint8_t>& key, const std::vector<uint8_t>& ad, const char* output_dir);