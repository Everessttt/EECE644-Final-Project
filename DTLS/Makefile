all: server client

server: server.cpp helpers.cpp tls_utils.cpp ../ChaCha20-Poly1305.cpp
	g++ server.cpp helpers.cpp tls_utils.cpp ../ChaCha20-Poly1305.cpp -o server -lmbedtls -lmbedcrypto -lmbedx509 -Wall

client: client.cpp helpers.cpp tls_utils.cpp ../ChaCha20-Poly1305.cpp
	g++ client.cpp helpers.cpp tls_utils.cpp ../ChaCha20-Poly1305.cpp -o client -lmbedtls -lmbedcrypto -lmbedx509 -Wall

clean:
	rm -f server client

.PHONY: all clean