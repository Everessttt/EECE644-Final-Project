# EECE644 Final Project

This project implements **ChaCha20-Poly1305** alongside **DTLS** to securely upload files from client to server.

## Requirements

**mbedTLS** library

## ChaCha20-Poly1305

### Compile and Test

```bash
g++ ChaCha20-Poly1305.cpp main.cpp -Wall
./a.out
```

## DTLS Client/Server

### Generate Server Certificates

```bash
cd certs
chmod +x gen_self_signed.sh
./gen_self_signed.sh
```

### Compile Server and Client

```bash
cd DTLS
make
```

### Run Server

```bash
./server
```

### Run Client

```bash
./client ./client_files/<filename>
```

## File Transfer Details

Client must place files in:

  ```
  ./client_files
  ```
Server saves uploaded files to:

  ```
  ./server_files
  ```
