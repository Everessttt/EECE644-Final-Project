# Final Project

This project implements **ChaCha20-Poly1305** alongside **DTLS** to securely upload files from client to server.

## Requirements

**mbedTLS** library

## ChaCha20-Poly1305

### Compile

```bash
g++ ChaCha20-Poly1305.cpp main.cpp -Wall
```

### Test

```bash
./a.out
```

## DTLS Client/Server

### Change Directory

```bash
cd DTLS
```

### Compile Server and Client

```bash
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
