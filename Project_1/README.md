### 

# CS118 Project 1: HTTPS Web Server

## Requirements

```bash
sudo apt-get install libssl-dev
```

## Building

```bash
make
```

Produces executable named `server`.

## Running

```bash
./server
```

Default: listens on port 8443, proxies to 127.0.0.1:5001

### Command-line options:

```bash
./server -b <port> -r <host> -p <port>
```

- `-b`: Local port (default 8443)
- `-r`: Remote host (default 127.0.0.1)
- `-p`: Remote port (default 5001)

## Testing

### Browser:

```
https://localhost:8443/index.html
```

Accept the certificate warning (self-signed certificate).

### curl:

```bash
curl -k https://localhost:8443/test.html
```

The `-k` flag accepts self-signed certificates.

### Binary file test:

```bash
cat /dev/urandom | head -c 1000000 > binaryfile
curl -k https://localhost:8443/binaryfile -o downloadfile
diff binaryfile downloadfile
```

## SSL Certificates

Place `server.crt` and `server.key` in the same directory as the `server` executable.

## Backend Server (for testing)

```bash
cd video_server
python3 -m http.server 5001
```

Then run your server with:

```bash
./server -r 127.0.0.1 -p 5001
```

## Common Issues

**SSL errors**: Ensure certificates are in current directory and check `ERR_print_errors_fp(stderr)` output.

**Compilation errors**: Verify Makefile has `-lssl -lcrypto` flags.

**Certificate warnings**: Expected for self-signed certificates - click "Advanced" → "Proceed".
