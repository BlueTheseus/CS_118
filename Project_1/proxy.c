#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>

#include <openssl/bio.h>

#define BUFFER_SIZE 1024
#define DEFAULT_LOCAL_PORT_TO_CLIENT 8443
#define DEFAULT_REMOTE_HOST "127.0.0.1"
#define DEFAULT_REMOTE_PORT 5001

int LOCAL_PORT_TO_CLIENT = 8443;
char REMOTE_HOST[] = "127.0.0.1";
int REMOTE_PORT = 5001;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

/* command-line arguments:
 * -b  local port
 * -r  remote host IP address
 * -p  remote port
 */
void parse_args(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

	for (int i = 0; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
				case 'b':
					LOCAL_PORT_TO_CLIENT = atoi(argv[i+1]);
					break;
				case 'r':
					strcpy(REMOTE_HOST, argv[i+1]);
					break;
				case 'p':
					REMOTE_PORT = atoi(argv[i+1]);
					break;
			};
		}
	}

	printf("\nset options:\n\tLocal port: %i (default 8443)\n\tRemote host: %s (default 127.0.0.1)\n\tRemote port: %i (default 5001)\n\n",
			LOCAL_PORT_TO_CLIENT,
			REMOTE_HOST,
			REMOTE_PORT
	      );
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // Initialize OpenSSL library
    if (!OPENSSL_init_ssl(0, NULL)) {
        perror("Error: openssl init failed");
        exit(EXIT_FAILURE);
    }

	SSL_METHOD *ssl_method = TLS_server_method();
    
    // Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        perror("Error: create SSL context failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "server.crt") != 1) {
        perror("Error: SSL load cert failed");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) != 1) {
        perror("Error: SSL load key failed");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        perror("Error: PKey and Cert don't match");
        exit(EXIT_FAILURE);
    }

    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

	if (SSL_CTX_get0_certificate(ssl_ctx) == NULL) {
		fprintf(stderr, "Error: No active certificate in SSL context\n");
		exit(EXIT_FAILURE);
	}

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error: socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error: bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (listen(server_socket, 10) == -1) {
        perror("Error: listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1) {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);

		SSL_set_accept_state(ssl);
        SSL_set_fd(ssl, client_socket);

		if (!SSL_is_server) {
			fprintf(stderr, "Error: SSL is not in accept state.\n");
		}

		//int ssl_handshake_error = SSL_accept(ssl);
		int ssl_handshake_error = SSL_do_handshake(ssl);

		if (ssl_handshake_error == 0) {
			fprintf(stderr, "Error: TLS/SSL handshake not successful but was shut down controlled and by the specifications of the TLS/SSL protocol.\n");
		}
		if (ssl_handshake_error < 0) {
			fprintf(stderr, "Error: TLS/SSL handshake not successful due to fatal error at protocol level or a connection failure occurred\n");
		}

        if (ssl != NULL) {
            handle_request(ssl);
        }
        
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }

        // Clean up SSL connection
        SSL_shutdown(ssl);
		SSL_free(ssl);

        close(client_socket);
    }

    close(server_socket);

    // Clean up SSL context
	SSL_CTX_free(ssl_ctx);
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Read request from SSL connection
    bytes_read = 0;

	int ssl_read_err = SSL_read_ex(ssl, buffer, 1024, &bytes_read);

	if (ssl_read_err <= 0) {
		printf("Error: SSL_read_ex() returned error code %i\n", ssl_read_err);
	}

    if (bytes_read <= 0) {
		fprintf(stderr, "Error: %i bytes read in SSL_read_ex()\n", bytes_read);
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    
    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    file_name++;
    if (strlen(file_name) == 0) {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

	char *to_replace = strstr(file_name, "%20");
	if (to_replace != NULL) {
		memcpy(to_replace, " ", 1);
		memmove(to_replace + 1, to_replace + 3, strlen(to_replace + 3) + 1);
	}

	to_replace = strstr(file_name, "%25");
	if (to_replace != NULL) {
		memcpy(to_replace, "%", 1);
		memmove(to_replace + 1, to_replace + 3, strlen(to_replace + 3) + 1);
	}

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

// Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";

        // Send response via SSL
		SSL_write(ssl, response, strlen(response));
        return;
    }
    
    char *content_type;
    if (strstr(path, ".html")) {
        content_type = "text/html";
	} else if (strstr(path, ".txt")) {
        content_type = "text/plain";
	} else if (strstr(path, ".jpg")) {
        content_type = "image/jpeg";
	} else if (strstr(path, ".m3u8")) {
        content_type = "application/vnd.apple.mpegurl";
    } else {
        content_type = "application/octet-stream";
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        printf("Error: Could not determine file size");
        return;
    }

    char *response = malloc(512);
    snprintf(response, 512, "HTTP/1.1 200 OK\r\n"
                   "Content-Type: %s; charset=UTF-8\r\n"
                   "Content-Length: %lld\r\n"
                   "Connection: close\r\n\r\n", content_type, (long long)st.st_size);

    // Send response header and file content via SSL
	SSL_write(ssl, response, strlen(response));

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        size_t total_written = 0;
        while (total_written < bytes_read) {
            int ret = SSL_write(ssl, buffer + total_written, bytes_read - total_written);
            if (ret <= 0) {
                int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                ERR_print_errors_fp(stderr);
                break;
            }
            total_written += ret;
        }
    }
    fclose(file);
}

// Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Error: Failed to create remote socket\n");

        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1></body></html>";

        // Send response via SSL
		SSL_write(ssl, response, strlen(response));
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Error: Failed to connect to remote server\n");
        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1></body></html>";

        // Send response via SSL
		SSL_write(ssl, response, strlen(response));
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // Forward response to client via SSL
        size_t total_written = 0;
        while (total_written < bytes_read) {
            int ret = SSL_write(ssl, buffer + total_written, bytes_read - total_written);
            if (ret <= 0) {
                int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                ERR_print_errors_fp(stderr);
                break;
            }
            total_written += ret;
        }
    }

    close(remote_socket);
    return;
}
