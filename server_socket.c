#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int optval;
    socklen_t optlen = sizeof(optval);

    // Create a TCP socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080); // Use any desired port number

    // Bind the socket to the specified address and port
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Binding failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Listening failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port 8080...\n");

    // Accept incoming connections
    socklen_t client_len = sizeof(client_addr);
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket == -1) {
        perror("Accepting connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Get the value of SO_REUSEADDR option
    if (getsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) == -1) {
        perror("getsockopt failed");
        close(client_socket);
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Check the value of SO_REUSEADDR option
    if (optval) {
        printf("SO_REUSEADDR is set for the socket.\n");
    } else {
        printf("SO_REUSEADDR is not set for the socket.\n");
    }

    // Close the sockets
    close(client_socket);
    close(server_socket);

    return 0;
}
