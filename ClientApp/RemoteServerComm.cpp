#include "RemoteServerComm.h"

int SendData(char* ip_address, int port, unsigned char* buffer, size_t size) {
    WSADATA wsa;
    SOCKET sockfd;
    struct sockaddr_in server_addr;

    if (size > MAX_BUFFER_SIZE) {
        printf("Size is greater than MAX_BUFFER_SIZE\n");
        return -1;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return -1;
    }

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return -1;
    }

    // Fill in server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip_address);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed.\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    // Send data
    int bytes_sent = send(sockfd, (char*)buffer, size, 0);
    if (bytes_sent < 0) {
        printf("Send failed.\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    // Close socket and cleanup
    closesocket(sockfd);
    WSACleanup();
    return 0;
}

int ReceiveData(unsigned char** buffer_ptr, size_t* size_ptr, int port) {
    WSADATA wsa;
    SOCKET listenfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    int addrlen = sizeof(client_addr);

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return -1;
    }

    // Create socket
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return -1;
    }

    // Fill in server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socket
    if (bind(listenfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Bind failed.\n");
        closesocket(listenfd);
        WSACleanup();
        return -1;
    }

    // Listen for connections
    if (listen(listenfd, 3) < 0) {
        printf("Listen failed.\n");
        closesocket(listenfd);
        WSACleanup();
        return -1;
    }

    // Accept connection
    if ((connfd = accept(listenfd, (struct sockaddr*)&client_addr, (int*)&addrlen)) == INVALID_SOCKET) {
        printf("Accept failed.\n");
        closesocket(listenfd);
        WSACleanup();
        return -1;
    }

    if (*buffer_ptr != NULL) {
        printf("Buffer already allocated.\n");
        return -1;
    }

    *buffer_ptr = (unsigned char*)malloc(MAX_BUFFER_SIZE);

    // Receive data
    int bytes_received = recv(connfd, (char*)*buffer_ptr, MAX_BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        printf("Receive failed.\n");
        closesocket(listenfd);
        closesocket(connfd);
        WSACleanup();
        return -1;
    }

    *buffer_ptr = (unsigned char*) realloc(*buffer_ptr, bytes_received);

    // Set size_ptr to the actual number of bytes received
    *size_ptr = bytes_received;

    // Close sockets and cleanup
    closesocket(connfd);
    closesocket(listenfd);
    WSACleanup();
    return 0;
}
