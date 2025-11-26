#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <getopt.h>
#include <signal.h>
#include "hmac.h"

// --- Общий код и настройки ---
#define XOR_KEY_DEFAULT 0xAB
#define LOCAL_PROXY_PORT_DEFAULT 9000    // Порт, который должен использовать браузер
#define REMOTE_PROXY_IP_DEFAULT "77.221.145.94" // IP вашего Удаленного XOR-сервера
#define REMOTE_PROXY_PORT_DEFAULT 7000   // Порт вашего Удаленного XOR-сервера
#define BUFFER_SIZE 4096
#define MAX_HOSTNAME_LEN 255


uint16_t LOCAL_PROXY_PORT = 9000;
uint16_t REMOTE_PROXY_PORT = 7000;
unsigned char XOR_KEY = 0xAB; 
char REMOTE_PROXY_IP[15] = "77.221.145.94"; 
char SERVER_PASSWORD[128] = "P@ssw0rd"; 

void xor_data(char* data, int len) {
    for (int i = 0; i < len; ++i) {
        data[i] ^= XOR_KEY;
    }
}

void get_port_bytes(unsigned short port, char* bytes) {
    unsigned short net_port = htons(port);
    memcpy(bytes, &net_port, 2);
}

// -----------------------------

/**
 * Читает данные от браузера и извлекает TARGET_HOST и TARGET_PORT.
 * Возвращает 0 в случае успеха, -1 в случае ошибки.
 */
int parse_connect_request(int browser_sock, char *target_host, unsigned short *target_port) {
    char buffer[BUFFER_SIZE];
    int received_len = recv(browser_sock, buffer, BUFFER_SIZE - 1, MSG_PEEK);
    
    if (received_len <= 0) {
        perror("recv error on browser connection");
        return -1;
    }
    buffer[received_len] = '\0'; // Гарантируем завершение строки
    
    char method[16], host_str[MAX_HOSTNAME_LEN + 1];
    int port_int = 0;
    
    // Парсим строку: CONNECT example.com:443 HTTP/1.1
    // Браузеры обычно отправляют HOST:PORT, иногда просто HOST
    if (sscanf(buffer, "%15s %255s", method, host_str) != 2 || strcmp(method, "CONNECT") != 0) {
        // Это не CONNECT-запрос, или формат неверен.
        fprintf(stderr, "Unsupported protocol or bad request.\n");
        return -1;
    }

    char *port_separator = strchr(host_str, ':');
    if (port_separator) {
        *port_separator = '\0'; // Обрезаем строку, чтобы host_str остался только хостом
        port_int = atoi(port_separator + 1); // Порт идет после ':'
    } else {
        // Если порт не указан (редко для CONNECT), предполагаем 443 (HTTPS)
        port_int = 443;
    }

    if (port_int <= 0 || port_int > 65535) {
        fprintf(stderr, "Invalid port number: %d\n", port_int);
        return -1;
    }

    strncpy(target_host, host_str, MAX_HOSTNAME_LEN);
    *target_port = (unsigned short)port_int;
    
    // Удаляем заголовок CONNECT из буфера сокета (Читаем все, что было получено)
    char dummy_buffer[BUFFER_SIZE];
    while(strstr(buffer, "\r\n\r\n") == NULL) { // Читаем, пока не найдем конец HTTP-заголовка
        recv(browser_sock, dummy_buffer, BUFFER_SIZE, 0); 
        // В реальном коде это должно быть более надежно
        break; 
    }
    recv(browser_sock, dummy_buffer, received_len, 0); // Упрощенное удаление буфера

    return 0;
}

/**
 * Устанавливает исходящее соединение с Удаленным XOR-Прокси-Сервером.
 * Возвращает сокет или -1.
 */
int connect_to_remote_proxy() {
    int remote_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_sock < 0) { perror("remote socket"); return -1; }

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(REMOTE_PROXY_PORT);
    inet_pton(AF_INET, REMOTE_PROXY_IP, &remote_addr.sin_addr);

    if (connect(remote_sock, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
        perror("connect to remote proxy failed");
        close(remote_sock);
        return -1;
    }
    
    printf("Child %d: Connected to remote XOR-Proxy %s:%d\n", getpid(), REMOTE_PROXY_IP, REMOTE_PROXY_PORT);
    // 1. Получаем challenge от сервера
    uint8_t challenge[32];
    int n = recv(remote_sock, challenge, 32, 0);
    if (n != 32) {
        printf("Server sent no challenge!\n");
        return -1;
    }

    // 2. Вычисляем HMAC
    uint8_t my_hmac[32];
    hmac_sha256(
        (uint8_t*)SERVER_PASSWORD,
        strlen(SERVER_PASSWORD),
        challenge,
        32,
        my_hmac
    );

    // 3. Отправляем серверу
    send(remote_sock, my_hmac, 32, 0);

    return remote_sock;
}

/**
 * Отправляет зашифрованный заголовок цели на Удаленный Прокси-Сервер.
 */
int send_xor_header(int remote_sock, const char* target_host, unsigned short target_port) {
    char header_buffer[MAX_HOSTNAME_LEN + 3];
    int addr_len = strlen(target_host);
    int header_len = 1 + addr_len + 2; 

    if (addr_len > MAX_HOSTNAME_LEN) return -1;

    int offset = 0;
    
    // Формируем заголовок
    header_buffer[offset++] = (unsigned char)addr_len; 
    memcpy(header_buffer + offset, target_host, addr_len);
    offset += addr_len;
    get_port_bytes(target_port, header_buffer + offset);
    
    // Шифруем и отправляем
    xor_data(header_buffer, header_len);
    if (send(remote_sock, header_buffer, header_len, 0) != header_len) {
        perror("send header failed");
        return -1;
    }
    
    printf("Child %d: Sent XOR header for %s:%d\n", getpid(), target_host, target_port);
    return 0;
}

void handle_browser_connection(int browser_sock) {
    char target_host[MAX_HOSTNAME_LEN + 1];
    unsigned short target_port;
    int remote_sock = -1;
    char buffer[BUFFER_SIZE];
    fd_set read_fds;

    // 1. Парсинг запроса от браузера для получения цели
    if (parse_connect_request(browser_sock, target_host, &target_port) < 0) {
        close(browser_sock);
        return;
    }
    
    printf("Child %d: Browser requested connection to %s:%d\n", getpid(), target_host, target_port);

    // 2. Установка соединения с Удаленным XOR-Прокси
    remote_sock = connect_to_remote_proxy();
    if (remote_sock < 0) {
        // Отправка ошибки 503 Service Unavailable браузеру
        send(browser_sock, "HTTP/1.1 503 Service Unavailable\r\n\r\n", 36, 0);
        close(browser_sock);
        return;
    }

    // 3. Отправка XOR-заголовка цели Удаленному Прокси
    if (send_xor_header(remote_sock, target_host, target_port) < 0) {
        close(browser_sock);
        close(remote_sock);
        return;
    }
    
    // 4. Отправка ответа браузеру, что туннель установлен
    send(browser_sock, "HTTP/1.1 200 Connection Established\r\n\r\n", 39, 0);
    printf("Child %d: Tunnel established, starting relay.\n", getpid());

    // 5. Двусторонний ретранслятор (Браузер <-> XOR-Прокси)
    int max_fd = (browser_sock > remote_sock) ? browser_sock : remote_sock;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(browser_sock, &read_fds);
        FD_SET(remote_sock, &read_fds);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            if (errno == EINTR) continue;
            perror("select error"); break;
        }

        // A. Браузер -> Удаленный Прокси (Шифрование)
        if (FD_ISSET(browser_sock, &read_fds)) {
            int received_len = recv(browser_sock, buffer, BUFFER_SIZE, 0);
            if (received_len <= 0) break; 
            xor_data(buffer, received_len);
            send(remote_sock, buffer, received_len, 0);
        }

        // B. Удаленный Прокси -> Браузер (Дешифрование)
        if (FD_ISSET(remote_sock, &read_fds)) {
            int received_len = recv(remote_sock, buffer, BUFFER_SIZE, 0);
            if (received_len <= 0) break;
            xor_data(buffer, received_len);
            send(browser_sock, buffer, received_len, 0);
        }
    }

    // Завершение
    printf("Child %d: Connection closed.\n", getpid());
    close(remote_sock);
    close(browser_sock);
    //_exit(0);
    return; 
}

void clean_up_zombies() {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    int listen_sock, browser_sock;
    struct sockaddr_in proxy_addr;
    pid_t pid;
    int option;
    
    struct option long_opts[] = {
        {"server-host", required_argument, 0, 's'},
        {"xor-byte", required_argument, 0, 'x'},
        {"listen", required_argument, 0, 'l'},
        {"server-port", required_argument, 0, 'p'},
        {"secret-key", required_argument, 0, 'k'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((option = getopt_long(argc, argv, "s:x:l:p:k:h", long_opts, NULL)) != -1) {
        switch (option) {
            case 's':
                strcpy(REMOTE_PROXY_IP, optarg);
                break;
            case 'k':
                strcpy(SERVER_PASSWORD, optarg);
                break;
            case 'x':
                XOR_KEY = (unsigned char) strtoul(optarg, NULL, 0);
                break;
            case 'l':
                LOCAL_PROXY_PORT = (uint16_t) atoi(optarg);
                break;
            case 'p':
                REMOTE_PROXY_PORT = (uint16_t) atoi(optarg);
                break;
            case 'h':
                printf("Usage: proxy_client [-s server-host] [-x xor-byte] [-l listen] [-k secret-key] [-p server-port] [--help]\n");
                return 0;
            default:
                return 1;
        }
    }

    printf("REMOTE_PROXY_IP: %s\nLOCAL_PROXY_PORT: %i\nREMOTE_PROXY_PORT: %i\nXOR_KEY: 0x%02X \n",
         REMOTE_PROXY_IP, LOCAL_PROXY_PORT, REMOTE_PROXY_PORT, (unsigned int)XOR_KEY);
    // 1. Настройка Прослушивающего сокета
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == -1) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(LOCAL_PROXY_PORT);

    if (bind(listen_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("bind"); close(listen_sock); return 1;
    }
    if (listen(listen_sock, 10) < 0) {
        perror("listen"); close(listen_sock); return 1;
    }
    printf("Local Proxy listening on port %d for browser connections.\n", LOCAL_PROXY_PORT);
    printf("Forwarding to Remote XOR-Proxy at %s:%d\n", REMOTE_PROXY_IP, REMOTE_PROXY_PORT);

    // 2. Главный цикл приема соединений
    while (1) {
        //clean_up_zombies();
        signal(SIGCHLD, SIG_IGN);

        browser_sock = accept(listen_sock, NULL, NULL);
        if (browser_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept(client)");
            continue;
        }
        
        pid = fork();

        if (pid < 0) {
            perror("fork failed");
            close(browser_sock);
        } else if (pid == 0) {
            // ДОЧЕРНИЙ ПРОЦЕСС
            close(listen_sock); 
            handle_browser_connection(browser_sock);
            _exit(0);
        } else {
            // РОДИТЕЛЬСКИЙ ПРОЦЕСС
            close(browser_sock); 
        }
    }

    close(listen_sock);
    return 0;
}