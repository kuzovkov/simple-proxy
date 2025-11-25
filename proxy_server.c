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
#include <time.h> // Для таймаута
#include <getopt.h>
#include <signal.h>

// --- Общий код и настройки ---
#define XOR_KEY_DEFAULT 0xAB
#define PROXY_PORT_DEFAULT 7000
#define BUFFER_SIZE 4096
#define MAX_HOSTNAME_LEN 255
#define TIMEOUT_SEC 5 // Таймаут для чтения заголовка

uint16_t PROXY_PORT = 7000;
unsigned char XOR_KEY = 0xAB; 


// Функция XOR-шифрования/дешифрования
void xor_data(char* data, int len) {
    for (int i = 0; i < len; ++i) {
        data[i] ^= XOR_KEY;
    }
}

// Утилита для получения порта из 2 байтов (сетевой порядок)
unsigned short get_port_from_bytes(char* bytes) {
    unsigned short port;
    memcpy(&port, bytes, 2);
    return ntohs(port);
}
// -----------------------------

/**
 * Функция для гарантированного чтения определенного числа байт из сокета.
 * @param sock_fd Файловый дескриптор сокета.
 * @param buffer Буфер для записи данных.
 * @param len Количество байт, которое нужно прочитать.
 * @return Количество прочитанных байт или -1 в случае ошибки/закрытия.
 */
int guaranteed_recv(int sock_fd, char* buffer, size_t len) {
    size_t total_received = 0;
    int bytes_left = len;
    
    while (total_received < len) {
        int received = recv(sock_fd, buffer + total_received, bytes_left, 0);
        
        if (received == 0) return 0; // Соединение закрыто
        if (received < 0) {
            if (errno == EINTR) continue; // Прервано сигналом
            perror("recv error in guaranteed_recv");
            return -1;
        }
        
        total_received += received;
        bytes_left -= received;
    }
    return total_received;
}


/**
 * Устанавливает исходящее соединение на основе данных из заголовка.
 * Возвращает файловый дескриптор сокета цели или -1 в случае ошибки.
 */
int connect_to_target(char* hostname, unsigned short port) {
    int target_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (target_sock < 0) {
        perror("target socket");
        return -1;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    
    struct hostent *host_info = gethostbyname(hostname);
    if (host_info == NULL) {
        fprintf(stderr, "DNS resolution failed for %s\n", hostname);
        close(target_sock);
        return -1;
    }
    
    memcpy(&target_addr.sin_addr, host_info->h_addr_list[0], host_info->h_length);

    if (connect(target_sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        perror("connect to target failed");
        close(target_sock);
        return -1;
    }
    
    printf("Child process %d: Connected to target %s:%d\n", getpid(), hostname, port);
    return target_sock;
}

/**
 * Читает и обрабатывает заголовок с данными о цели.
 * Возвращает размер заголовка, или -1 в случае ошибки.
 * После успешного вызова буфер сокета очищен от заголовка.
 */
int read_and_process_header(int client_sock, int* target_sock_ptr) {
    char hostname_buffer[MAX_HOSTNAME_LEN + 3]; // 1 (длина) + 255 (домен) + 2 (порт)
    int received_len;
    
    // 1. Чтение 1-го байта: Длина адреса (L)
    received_len = guaranteed_recv(client_sock, hostname_buffer, 1);
    if (received_len <= 0) return -1;
    
    // Дешифруем только этот байт, чтобы получить длину L
    xor_data(hostname_buffer, 1);
    int addr_len = (unsigned char)hostname_buffer[0];
    
    if (addr_len == 0 || addr_len > MAX_HOSTNAME_LEN) {
        fprintf(stderr, "Child %d: Invalid address length (%d).\n", getpid(), addr_len);
        return -1;
    }
    
    // 2. Чтение оставшейся части заголовка: L байт (домен) + 2 байта (порт)
    int remaining_header_len = addr_len + 2;
    
    // Читаем оставшиеся N+2 байта заголовка, начиная с hostname_buffer[1]
    received_len = guaranteed_recv(client_sock, hostname_buffer + 1, remaining_header_len);
    if (received_len <= 0) return -1;
    
    // Дешифруем оставшуюся часть заголовка
    xor_data(hostname_buffer + 1, remaining_header_len);
    
    // 3. Извлечение информации и установка соединения
    char hostname[MAX_HOSTNAME_LEN + 1];
    memcpy(hostname, hostname_buffer + 1, addr_len);
    hostname[addr_len] = '\0';
    
    unsigned short port = get_port_from_bytes(hostname_buffer + 1 + addr_len);
    
    *target_sock_ptr = connect_to_target(hostname, port);
    if (*target_sock_ptr < 0) {
        return -1;
    }
    
    // Общая длина заголовка
    return 1 + addr_len + 2;
}


void handle_connection(int client_sock) {
    int target_sock = -1;
    char buffer[BUFFER_SIZE];
    fd_set read_fds;
    
    // 1. Обработка заголовка: читаем, расшифровываем, устанавливаем target_sock
    if (read_and_process_header(client_sock, &target_sock) < 0) {
        fprintf(stderr, "Child %d: Failed to establish target connection.\n", getpid());
        close(client_sock);
        return;
    }
    
    // 2. Двусторонний ретранслятор
    int max_fd = (client_sock > target_sock) ? client_sock : target_sock;
    printf("Child process %d: Relay started.\n", getpid());

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(target_sock, &read_fds);

        // Устанавливаем небольшой таймаут, чтобы избежать бесконечного зависания
        struct timeval tv = {1, 0}; 

        if (select(max_fd + 1, &read_fds, NULL, NULL, &tv) == -1) {
            if (errno == EINTR) continue;
            perror("select error"); break;
        }

        // A. Client -> Target (Расшифровка)
        if (FD_ISSET(client_sock, &read_fds)) {
            int received_len = recv(client_sock, buffer, BUFFER_SIZE, 0);
            if (received_len <= 0) break; 
            xor_data(buffer, received_len);
            send(target_sock, buffer, received_len, 0);
        }

        // B. Target -> Client (Шифрование)
        if (FD_ISSET(target_sock, &read_fds)) {
            int received_len = recv(target_sock, buffer, BUFFER_SIZE, 0);
            if (received_len <= 0) break;
            xor_data(buffer, received_len);
            send(client_sock, buffer, received_len, 0);
        }
    }

    // Завершение
    close(target_sock);
    close(client_sock);
    return; 
}

void clean_up_zombies() {
    // Уборка "зомби" процессов (неблокирующий wait)
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    int listen_sock, client_sock;
    struct sockaddr_in proxy_addr;
    pid_t pid;
    int option;

    struct option long_opts[] = {
        {"xor-byte", required_argument, 0, 'x'},
        {"listen", required_argument, 0, 'l'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((option = getopt_long(argc, argv, "x:l:h", long_opts, NULL)) != -1) {
        switch (option) {
            case 'x':
                XOR_KEY = (unsigned char) strtoul(optarg, NULL, 0);
                break;
            case 'l':
                PROXY_PORT = (uint16_t) atoi(optarg);
                break;
            case 'h':
                printf("Usage: proxy_server [-x xor-byte]  [-l listen] [--help]\n");
                return 0;
            default:
                return 1;
        }
    }

    // 1. Настройка Прослушивающего сокета
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == -1) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(PROXY_PORT);

    if (bind(listen_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("bind"); close(listen_sock); return 1;
    }
    if (listen(listen_sock, 10) < 0) {
        perror("listen"); close(listen_sock); return 1;
    }
    printf("Proxy Server listening on port %d (PID: %d) (XOR_KEY: 0x%02X) \n", PROXY_PORT, getpid(), (unsigned int)XOR_KEY);

    // 2. Главный цикл приема соединений
    while (1) {
        //clean_up_zombies();
        signal(SIGCHLD, SIG_IGN);
        client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept(server)");
            continue;
        }
        
        printf("\nParent PID %d: New client accepted. Forking...\n", getpid());

        pid = fork();

        if (pid < 0) {
            perror("fork failed");
            close(client_sock);
        } else if (pid == 0) {
            // ДОЧЕРНИЙ ПРОЦЕСС
            close(listen_sock); 
            handle_connection(client_sock);
            _exit(0);
        } else {
            // РОДИТЕЛЬСКИЙ ПРОЦЕСС
            close(client_sock); 
        }
    }

    close(listen_sock);
    return 0;
}