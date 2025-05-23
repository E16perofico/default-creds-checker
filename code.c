#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 256

int checkVulnerability(char *response){
    printf("[*] Analizzo la risposta per la vulnerabilità...\n");

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        if (strstr(response, "Location: /main.htm") != NULL ||
            strstr(response, "Welcome, admin") != NULL ||
            strstr(response, "Login successful") != NULL) {
            printf("[+] VULNERABILE: Le credenziali predefinite (admin:admin) potrebbero funzionare!\n");
            return 1;
        }
    }

    if (strstr(response, "Invalid credentials") != NULL ||
        strstr(response, "Login failed") != NULL ||
        strstr(response, "authentication failed") != NULL) {
        printf("[-] Credenziali predefinite (admin:admin) non riuscite.\n");
        return 0;
    }

    printf("[-] Non è stato possibile determinare in modo conclusivo il successo/fallimento del login.\n");
    return -1;
}

char* createHttpSocket(const char *host, int port, const char *request) {
    printf("[*] Connessione a %s:%d...\n", host, port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "[-] getaddrinfo fallito per %s: %s\n", host, gai_strerror(status));
        return NULL;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("[-] Creazione socket fallita");
        freeaddrinfo(res);
        return NULL;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("[-] Connessione fallita");
        close(sock);
        freeaddrinfo(res);
        return NULL;
    }
    printf("[+] Connessione stabilita.\n");
    printf("[+] Invio richiesta...\n");

    int sent = send(sock, request, strlen(request), 0);
    if (sent == -1) {
        perror("[-] Invio fallito");
        close(sock);
        freeaddrinfo(res);
        return NULL;
    }

    char* response_buffer = malloc(BUFFER_SIZE);
    if (response_buffer == NULL) {
        perror("[-] Malloc fallita per il buffer di risposta");
        close(sock);
        freeaddrinfo(res);
        return NULL;
    }
    memset(response_buffer, 0, BUFFER_SIZE);

    int received_bytes = 0;
    int total_received = 0;
    while ((received_bytes = recv(sock, response_buffer + total_received, BUFFER_SIZE - 1 - total_received, 0)) > 0) {
        total_received += received_bytes;
        if (total_received >= BUFFER_SIZE - 1) {
            printf("[-] Attenzione: Buffer di risposta pieno, la risposta potrebbe essere stata troncata.\n");
            break;
        }
    }

    if (total_received > 0) {
        response_buffer[total_received] = '\0';
        printf("[+] Risposta ricevuta (primi %d bytes):\n%s\n", total_received, response_buffer);
    } else if (total_received == 0) {
        printf("[-] Nessuna risposta ricevuta (connessione chiusa dal peer).\n");
        free(response_buffer);
        response_buffer = NULL;
    } else {
        perror("[-] Errore nella ricezione della risposta");
        free(response_buffer);
        response_buffer = NULL;
    }

    close(sock);
    freeaddrinfo(res);
    return response_buffer;
}

void scan_target(const char *host, int port) {
    const char *username = "admin";
    const char *password = "admin";

    char post_data_format[] = "{\"topicurl\":\"setting/setUserLogin\",\"username\":\"%s\",\"userpass\":\"%s\",\"submit-url\":\"/login.htm\"}";
    char post_data[256];
    snprintf(post_data, sizeof(post_data), post_data_format, username, password);

    int content_length = strlen(post_data);

    char http_request[BUFFER_SIZE];
    snprintf(http_request, sizeof(http_request),
        "POST /boafrm/formLogin HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Length: %d\r\n"
        "X-Requested-With: XMLHttpRequest\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36\r\n"
        "Origin: http://%s:%d\r\n"
        "Referer: http://%s:%d/login.htm\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        host, port, content_length, host, port, host, port, post_data);

    printf("\n--- Test su %s:%d ---\n", host, port);
    printf("[*] Richiesta HTTP costruita:\n%s\n", http_request);

    char* response = createHttpSocket(host, port, http_request);

    if (response != NULL) {
        if (checkVulnerability(response) == 1) {
            printf("[+] Il target %s:%d è potenzialmente vulnerabile alle credenziali predefinite (admin:admin)!\n", host, port);
        } else {
            printf("[-] Il target %s:%d non sembra vulnerabile con admin:admin.\n", host, port);
        }
        free(response);
    } else {
        printf("[-] Impossibile ottenere una risposta da %s:%d.\n", host, port);
    }
    printf("--- Fine test su %s:%d ---\n", host, port);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Utilizzo: %s <file_lista.txt>\n", argv[0]);
        printf("Il file_lista.txt deve contenere host:porta o solo host per riga.\n");
        printf("Esempio:\n");
        printf("  192.168.1.1:8080\n");
        printf("  esempio.com\n");
        printf("  10.0.0.5:80\n");
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("[-] Errore nell'apertura del file");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = 0;

        char host[MAX_LINE_LENGTH];
        int port = 80;

        char *colon_pos = strchr(line, ':');
        if (colon_pos != NULL) {
            strncpy(host, line, colon_pos - line);
            host[colon_pos - line] = '\0';

            port = atoi(colon_pos + 1);
            if (port == 0) {
                printf("[-] Porta non valida specificata in riga: %s. Imposto a porta 80.\n", line);
                port = 80;
            }
        } else {
            strncpy(host, line, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        }

        if (strlen(host) == 0) {
            printf("[-] Riga vuota o non valida nel file: %s. Saltata.\n", line);
            continue;
        }

        if (port < 1 || port > 65535) {
            printf("[-] Numero di porta non valido per %s: %d. Saltato.\n", host, port);
            continue;
        }

        scan_target(host, port);
    }

    fclose(file);
    return 0;
}
