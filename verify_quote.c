#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

typedef struct
{
    int size;
    uint8_t *data;
} Data;

EVP_PKEY *load_pubkey(const char *file)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;

    FILE *fp = NULL;
    fp = fopen(file, "r");
    uint8_t *buffer = malloc(1024);
    int size = fread(buffer, 1, 1024, fp);
    fclose(fp);

    key = BIO_new_mem_buf(buffer, size);

    pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);

    BIO_free(key);
    free(buffer);

    return pkey;
}

int read_data(const char *file, Data *data) {
    int res = 0;
    FILE *fp = NULL;

    fp = fopen(file, "rb");
    uint8_t *buffer = malloc(1024);
    int size = fread(buffer, 1, 1024, fp);
    fclose(fp);

    data->size = size;
    data->data = buffer;

    return res;
}

int verify(char *data, int datalen, char *sig, int siglen) {
    int res = EXIT_SUCCESS;

    EVP_PKEY *pubkey = NULL;

    pubkey = load_pubkey("key.pem");

    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = EVP_sha256();

    mdctx = EVP_MD_CTX_create();
    res = EVP_VerifyInit_ex(mdctx, md, NULL);
    if (res == 0) {
        printf("Failed to EVP_VerifyInit_ex().\n");
    }

    Data quote = {0};
    //read_data("quote.data", &quote);
    quote.size = datalen;
    quote.data = data;

    EVP_VerifyUpdate(mdctx, quote.data, quote.size);
    if (res == 0) {
        printf("Failed to EVP_VerifyUpdate().\n");
    }

    Data signature = {0};
    //read_data("quote.sig", &signature);
    signature.size = siglen;
    signature.data = sig;
    int verify = EVP_VerifyFinal(mdctx, signature.data, signature.size, pubkey);

    if (verify == 1) {
        printf("Verified OK\n");
    } else {
        printf("Verified failed...\n");
    }

    //free(quote.data);
    //free(signature.data);

    return verify;
}

int main(int argc , char *argv[]) {
    int server_sock , c;
    int newfd;
    struct sockaddr_in server, client;
    char buf[2000];
    fd_set master; // master file descriptor 清單
    fd_set read_fds; // 給 select() 用的暫時 file descriptor 清單
    int fdmax; // 最大的 file descriptor 數目
    int i;

    FD_ZERO(&master); // 清除 master 與 temp sets
    FD_ZERO(&read_fds);

    //Create socket
    server_sock = socket(AF_INET , SOCK_STREAM , 0);
    if (server_sock == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8890 );

    //Bind
    if( bind(server_sock,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(server_sock , 3);

    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    FD_SET(server_sock, &master);
    fdmax = server_sock;

    //accept connection from an incoming client
    //main loop
    for(;;) {
        read_fds = master; // 複製 master

        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(4);
        }

        // multiplexer
        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) { // event triggered
                if (i == server_sock) {
                    // handle new connections
                    newfd = accept(server_sock, (struct sockaddr *)&client, (socklen_t*)&c);
                    if (newfd < 0) {
                        perror("accept failed");
                        return 1;
                    }
                    puts("Connection accepted");
                    FD_SET(newfd, &master); // 新增到 master set
                    if (newfd > fdmax) { // 持續追蹤最大的 fd
                        fdmax = newfd;
                    }
                    printf("selectserver: new connection\n");
                } else {
                    // read
                    int nbytes = 0;
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) > 0) {
                        //recv data
                        //char *payload;
                        printf("len=%d\n", nbytes);
                        char data[1024];
                        char sig[1024];
                        char *p;
                        p = buf;
                        while(p < buf+nbytes) {
                            p = memchr (p, '\r', buf+nbytes-p);
                            if(p == NULL) {
                                break;
                            }
                            if((p+1 == '\n') && (p+2 == '\r') && (p+3 == \n)) {
                                break;
                            }
                        }
                        unsigned int data_len = p - buf;
                        unsigned int sig_len = nbytes - data_len - 4;

                        memcpy(data, buf, data_len);
                        memcpy(sig, p+4, sig_len);

                        int result = verify(data, data_len, sig, sig_len);
                        

                        //response
                        char body[2048];
                        memset(body, sizeof(body), 0);

                        if(result == 1) {
                            strcpy(body, "1");
                        } else {
                            strcpy(body, "0");
                        }

                        //sprintf(body, "{\"result\":\"%s\"}", result);

                        //sprintf(header, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", strlen(body));

                        if (send(i, body, strlen(body), 0) == -1) {
                            perror("send error");
                        }
                        close(i);
                        FD_CLR(i, &master); // 從 master set 中移除
                    } else {
                        // got error or connection closed by client
                        if (nbytes == 0) {
                            // 關閉連線
                            printf("selectserver: socket %d hung up\n", i);
                        } else {
                            perror("recv");
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // 從 master set 中移除
                    }
                    
                }
            }
        }
    }
    return 0;
}

