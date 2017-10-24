#include <ctype.h>
#include <stdio.h>    
#include <stdlib.h>    
#include <errno.h>    
#include <string.h>        
#include <netinet/in.h>   
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>    
#include <sys/wait.h>    
#include <unistd.h>    
#include <arpa/inet.h>    
#include <openssl/ssl.h>    
#include <openssl/err.h>    


char dest_host[20];
int dest_port;
#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define ISspace(x) isspace((int)(x))    
#define MAXBUF 1024    
int GetLine(SSL*, char*, int);
void error_die(const char*);
int InitSocket(u_short*);
void Return501(SSL*);
void Return400(SSL*);
void Return404(SSL*);
void cat(SSL*, FILE*);
void accept_request(SSL *);
int Strcmp(const char *, const char *);
int char2num(const char *);
int Transmit(SSL*, int);
int SendHeaders(int , int );



int char2num(const char *buf)
{
    int i = 0, sum = 0;
    while(buf[i] != '\0' && buf[i] != '\n'){
        sum *= 10;
        sum += buf[i]-'0';
        i++;
    }
    return sum;
}


int Strcmp(const char * buf, const char * arr)
{
    int i = 0;
    for(i = 0; i < 15; i++){
        if(buf[i] != arr[i]){
            return 0;
        }
    }
    return 1;
}


void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

int GetLine(SSL* ssl, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;
    while ((i < size - 1) && (c != '\n'))
    {
		n = SSL_read(ssl, &c, 1);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
				n = SSL_read(ssl, &c, 1);
                /* DEBUG printf("%02X\n", c); */
				if(c != '\n')
					printf("error: GetLine end is't \n");
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';
printf("%s\n",buf);
    return(i);
}


void accept_request(SSL *client)
{
	printf("accept_request start=========================\n");
	int clientSocket = 0;
	char buf[1024];
	size_t numchars;
	char method[255];
	char path[512];
	char url[255];
	size_t i, j;
	struct stat st;
	int cgi = 0;
    int contentLength = 0;
	
	char *query_string = NULL;
	
	numchars = GetLine(client, buf, sizeof(buf));
	i = 0; j = 0;
	while(!ISspace(buf[i]) && (i < sizeof(method) - 1))
		method[i] = buf[i],i++;
	j = i;
	method[i] = '\0';
printf("%s\n",buf);
printf("method =====> %s\n", method);
	if(strcasecmp(method, "GET") && strcasecmp(method, "POST"))
	{
		Return501(client);
		return ;
	}
	

	i = 0;
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
	url[i] = '\0';
	
	if(strcasecmp(method, "GET") == 0){
		query_string = url;
		while(( *query_string != '?') && (*query_string != '\0'))
			query_string++;
		if(*query_string == '?'){
			cgi = 1;
			*query_string++ = '\0';
		}	
	}
	
	sprintf(path, "htdocs%s", url);
	if(path[strlen(path) - 1] == '/')
		strcat(path, "index.html");
    /*  DEBUG printf("path: %s\n",path);   */
	if(stat(path, &st) == -1){
		while((numchars > 0) && strcmp("\n", buf))
			numchars = GetLine(client, buf, sizeof(buf));
		Return404(client);
	}
	else
	{
    /*
		if((st.st_mode & S_IFMT) == S_IFDIR)
			strcat(path, "/index.html");
		if((st.st_mode & S_IXUSR) ||
			(st.st_mode & S_IXGRP) ||
			(st.st_mode & S_IXOTH)  )
			cgi = 0;
    */

		while(1){
			int iii  = GetLine(client, buf, 1024);
    	    if(Strcmp(buf,"Content-Length:")){
        	    contentLength = char2num(buf+16);
				//printf("Contentlen:%d/n",contentLength);
			}
		//	printf("iii:%d -- %s",iii,buf);
        	if(iii == 1) break;
		}
		Transmit(client, contentLength);
	}
	
	close(clientSocket);
}



int Transmit(SSL *client ,int contentLength)
{
/* DEBUG printf("Transmit start =========\n"); */
    int fd = 0;
    struct sockaddr_in dest;
    char buf[1024];

    SSL_read(client, buf, contentLength);
    buf[contentLength] = '\0';

    fd = socket( AF_INET, SOCK_STREAM, 0 );
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    if (inet_aton(dest_host, (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror("error 222");
        exit(errno);
    }
    if (connect(fd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
            exit(errno);
    }
    SendHeaders(fd, contentLength); 
    write(fd, buf, contentLength);
    close(fd);
    return 0;    
}

int SendHeaders(int client, int contentLength)
{
    char buf[256];
    strcpy(buf, "POST /zxsm_gzh_recall HTTP/1.1\r\n");
    write(client, buf, strlen(buf));
    strcpy(buf, "Content-Type: text/xml;charset=ISO-8859-1\r\n");
    write(client, buf, strlen(buf));
    sprintf(buf, "Content-Length: %d\r\n", contentLength);
    write(client, buf, strlen(buf));
    strcpy(buf, "HOST: 172.20.11.36:16500\r\n");
    write(client, buf, strlen(buf));
    strcpy(buf, "Connection: Keep-Alive\r\n");
    write(client, buf, strlen(buf));
    strcpy(buf, "User-Agent: Apache-HttpClient/4.3.5 (java 1.5)\r\n");
    write(client, buf, strlen(buf));
    strcpy(buf, "Accept-Encoding: gzip,deflate\r\n");
    write(client, buf, strlen(buf));
    strcpy(buf, "\r\n");
    write(client, buf, strlen(buf));
    return 1;
}

void cat(SSL *ssl, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
		SSL_write(ssl, buf, strlen(buf));
        fgets(buf, sizeof(buf), resource);
    }
}

void Return404(SSL *ssl)
{
    char buf[256];
    sprintf(buf, "HTTP/1.0 404 NOT FOUNT\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "Content-type: text/html\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "<h1>404 Not Fount </h1>\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "The requested URL was not found on this server.\r\n");
    SSL_write(ssl, buf, strlen(buf));    
}

void Return400(SSL *ssl)
{
    char buf[256];
    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "Content-type: text/html\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "<P>400 error. Your browser sent a bad request, ");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    SSL_write(ssl, buf, strlen(buf));    
}


void Return501(SSL * ssl)
{
	char buf[256];
	int len;	
	
    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, SERVER_STRING);
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "Content-Type: text/html\r\n");
    SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "\r\n");
    len = SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    len = SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "</TITLE></HEAD>\r\n");
    len = SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    len = SSL_write(ssl, buf, strlen(buf));    
    sprintf(buf, "</BODY></HTML>\r\n");
    SSL_write(ssl, buf, strlen(buf));    
}


int InitSocket(u_short *port)
{	
	int httpd = 0;
	int on = 1;
	struct sockaddr_in sk_in;
	

	httpd = socket(PF_INET, SOCK_STREAM, 0);
	if(httpd == -1)
		error_die("socket");
	memset(&sk_in, 0, sizeof(sk_in));
	sk_in.sin_family = AF_INET;
	sk_in.sin_port = htons(*port);
	sk_in.sin_addr.s_addr = htonl(INADDR_ANY);
	//设置改sokcet立即释放端口，让端口可以重复使用
	if((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))<0)	{
		error_die("setsockopt failed");
	}
	if(bind(httpd, (struct sockaddr*)&sk_in, sizeof(sk_in)) < 0){
		error_die("bind");
	}
	if(*port == 0){
		socklen_t len = sizeof(sk_in);
		if(getsockname(httpd, (struct sockaddr *)&sk_in, &len) == -1)
			error_die("getsockanme");	
		*port = ntohs(sk_in.sin_port);
	}
	if(listen(httpd, 5) < 0)
		error_die("listen");
	printf("Init Socket Success\n");
	return(httpd);
}


    
int main(int argc, char **argv)    
{    
    int sockfd = -1;
	int new_fd = -1;    
    socklen_t len;    
    struct sockaddr_in their_addr;    
    u_short myport = 9999;    
    SSL_CTX *ctx;    

    if(argc < 4){
        strcpy(dest_host, "172.20.11.36");
        dest_port = 16500;
    }    
    else {
        printf("%s\n", argv[3]);
        strcpy(dest_host, argv[3]);
        dest_port = char2num(argv[4]);        
    }
    
    SSL_library_init();    
    OpenSSL_add_all_algorithms();    
    SSL_load_error_strings();    
    ctx = SSL_CTX_new(TLSv1_2_server_method());    
    if (ctx == NULL) {    
        ERR_print_errors_fp(stdout);    
        exit(1);    
    }    
    if (SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) <= 0) {    
        ERR_print_errors_fp(stdout);    
        exit(1);    
    }    
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {    
        ERR_print_errors_fp(stdout);    
        exit(1);    
    }    
    if (!SSL_CTX_check_private_key(ctx)) {    
        ERR_print_errors_fp(stdout);    
        exit(1);    
    }   
    

	sockfd = InitSocket(&myport);

       
    while (1) {    
        SSL *ssl;    
        len = sizeof(struct sockaddr);    
            
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1) {    
            perror("accept");    
            exit(errno);    
        } else    
            printf("server: got connection from %s, port %d, socket %d \n",
					inet_ntoa(their_addr.sin_addr),ntohs(their_addr.sin_port), new_fd);    
            
        ssl = SSL_new(ctx);    
        SSL_set_fd(ssl, new_fd);    
        if (SSL_accept(ssl) == -1) {    
            printf("error:accept");    
            goto finish;
        }    
		accept_request(ssl);	

    finish:    
        SSL_shutdown(ssl);    
        SSL_free(ssl);    
        close(new_fd);    
    }    
    close(sockfd);    
    SSL_CTX_free(ctx);    
    return 0;    
}   
