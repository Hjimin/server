#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
int main(int argc,char **argv)
{
        int sockfd,n;
        char sendbuff[1500];
        char recvbuff[1500];
	char* sendline;
        char* recvline;
	ssize_t recv_size;
	ssize_t write_size;
	int size;
        struct sockaddr_in servaddr;
        sockfd=socket(AF_INET,SOCK_STREAM,0);
        bzero(&servaddr,sizeof(servaddr));
     
        servaddr.sin_family=AF_INET;
        servaddr.sin_port=htons(atoi(argv[2]));
     
        printf("start\n"); 
        inet_pton(AF_INET,argv[1],&(servaddr.sin_addr));
        connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
        printf("connected\n"); 
        size = atoi(argv[3]); 
	while(1)
        {
            	bzero(sendbuff, 100);
		sendline = strcpy(sendbuff, "Hello\n");
            	bzero(recvbuff, 100);
    		write_size += write(sockfd,sendline,size);
            	recv_size += read(sockfd,recvbuff,1500);
		//printf("size %lu", size);
		//printf("size %u \n",strlen(recvline));
            	printf("%s",recvbuff);
		printf("send :%lu, recv :%lu\n",write_size,recv_size);
        }
 
}
