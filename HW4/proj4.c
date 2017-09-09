/*Timothy Kuo
*tyk3
*EECS 325
*Created 4/20/17
*This is the client side of the program that can connect to a server
*and request strings to be manipulated
*/
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ERROR 1
#define REQUIRED_ARGC 3
#define HOST_POS 1
#define PORT_POS 2
#define PROTOCOL "tcp"
#define BUFLEN 1024

int usage (char *progname)
{
    fprintf (stderr,"usage: %s host port\n", progname);
    exit (ERROR);
}

int errexit (char *format, char *arg)
{
    fprintf (stderr,format,arg);
    fprintf (stderr,"\n");
    exit (ERROR);
}

int main (int argc, char *argv [])
{
    struct sockaddr_in sin;
    struct hostent *hinfo;
    struct protoent *protoinfo;
    char buffer [BUFLEN];
    int sd, nBytes;

    if (argc != REQUIRED_ARGC)
        usage (argv [0]);

    /* lookup the hostname */
    hinfo = gethostbyname (argv [HOST_POS]);
    if (hinfo == NULL)
        errexit ("cannot find name: %s", argv [HOST_POS]);

    /* set endpoint information */
    memset ((char *)&sin, 0x0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (atoi (argv [PORT_POS]));
    memcpy ((char *)&sin.sin_addr,hinfo->h_addr,hinfo->h_length);

    if ((protoinfo = getprotobyname (PROTOCOL)) == NULL)
        errexit ("cannot find protocol information for %s", PROTOCOL);

    /* allocate a socket */
    /*   would be SOCK_DGRAM for UDP */
    sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
    if (sd < 0)
        errexit("cannot create socket",NULL);

    /* connect the socket */
    if (connect (sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit ("cannot connect", NULL);

    /* snarf whatever server provides and print it */
    while(1) {
      printf("Hello, please enter a string to manipulate or type \"exit\" to exit:\n");
      fgets(buffer, 1024, stdin);

      //if user wants to exit
      if(strncmp(buffer, "exit", 4) == 0)
        break;

      nBytes = strlen(buffer) + 1;
      //send string
      if (send (sd, buffer, nBytes, 0) < 0)
        perror("send string failed");

      //send operation
      printf("String received. Please enter a manipulation operation:\n");
      fgets(buffer, 1024, stdin);
      nBytes = strlen(buffer) + 1;
      if (send (sd, buffer, nBytes, 0) < 0)
        perror("send operation failed");

      //if user wants to exit
      if(strncmp(buffer, "exit", 4) == 0)
        break;

      //receive manipulated string
      if (recv (sd, buffer, 1024, 0) < 0)
        perror("recv failed");

      printf("Result from server: %s\n\n", buffer);
    }

    /* close & exit */
    close (sd);
    exit (0);
}
