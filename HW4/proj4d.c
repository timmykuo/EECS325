/*Timothy Kuo
*tyk3
*EECS 325
*Created 4/20/17
*This is the server program that will allow multiple clients to connect
*and manipulate the strings that the client sends according to the command
*that the client requests.
*/
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/in.h>

#define REQUIRED_ARGC 2
#define PORT_POS 1
#define ERROR 1
#define QLEN 1
#define PROTOCOL "tcp"
#define ERROR_MSG " Sorry, operation does not exist. Please send another"
#define BUFLEN 1024
#define EXIT "exit"

void delete(char str[], char c) {
  char *pointer = str, *string = str;
  while (*pointer) {
    *string = *pointer++;
    string += (*string != c);
  }
  *string = '\0';
}

void reverse(char s[])
{
    int length = strlen(s);
    int temp, beg, end;

    for (beg = 0, end = length - 1; beg < end; beg++, end--)
    {
        temp = s[beg];
        s[beg] = s[end];
        s[end] = temp;
    }
}

int countChars(char s[], char c) {
  int counter = 0;
  for (int i = 0; i < strlen(s); i++) {
    if(s[i] == c) {
      counter++;
    }
  }
  return counter;
}

int usage (char *progname)
{
    fprintf (stderr,"usage: %s port\n", progname);
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
    struct sockaddr addr;
    struct protoent *protoinfo;
    unsigned int addrlen;
    int sd, sd2, nBytes, stringBytes;
    char buffer [BUFLEN];
    char string [BUFLEN];
    if (argc != REQUIRED_ARGC)
        usage (argv [0]);

    /* determine protocol */
    if ((protoinfo = getprotobyname (PROTOCOL)) == NULL)
        errexit ("cannot find protocol information for %s", PROTOCOL);

    /* setup endpoint info */
    memset ((char *)&sin,0x0,sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons (atoi (argv [PORT_POS]));

    /* allocate a socket */
    /*   would be SOCK_DGRAM for UDP */
    sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
    if (sd < 0)
        errexit("cannot create socket", NULL);

    /* bind the socket */
    if (bind (sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit ("cannot bind to port %s", argv [PORT_POS]);

    /* listen for incoming connections */
    if (listen (sd, QLEN) < 0)
        errexit ("cannot listen on port %s\n", argv [PORT_POS]);

    while(1) {
      /* accept a connection */
      sd2 = accept (sd,&addr,&addrlen);
      if (sd2 < 0)
          errexit ("error accepting connection", NULL);

      if(!fork()) {
        nBytes = 1;

        while(nBytes != 0) {
          stringBytes = 1;
          //receive the string
          if ((stringBytes = recv (sd2, string, 1024, 0)) < 0)
            perror("error receving string");
          printf("String received from client:%s\n", string);

          if ((nBytes = recv(sd2, buffer, 1024, 0)) < 0)
            perror("error receiving command");
          printf("Command received from client:%s\n", buffer);

          if(buffer[0] != '-' || strlen(buffer) > 4) {
            if(send (sd2, " Sorry, operation does not exist. Please send another", strlen (ERROR_MSG), 0) < 0)
              perror("send error message failed");
          }
          else {
            //reverse
            if(buffer[1] == 'r') {
              reverse(string);
            }
            //to lowercase
            else if(buffer[1] == 'l' && buffer[2] == 'c') {
                for (int i = 0; i < stringBytes-1; i++) {
                  string[i] = tolower(string[i]);
                }
            }
            //to uppercase
            else if(buffer[1] == 'u' && buffer[2] == 'c') {
              for (int i = 0; i < stringBytes-1; i++) {
                string[i] = toupper(string[i]);
              }
            }
            //remove 'x'
            else if(buffer[1] == 'm') {
              delete(string, buffer[2]);
            }
            //count number of 'x'
            else if(buffer[1] == 'n') {
              int counter = countChars(string, buffer[2]);
              memset(string,0,strlen(string));
              sprintf(string, "%d", counter);
            }
            else {
              if (send (sd2, "Sorry, unrecognizable command", sizeof("Sorry, unrecognizable command"), 0) < 0)
                perror("send manipulated string failed");
            }

            if (send (sd2, string, stringBytes, 0) < 0)
              perror("send manipulated string failed");
          }

        }
        close(sd2);
        exit(0);
      }
      else {
        close(sd2);
      }
    }

    /* close connections and exit */
    close (sd);
    close (sd2);
    exit (0);
}
