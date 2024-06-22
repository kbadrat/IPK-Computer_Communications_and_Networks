// Header file for hinfosvc.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#ifndef HINFOSVC_H
#define HINFOSVC_H    

#define NUMBER_OF_CONNECTIONS 10 
#define REQUEST_LENGTH  512 //The maximum length of a request.
#define RESPONSE_LENGTH 1024 //The maximum length of a response.
#define SLEEP_TIME 1        
#define HTTP_HEADER      "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
#define BAD_REQUEST      "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n400 Bad Request\n"
#define REQUEST_CPU_NAME "GET /cpu-name HTTP/1.1"
#define REQUEST_HOSTNAME "GET /hostname HTTP/1.1"
#define REQUEST_LOAD     "GET /load HTTP/1.1"

int args_handler(int argc, char *argv[]); //Argument processing.
int server_go(int port, int listener);    //Creates and configures a server.
void requests_handler(int listener);      //Requests processing.
void about_hostname(int new_socket);      //Sends a response about the domain name.
void about_cpu(int new_socket);           //Sends a response about the processor model. 
void about_cpu_load(int new_socket);      //Sends a response about the processor load
char* concat(char *s1, char *s2);         //String concatenation.

#endif /*HINFOSVC_H*/