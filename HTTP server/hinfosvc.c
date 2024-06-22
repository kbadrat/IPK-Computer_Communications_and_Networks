#include "hinfosvc.h"

int args_handler(int argc, char *argv[])
{
    if (argc != 2)
        {
            fprintf(stderr, "You must specify the port number as the first argument. Only one argument is expected.\n");
            exit(EXIT_FAILURE);
        }
    return atoi(argv[1]);
}

int server_go(int port, int listener)
{
    // Creating socket.
    if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        fprintf(stderr, "Error in socket");
        exit(EXIT_FAILURE);
    }

    // Setting socket.
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    //Allow to reuse the port even if the process crash or been killed.
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int)) < 0)
    {
        fprintf(stderr,"Error in set socket opt\n");
        exit(EXIT_FAILURE);
    }

    //Binding an address to the socket
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        fprintf(stderr,"Error in bind\n"); 
        exit(EXIT_FAILURE);
    }

    //Prepared to accept the connections. Connected user limiter.
    if (listen(listener, NUMBER_OF_CONNECTIONS) < 0)
    {
        fprintf(stderr,"Error in listen\n");
        exit(EXIT_FAILURE);
    }

    return listener;
}

void requests_handler(int listener)
{
    int new_socket;

    //Until CTRL+C
    while(1)
    {
        //Take the first connection request in the queue. 
        if ((new_socket = accept(listener, NULL, NULL)) < 0)
        {
            fprintf(stderr, "Error in accept\n");
            exit(EXIT_FAILURE);
        }

        //Saves the request.
        char buffer[REQUEST_LENGTH] = {0};
        read(new_socket , buffer, REQUEST_LENGTH);

        //Processes the request.
        if (strncmp(buffer, REQUEST_CPU_NAME, strlen(REQUEST_CPU_NAME)) == 0)
            about_cpu(new_socket);
        else if (strncmp(buffer, REQUEST_HOSTNAME, strlen(REQUEST_HOSTNAME)) == 0)
            about_hostname(new_socket);
        else if (strncmp(buffer, REQUEST_LOAD, strlen(REQUEST_LOAD)) == 0)
            about_cpu_load(new_socket);
        else 
            write(new_socket, BAD_REQUEST, strlen(BAD_REQUEST));

        close(new_socket);
    }
}

void about_cpu(int new_socket)
{
    char cpu_name[RESPONSE_LENGTH];

    //Preparing a response.
    FILE *file = popen("lscpu | grep 'Model name' | cut -f 2 -d \":\" | awk '{$1=$1}1'","r");
    fgets(cpu_name, RESPONSE_LENGTH, file);
    pclose(file);

    char *result = concat(HTTP_HEADER, cpu_name);

    //Sends a response.
    write(new_socket, result, strlen(result));
    
    free(result);
}

void about_hostname(int new_socket)
{
    char hostname[RESPONSE_LENGTH];

    //Preparing a response.
    FILE *file = popen("cat /proc/sys/kernel/hostname","r");
    fgets(hostname, RESPONSE_LENGTH, file);
    pclose(file);

    char *result = concat(HTTP_HEADER, hostname);

    //Sends a response.
    write(new_socket, result, strlen(result));

    free(result);
}

void about_cpu_load(int new_socket)
{
    char cpu_top[RESPONSE_LENGTH];

    //Preparing a response.
    FILE *file = popen("cat /proc/stat","r");
    fgets(cpu_top, RESPONSE_LENGTH, file);
    pclose(file);
    
    //Variables to count.
    int prevuser, prevnice, prevsystem, previdle, previowait, previrq, prevsoftirq, prevsteal;
    int user, nice, system, idle, iowait, irq, softirq, steal;
    int PrevIdle, Idle, PrevNonIdle, NonIdle, PrevTotal, Total, totald, idled, cpu_load;

    strtok(cpu_top, " ");
    sscanf(strtok(NULL, " "), "%d", &user);
    sscanf(strtok(NULL, " "), "%d", &nice);
    sscanf(strtok(NULL, " "), "%d", &system);
    sscanf(strtok(NULL, " "), "%d", &idle);
    sscanf(strtok(NULL, " "), "%d", &iowait);
    sscanf(strtok(NULL, " "), "%d", &irq);
    sscanf(strtok(NULL, " "), "%d", &softirq);
    sscanf(strtok(NULL, " "), "%d", &steal);

    //Sleep the present executable for 1 sec. 
    sleep(SLEEP_TIME);

    FILE *file2 = popen("cat /proc/stat","r");
    fgets(cpu_top, RESPONSE_LENGTH, file2);
    pclose(file2);   

    strtok(cpu_top, " ");
    sscanf(strtok(NULL, " "), "%d", &prevuser);
    sscanf(strtok(NULL, " "), "%d", &prevnice);
    sscanf(strtok(NULL, " "), "%d", &prevsystem);
    sscanf(strtok(NULL, " "), "%d", &previdle);
    sscanf(strtok(NULL, " "), "%d", &previowait);
    sscanf(strtok(NULL, " "), "%d", &previrq);
    sscanf(strtok(NULL, " "), "%d", &prevsoftirq);
    sscanf(strtok(NULL, " "), "%d", &prevsteal);

    //Counting up.
    PrevIdle = previdle + previowait;
    Idle = idle + iowait;

    PrevNonIdle = prevuser + prevnice + prevsystem + previrq + prevsoftirq + prevsteal;
    NonIdle = user + nice + system + irq + softirq + steal;

    PrevTotal = PrevIdle + PrevNonIdle;
    Total = Idle + NonIdle;

    totald = Total - PrevTotal;
    idled = Idle - PrevIdle;

    cpu_load = 100 * (totald - idled)/totald;

    //Variable for the char result.
    char cpu_load_char[4];

    //Int to Char.
    sprintf(cpu_load_char, "%d", cpu_load);

    //Preparing HTTP response.
    char *result = concat(cpu_load_char, "%\n");
    result = concat(HTTP_HEADER, result);

    //Sends a response.
    write(new_socket, result, strlen(result));

    free(result);
}

char* concat(char *s1, char *s2) 
{
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);                      

    char *result = malloc(len1 + len2 + 1);

    if (!result) {
        fprintf(stderr, "malloc() failed: insufficient memory!\n");
        return NULL;
    }

    memcpy(result, s1, len1);
    memcpy(result + len1, s2, len2 + 1);    

    return result;
}