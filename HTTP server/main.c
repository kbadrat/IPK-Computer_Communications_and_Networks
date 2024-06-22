//Author: Vladyslav Kovalets - xkoval21

#include "hinfosvc.h"

int main(int argc, char *argv[])
{ 
    //Working with arguments. The first argument is assumed to be a port.
    int port = args_handler(argc, argv);
    
    //Create server.
    int listener = server_go(port, listener);
    
    //Requests processing.
    requests_handler(listener);
    
    return 0;
}