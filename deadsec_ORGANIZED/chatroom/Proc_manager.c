#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <semaphore.h>
#include <unistd.h>

/*
 * make a client and a server function that communicate using shared memory.
 * for every 1 server there can be three clients, then it is considered at capacity
 * clients may issue messages to the server, but not to other clients(in theory)
 * server may issue messages to individual clients or to all clients
 
 Loader:
    allows you to choose whether to set up a server or client
    forks off and spawns that decided process
    THIS PROGRAM

 Server: 
    is the process that will setup and destroy a segment of shared memory, as well as a semaphore to go along with it.
    The semaphore should control whether or not the message section can be written too
    the server will parse the message and put it in the messages section.
    the messages section can be read by all the clients, allowing them to see all of the previous messages
    the bug should be in the server, and should be a race condition between to clients writting to the same area.
    So maybe, I don't use semaphores, and instead use a broken form of my own race condition prevention.
    Or, I could search for common bugs in semaphores.
    The messages sent could be [size][message]. the program creates a buffer of size size to read the text, and then copies it to the stack using strcpy, or something. This could give the proper overflow.
    should automatically close after a set amount of time, unlinking the memory. this is too prevent memory overflow

    Conditions for bug:
        pointer the the same chunk of memory in the shared memory space. 
        one starts, the reads, break in the reading, another starts and writes a new size, first finishes writing, then 2nd writes.
        should be deterministic because it requires writing.

 Client:
    continously polls for new messages, cause the display to update each time. probably forked.
    I could actually write the messages to a file from the server, so that there is no size limit
*/

//void* shrmem = NULL;
//int shrmem_id = NULL;

void error(char* message){
    printf("[!] ERROR: %s\n", message);
    return;
}

void info(char* message){
    printf("[*] INFO: %s\n", message);
    return;
}

void setup(){
    setvbuf(stdin,(char*)0x0,2,0);
    setvbuf(stdout,(char*)0x0,2,0);
    setvbuf(stderr,(char*)0x0,2,0);
    return;
}

//void setup_IPC(){
//    shrmem_id = shmget(IPC_PRIVATE, 0x1000, 0666);
//    if(shrmem_id == -1){
//        error("Couldn't open Shared mem");
//        exit(-1);
//    }
//    shrmem = shmat(shrmem_id, (void*)0, 0);
//    if((int)shrmem == -1){
//        error("Could not connect to shared memory");
//        exit(-1);
//    }
//    return;
//}

int main(int argc, char* argv[]){
    char answer[40];
    char* ret;
    setup();
    puts("Choose whether to spawn a server or client process, not part of the challenge");
    int pid = fork();
    read(0, answer, 20);
    ret = strstr(answer, "server");
    if(strcmp(answer, "server")==0){
        puts("Launching server...");
        system("./server");
    }
    else{
        puts("Launching client");
        system("./client");
    }
    exit(0); 
}
