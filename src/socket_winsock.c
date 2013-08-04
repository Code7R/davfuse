#define _ISOC99_SOURCE

#include <winsock2.h>
#include <Ws2tcpip.h>

#include <stdbool.h>

#include "logging.h"

#include "socket_winsock.h"

bool
init_socket_subsystem(void) {
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;

  int err = WSAStartup(wVersionRequested, &wsaData);
  if (err) {
    /* Tell the user that we could not find a usable */
    /* Winsock DLL.                                  */
    log_error("Couldn't initialize WSAStartup: %d", err);
    return false;
  }

  if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
    /* we didn't get the version we requested */
    WSACleanup();
    return false;
  }

  return true;
}

bool
set_socket_non_blocking(fd_t sock) {
  u_long argp = 1;
  int ret_ioctl = ioctlsocket(sock, FIONBIO, &argp);
  return !ret_ioctl;
}

bool ignore_sigpipe() {
  return true;
}
