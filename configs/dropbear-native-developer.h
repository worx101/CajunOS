#ifndef CAJUNOS_DROPBEAR_LOCALOPTIONS_H
#define CAJUNOS_DROPBEAR_LOCALOPTIONS_H

/* Stage 9B is public-key-only.  Password and PAM code are not compiled. */
#define DROPBEAR_SVR_PUBKEY_AUTH 1
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_PAM_AUTH 0

/* The seed needs an interactive shell, not forwarding or agent features. */
#define DROPBEAR_SVR_LOCALTCPFWD 0
#define DROPBEAR_SVR_REMOTETCPFWD 0
#define DROPBEAR_SVR_LOCALSTREAMFWD 0
#define DROPBEAR_SVR_REMOTESTREAMFWD 0
#define DROPBEAR_SVR_AGENTFWD 0
#define DROPBEAR_X11FWD 0
#define DROPBEAR_SFTPSERVER 0
#define DROPBEAR_SVR_PUBKEY_OPTIONS 0
#define INETD_MODE 0
#define NON_INETD_MODE 1

/* Keep the server and key generator only; there is no client in the image. */
#define DROPBEAR_CLIENT 0
#define DROPBEAR_SERVER 1
#define DROPBEAR_PIDFILE "/run/dropbear.pid"

#endif
