#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include "handlesig.h"

volatile sig_atomic_t reload_certificate = 0;
pid_t db_proc = -1;
pid_t ssl_proc = -1;
pid_t http_proc = -1;
static pid_t server_parent = -1;
static int reload_fd = -1;

static int configure_sighup(int reload_enabled)
{
	sigset_t mask;
	struct sigaction act = {0};

	if(reload_fd >= 0){
		close(reload_fd);
		reload_fd = -1;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);

	if (reload_enabled) {
		act.sa_handler = SIG_DFL;
		sigemptyset(&act.sa_mask);
		
		if(sigaction(SIGHUP, &act, NULL) == -1) return -1;

		if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) return -1;

		reload_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
 
		return reload_fd == -1 ? -1 : 0;
	}

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGHUP, &act, NULL) == -1) return -1;
	
	return sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

int certificate_reload_fd(void)
{
	return reload_fd;
}

int consume_certificate_reload(void)
{
	struct signalfd_siginfo info;
	int received = 0;

	for (;;) {

		ssize_t n = read(reload_fd, &info, sizeof(info));
		
		if (n == (ssize_t)sizeof(info)) {
			if(info.ssi_signo == SIGHUP){
				received = 1;
			}
			continue;
		}
		
		if (n == -1 && errno == EINTR) continue;


		if (n == -1 
			&& (errno == EAGAIN || errno == EWOULDBLOCK)) return received;

		return -1;
	}
}
static void terminate_process(int signo)
{
    /* No stdio, allocator, OpenSSL, epoll bookkeeping, or stale PID lists here.
     * The kernel closes descriptors and terminates our attached children. */
    _exit(128 + signo);
}

static void request_certificate_reload(int signo)
{
    (void)signo;
    reload_certificate = 1;
}

static int install_handlers(int reload_enabled)
{
    struct sigaction act = {0};
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGINT);
    sigaddset(&act.sa_mask, SIGTERM);

    act.sa_handler = terminate_process;
    if(sigaction(SIGINT, &act, NULL) || sigaction(SIGTERM, &act, NULL)) return -1;

    /* A disconnected peer is an I/O failure, not a server shutdown request. */
    act.sa_handler = SIG_IGN;
    if(sigaction(SIGPIPE, &act, NULL)) return -1;

	if(configure_sighup(reload_enabled) == -1) return -1;

    /* 
		man pages (man 2 sigaction) says that:
				POSIX.1-1990  disallowed  setting the action for SIGCHLD to SIG_IGN.  
				POSIX.1-2001 and later allow this possibility, so that ignoring SIGCHLD can be used to prevent the creation of zombies (see wait(2)).
			  	Nevertheless, the historical BSD and System V behaviors for ignoring SIGCHLD differ, so that
       			the only completely portable method of ensuring that terminated children do not become zombies 
				is to catch the SIGCHLD signal and perform a  wait(2) or similar.

		this make the children waitable;
	*/
    act.sa_handler = SIG_DFL;
    if(sigaction(SIGCHLD, &act, NULL)) return -1;
    return 0;
}

int handle_sig_main_process(void) { return install_handlers(1); }
int handle_sig_http_process(void) { return install_handlers(0); }
int handle_sig_ssl_process(void) { return install_handlers(1); }
int handle_sig_db_process(void) { return install_handlers(0); }

pid_t server_fork(void)
{
    pid_t parent = getpid();
    pid_t child = fork();
    if(child == 0){
        server_parent = parent;
        /* Linux clears this setting at every fork: arm it in EVERY child.
         * SIGKILL also covers a blocked worker or a parent killed with -9. */
        if(prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1)
            _exit(125);
        /* Parent may have exited between fork and prctl. Never attach to init. */
        if(getppid() != parent) _exit(125);
    }
    return child;
}

int signal_server_process(pid_t pid, int signo)
{
    /* Reject init, process groups, and the broadcast sentinel, even on error paths. */
    if(pid <= 1){ errno = EINVAL; return -1; }
    return kill(pid, signo);
}

int signal_server_parent(int signo)
{
    if(server_parent <= 1 || getppid() != server_parent){ errno = ESRCH; return -1; }
    return signal_server_process(server_parent, signo);
}

int server_child_running(pid_t pid)
{
    if(pid <= 1) return 0;
    int status;
    pid_t result;
    do { 
		result = waitpid(pid, &status, WNOHANG); 
	} while(result < 0 && errno == EINTR);

    return result == 0;
}

