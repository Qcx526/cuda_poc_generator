/* Record where a child process faulted, without a debugger.
 *
 * Loaded with LD_PRELOAD, this installs handlers for the fatal signals and, on
 * the way down, writes the faulting instruction pointer, the faulting address
 * and the module it belongs to. The handler then restores the default
 * disposition and re-raises, so the process still dies with the same signal and
 * the caller still sees the same exit status.
 *
 * The point is the offset, not the address: two inputs that crash the same
 * function at the same instruction are the same bug, and a fingerprint has to
 * say so before anything can be called a new finding.
 *
 *   CRASHCAP_OUT=/tmp/x LD_PRELOAD=./crashcap.so nvdisasm input.cubin
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

static void write_line(const char *path, const char *line) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }
    size_t len = strlen(line);
    ssize_t ignored = write(fd, line, len);
    (void)ignored;
    close(fd);
}

static void handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    unsigned long pc = 0;
#if defined(__x86_64__)
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    pc = (unsigned long)uc->uc_mcontext.pc;
#endif

    char module[256] = "?";
    unsigned long base = 0;
    Dl_info dl;
    if (pc && dladdr((void *)pc, &dl) && dl.dli_fname) {
        const char *slash = strrchr(dl.dli_fname, '/');
        snprintf(module, sizeof(module), "%s", slash ? slash + 1 : dl.dli_fname);
        base = (unsigned long)dl.dli_fbase;
    }

    char line[640];
    snprintf(line, sizeof(line),
             "sig=%d pc=0x%lx base=0x%lx off=0x%lx addr=0x%lx module=%s\n",
             sig, pc, base, base ? pc - base : 0,
             (unsigned long)(info ? info->si_addr : 0), module);

    const char *out = getenv("CRASHCAP_OUT");
    if (out) {
        write_line(out, line);
    }

    signal(sig, SIG_DFL);
    raise(sig);
}

static void install(int sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

__attribute__((constructor)) static void crashcap_init(void) {
    install(SIGSEGV);
    install(SIGBUS);
    install(SIGILL);
    install(SIGFPE);
    install(SIGABRT);
}
