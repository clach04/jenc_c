/*
 * jenc - encrypt/decrypt .jenc files (V001, Markor / jpencconverter).
 *
 * Usage:
 *   jenc -e|-d IN OUT [--password PASS] [-b|--brave]
 *   Use - for IN/OUT to use stdin/stdout.
 *
 * Password sources, in order: --password, env JENC_PASSWORD, no-echo prompt.
 * Encrypt prompts twice unless -b/--brave. Decrypt fails before writing if the
 * MAC does not verify, and any partial output file is removed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "jenc.h"

#define PASS_MAX 1024
#define ENV_PASSWORD "JENC_PASSWORD"

#define ERR(...) do { fprintf(stderr, "jenc: " __VA_ARGS__); exit(1); } while (0)

/* --- binary stdio --- */

static void set_binary_stdout(void)
{
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
}

static void set_binary_stdin(void)
{
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
}

/* --- no-echo password input --- */

#ifdef _WIN32
static void set_echo(int on)
{
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(h, &mode)) {
        if (on) mode |= ENABLE_ECHO_INPUT;
        else    mode &= ~ENABLE_ECHO_INPUT;
        SetConsoleMode(h, mode);
    }
}
#else
static struct termios orig_termios;
static int termios_saved;
static void set_echo(int on)
{
    struct termios t;
    if (!on) {
        if (tcgetattr(STDIN_FILENO, &orig_termios) == 0) {
            termios_saved = 1;
            t = orig_termios;
            t.c_lflag &= ~(tcflag_t)ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &t);
        }
    } else if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
        termios_saved = 0;
    }
}
#endif

static int read_password(const char *prompt, char *buf, size_t buflen)
{
    size_t len;
    fprintf(stderr, "%s", prompt);
    set_echo(0);
    if (!fgets(buf, (int)buflen, stdin)) {
        set_echo(1);
        ERR("failed to read password\n");
    }
    set_echo(1);
    fprintf(stderr, "\n");
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return (int)len;
}

/* --- file IO --- */

static unsigned char *read_all(FILE *f, size_t *len_out)
{
    unsigned char *buf = NULL;
    size_t cap = 0, len = 0;
    for (;;) {
        size_t n;
        if (len == cap) {
            size_t newcap = cap ? cap * 2 : 4096;
            unsigned char *nb = realloc(buf, newcap);
            if (!nb) ERR("out of memory reading input\n");
            buf = nb;
            cap = newcap;
        }
        n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    if (ferror(f)) ERR("read error on input\n");
    *len_out = len;
    return buf;
}

static void write_all(FILE *f, const unsigned char *buf, size_t len, const char *what)
{
    if (len && fwrite(buf, 1, len, f) != len) ERR("write error on %s\n", what);
    if (fflush(f) != 0) ERR("flush error on %s\n", what);
}

/* --- main --- */

static void usage(void)
{
    fprintf(stderr, "Usage: jenc -e|-d infile outfile [--password PASS] [-b/--brave]\n");
    fprintf(stderr, "  -e        encrypt\n");
    fprintf(stderr, "  -d        decrypt\n");
    fprintf(stderr, "  -h/--help show this help\n");
    fprintf(stderr, "  --password PASS  supply password on command line (unsafe), else env %s, else prompt\n", ENV_PASSWORD);
    fprintf(stderr, "  -b/--brave       only prompt for password once (encrypt only)\n");
#ifdef JENC_DEBUG_SKIP_MAC
    fprintf(stderr, "  --skip-mac       DEBUG BUILD: decrypt WITHOUT MAC check (unauthenticated)\n");
#endif
    fprintf(stderr, "  Use - for infile/outfile to use stdin/stdout\n");
}

int main(int argc, char *argv[])
{
    int mode = 0; /* 0=none, 1=encrypt, 2=decrypt */
    int brave = 0;
    int skip_mac = 0;
    const char *password = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;
    char pass1[PASS_MAX], pass2[PASS_MAX];
    unsigned char *data = NULL;
    size_t data_len = 0;
    unsigned char *result = NULL;
    size_t result_len = 0;
    jenc_status st;
    FILE *fin = NULL, *fout = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--brave") == 0) {
            brave = 1;
#ifdef JENC_DEBUG_SKIP_MAC
        } else if (strcmp(argv[i], "--skip-mac") == 0) {
            skip_mac = 1;
#endif
        } else if (strcmp(argv[i], "--password") == 0) {
            if (++i >= argc) ERR("--password requires an argument\n");
            password = argv[i];
        } else if (strcmp(argv[i], "-") == 0 || argv[i][0] != '-') {
            if (!infile) infile = argv[i];
            else if (!outfile) outfile = argv[i];
            else ERR("extra argument: %s\n", argv[i]);
        } else {
            ERR("unknown option: %s\n", argv[i]);
        }
    }

    if (!mode || !infile || !outfile) {
        usage();
        return 1;
    }

    /* password: --password, env, prompt */
    if (!password) {
        const char *envpw = getenv(ENV_PASSWORD);
        if (envpw) password = envpw;
    }
    if (password) {
        if (strlen(password) >= PASS_MAX) ERR("password too long (max %d)\n", PASS_MAX - 1);
        if (password[0] == '\0') ERR("empty password\n");
    } else {
        if (read_password("password: ", pass1, PASS_MAX) == 0) ERR("empty password\n");
        if (mode == 1 && !brave) {
            read_password("confirm: ", pass2, PASS_MAX);
            if (strcmp(pass1, pass2) != 0) ERR("passwords do not match\n");
        }
        password = pass1;
    }

    /* input */
    if (strcmp(infile, "-") == 0) {
        set_binary_stdin();
        fin = stdin;
    } else {
        fin = fopen(infile, "rb");
        if (!fin) ERR("cannot open %s\n", infile);
    }
    data = read_all(fin, &data_len);
    if (fin != stdin) fclose(fin);
    if (!data) {
        data = malloc(1);
        if (!data) ERR("out of memory\n");
    }

    /* crypt, fully in memory; nothing is written until this succeeds */
    if (mode == 1) {
        st = jenc_encrypt(password, data, data_len, &result, &result_len);
    } else if (skip_mac) {
#ifdef JENC_DEBUG_SKIP_MAC
        st = jenc_decrypt_skip_mac(password, data, data_len, &result, &result_len);
#else
        ERR("--skip-mac is only available in a JENC_DEBUG_SKIP_MAC build\n");
#endif
    } else {
        st = jenc_decrypt(password, data, data_len, &result, &result_len);
    }
    if (st != JENC_OK) {
        fprintf(stderr, "jenc: %s failed: %s\n",
                mode == 1 ? "encrypt" : "decrypt", jenc_status_str(st));
        free(data);
        return 1;
    }
    free(data);

    /* output */
    if (strcmp(outfile, "-") == 0) {
        set_binary_stdout();
        write_all(stdout, result, result_len, "stdout");
    } else {
        fout = fopen(outfile, "wb");
        if (!fout) ERR("cannot open %s for writing\n", outfile);
        write_all(fout, result, result_len, outfile);
        fclose(fout);
    }

    jenc_free(result);
    return 0;
}
