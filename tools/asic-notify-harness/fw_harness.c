/* C2/C1 harness: replicate each real firmware's stratum line-accumulation loop
 * (transcribed verbatim from the vendored firmware source) and parse the result
 * with the REAL cJSON library, fed a REAL captured mining.notify body.
 *
 * Bitaxe ESP-Miner v2.12.2 / v2.14.1  (components/stratum/stratum_api.c):
 *   growing realloc buffer, BUFFER_SIZE=1024 init + 1024-increment growth,
 *   1023-byte socket chunks, strncat; realloc failure -> esp_restart().
 * NerdQAxe++ v1.0.37 (main/stratum/stratum_api.cpp):
 *   fixed BIG_BUFFER_SIZE=16384; if a line reaches the cap without '\n' ->
 *   "Buffer full" -> flush + reconnect (NULL).
 *
 * We model the ESP32 heap ceiling as a parameter (HEAP_CEIL) to detect the
 * Bitaxe realloc-failure/restart path. Reports peak buffer, restart/flush,
 * parse success, method, and params count for each firmware, per notify file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#define ESP_BUFFER_SIZE 1024
#define NQ_BIG_BUFFER_SIZE 16384
#define SOCK_CHUNK 1023   /* firmware reads up to BUFFER_SIZE-1 per recv */

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1); fread(b, 1, n, f); b[n] = 0; fclose(f);
    *len = (size_t)n; return b;
}

/* Parse the assembled line with REAL cJSON, exactly as STRATUM_V1_parse does. */
static void parse_and_report(const char *line) {
    cJSON *json = cJSON_Parse(line);
    if (!json) { printf("    cJSON_Parse: FAIL (invalid JSON)\n"); return; }
    cJSON *method = cJSON_GetObjectItem(json, "method");
    cJSON *params = cJSON_GetObjectItem(json, "params");
    int pc = (params && cJSON_IsArray(params)) ? cJSON_GetArraySize(params) : -1;
    printf("    cJSON_Parse: OK  method=%s  params=%d\n",
           (method && cJSON_IsString(method)) ? method->valuestring : "(none)", pc);
    cJSON_Delete(json);
}

/* Bitaxe ESP-Miner growing-realloc accumulation. heap_ceil models ESP32 free
 * heap available for the json buffer; realloc past it => esp_restart(). */
static void run_bitaxe(const char *tag, const char *data, size_t dlen, size_t heap_ceil) {
    size_t size = ESP_BUFFER_SIZE, peak = ESP_BUFFER_SIZE;
    char *buf = calloc(1, size);
    size_t off = 0; int reallocs = 0;
    printf("  [Bitaxe ESP-Miner grow-realloc, heap_ceil=%zuKB] %s\n", heap_ceil/1024, tag);
    while (!strstr(buf, "\n")) {
        size_t nbytes = dlen - off; if (nbytes > SOCK_CHUNK) nbytes = SOCK_CHUNK;
        if (nbytes == 0) { printf("    (stream ended without newline)\n"); break; }
        /* realloc_json_buffer(nbytes) */
        size_t old = strlen(buf), need = old + nbytes + 1;
        if (need >= size) {
            size_t nsz = need + (ESP_BUFFER_SIZE - (need % ESP_BUFFER_SIZE));
            if (nsz > heap_ceil) { printf("    *** realloc FAILED (nsz=%zu > heap_ceil) -> esp_restart() ***\n", nsz); free(buf); return; }
            buf = realloc(buf, nsz); memset(buf + old, 0, nsz - old); size = nsz; reallocs++;
        }
        strncat(buf, data + off, nbytes); off += nbytes;
        if (size > peak) peak = size;
    }
    printf("    assembled_len=%zu  peak_buffer=%zu  reallocs=%d  overflow=NO\n", strlen(buf), peak, reallocs);
    parse_and_report(buf);
    free(buf);
}

/* NerdQAxe++ fixed 16 KB accumulation with the cap-flush failure path. */
static void run_nerdqaxe(const char *tag, const char *data, size_t dlen) {
    char *buf = calloc(1, NQ_BIG_BUFFER_SIZE);
    size_t m_len = 0, off = 0;
    printf("  [NerdQAxe++ fixed 16KB buffer] %s\n", tag);
    for (;;) {
        char *nl = memchr(buf, '\n', m_len);
        if (nl) { printf("    assembled_len=%ld  cap=%d  overflow=NO\n", (long)(nl - buf), NQ_BIG_BUFFER_SIZE);
                  parse_and_report(buf); free(buf); return; }
        if (m_len >= (size_t)NQ_BIG_BUFFER_SIZE - 1) { printf("    *** Buffer full without newline -> flush + reconnect (line rejected) ***\n"); free(buf); return; }
        size_t avail = NQ_BIG_BUFFER_SIZE - m_len - 1;
        size_t nbytes = dlen - off; if (nbytes > avail) nbytes = avail; if (nbytes > SOCK_CHUNK) nbytes = SOCK_CHUNK;
        if (nbytes == 0) { printf("    (stream ended without newline)\n"); free(buf); return; }
        memcpy(buf + m_len, data + off, nbytes); m_len += nbytes; off += nbytes; buf[m_len] = 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <label> <notify.bin>\n", argv[0]); return 1; }
    size_t dlen; char *data = slurp(argv[2], &dlen);
    printf("== %s : notify body = %zu bytes ==\n", argv[1], dlen);
    /* Model a conservative ESP32 free-heap ceiling for the JSON buffer. Bitaxe
     * BM1370 boards free-heap at runtime is typically >=100KB; use 64KB as a
     * deliberately conservative ceiling for the JSON accumulation buffer. */
    run_bitaxe(argv[1], data, dlen, 64 * 1024);
    run_nerdqaxe(argv[1], data, dlen);
    free(data);
    return 0;
}
