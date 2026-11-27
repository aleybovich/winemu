#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>

static int cmp_int(const void *a, const void *b) { int x = *(const int*)a, y = *(const int*)b; return (x > y) - (x < y); }
static int cmp_str(const void *a, const void *b) { return strcmp(*(char* const*)a, *(char* const*)b); }
static jmp_buf jb;
static void jumper(int n) { if (n == 0) longjmp(jb, 42); jumper(n - 1); }
static int sum(int n, ...) { va_list ap; va_start(ap, n); int s = 0; for (int i = 0; i < n; i++) s += va_arg(ap, int); va_end(ap); return s; }
static void vmsg(const char *fmt, ...) { char buf[128]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap); printf("[%s]\n", buf); }
typedef struct { double x, y; char name[16]; } Pt;
static Pt mkpt(double x, double y, const char *n) { Pt p; p.x = x; p.y = y; strncpy(p.name, n, 15); p.name[15] = 0; return p; }
static uint64_t fib(int n) { return n < 2 ? n : fib(n-1) + fib(n-2); }

int main(int argc, char **argv) {
    printf("== printf ==\n");
    printf("%d %i %u %x %X %o %c %s %%\n", -42, 17, 3000000000u, 0xbeef, 0xcafe, 0755, 'Z', "str");
    printf("[%5d] [%-5d] [%05d] [%+d] [% d] [%.3d] [%*d] [%-*d]\n", 42, 42, 42, 42, 42, 7, 6, 9, 6, 9);
    printf("%lld %llu %llx %" PRId64 " %zu %hd %hhu\n", -9223372036854775807LL - 1, 18446744073709551615ULL, 0x123456789abcdefULL, (int64_t)-5, (size_t)12345, (short)-3, (unsigned char)250);
    printf("%f %.2f %10.3f %-10.1f| %e %E %.0e %g %G %g %g %g\n", 3.14159, 2.71828, -1.5, 9.99, 12345.678, 0.000123, 5.5, 0.0001, 1e20, 100000.0, 1e-5, 123456789.0);
    printf("%g %g %g %.3g %#g %#x %#o %a\n", 0.5, 1.0, 1e100, 3.14159, 1.0, 255, 8, 1.0);
    printf("%s|%10s|%-10s|%.2s|%c%c\n", "abc", "right", "left", "truncate", 'o', 'k');
    printf("%f %f %.1f %.10f\n", 1e15, -0.0, 0.05, 1.0/3.0);
    printf("inf=%f %e\n", INFINITY, -INFINITY);
    char buf[256];
    int n = snprintf(buf, 10, "%s", "hello world this is long");
    printf("snprintf n=%d buf=%s\n", n, buf);
    sprintf(buf, "%08.3f|%x|%-6s|", 3.5, 4096, "ab"); puts(buf);
    vmsg("vm %d %s %.1f", 7, "x", 2.25);
    printf("== strings ==\n");
    strcpy(buf, "Hello"); strcat(buf, ", World"); printf("%s %zu\n", buf, strlen(buf));
    printf("%d %d %d\n", strcmp("abc", "abd") < 0, strncmp("abcdef", "abcxyz", 3), strcmp("b", "a") > 0);
    printf("%s %s %s\n", strchr(buf, 'W'), strrchr(buf, 'o'), strstr(buf, "lo,"));
    printf("%zu %zu\n", strspn("aaabbbccc", "ab"), strcspn("hello world", " "));
    char tok[] = "a,b;;c,d"; for (char *t = strtok(tok, ",;"); t; t = strtok(NULL, ",;")) printf("tok=%s ", t); printf("\n");
    char *d = strdup("duplicate"); printf("%s\n", d); free(d);
    memset(buf, 'x', 5); buf[5] = 0; printf("%s\n", buf);
    memcpy(buf, "abcdef", 7); memmove(buf + 2, buf, 4); printf("%s\n", buf);
    printf("%d %d\n", memcmp("abc", "abd", 3) < 0, memcmp("same", "same", 4));
    printf("%c %c %d %d %d %d\n", toupper('a'), tolower('Q'), isdigit('5') != 0, isalpha('!') != 0, isspace('\t') != 0, isxdigit('f') != 0);
    printf("== conversions ==\n");
    char *end;
    printf("%ld %ld %lu %lld\n", strtol("  -123abc", &end, 10), strtol("0x1F", NULL, 16), strtoul("777", NULL, 8), strtoll("9223372036854775807", NULL, 10));
    printf("end=%s\n", end);
    printf("%d %ld %.3f %.4f\n", atoi("  42"), atol("-99"), atof("3.14159"), strtod("2.5e3xyz", &end));
    printf("end=%s\n", end);
    errno = 0; long big = strtol("99999999999999999999", NULL, 10); printf("ovf %ld errno=%d\n", big, errno == ERANGE);
    int a, b2; char w[32]; double f;
    int got = sscanf("12 abc 3.5 99", "%d %s %lf %d", &a, w, &f, &b2);
    printf("sscanf=%d %d %s %.2f %d\n", got, a, w, f, b2);
    got = sscanf("key=value;rest", "%[^=]=%[^;]", buf, w); printf("scanset=%d %s %s\n", got, buf, w);
    got = sscanf("0x1a 017 -5", "%i %i %i", &a, &b2, &n); printf("%%i=%d %d %d %d\n", got, a, b2, n);
    got = sscanf("", "%d", &a); printf("empty=%d\n", got);
    printf("== memory ==\n");
    int *arr = malloc(1000 * sizeof(int)); for (int i = 0; i < 1000; i++) arr[i] = (i * 7919) % 1000;
    qsort(arr, 1000, sizeof(int), cmp_int);
    int ok = 1; for (int i = 1; i < 1000; i++) if (arr[i-1] > arr[i]) ok = 0; printf("sorted=%d first=%d last=%d\n", ok, arr[0], arr[999]);
    int key = 500; int *hit = bsearch(&key, arr, 1000, sizeof(int), cmp_int); printf("bsearch=%d\n", hit ? *hit : -1);
    arr = realloc(arr, 100000 * sizeof(int)); arr[99999] = 5; printf("realloc ok %d %d\n", arr[999], arr[99999]); free(arr);
    int *z = calloc(100, sizeof(int)); int zs = 0; for (int i = 0; i < 100; i++) zs += z[i]; printf("calloc zero=%d\n", zs); free(z);
    void *ptrs[500]; for (int i = 0; i < 500; i++) { ptrs[i] = malloc(i * 13 + 1); memset(ptrs[i], i, i * 13 + 1); }
    for (int i = 0; i < 500; i += 2) free(ptrs[i]); for (int i = 0; i < 500; i += 2) ptrs[i] = malloc(i + 3);
    int bad = 0; for (int i = 1; i < 500; i += 2) for (int j = 0; j < i * 13 + 1; j++) if (((unsigned char*)ptrs[i])[j] != (unsigned char)i) bad++;
    printf("heap integrity bad=%d\n", bad); for (int i = 0; i < 500; i++) free(ptrs[i]);
    const char *names[] = {"pear", "apple", "fig", "banana", "cherry"}; qsort(names, 5, sizeof(char*), cmp_str);
    for (int i = 0; i < 5; i++) printf("%s ", names[i]); printf("\n");
    printf("== math ==\n");
    printf("%.6f %.6f %.6f %.6f %.6f\n", sin(1.0), cos(1.0), tan(0.5), atan2(1, -1), sqrt(2));
    printf("%.6f %.6f %.6f %.6f %.6f\n", exp(1.5), log(10), log10(1000), pow(2, 0.5), fabs(-3.25));
    printf("%.1f %.1f %.1f %.1f %.3f %.3f\n", floor(-2.5), ceil(-2.5), round(2.5), trunc(-2.7), fmod(10.5, 3), hypot(3, 4));
    printf("%.4f %.4f %.4f %d %ld\n", sinf(0.5f), sqrtf(2.0f), powf(3.0f, 2.5f), (int)lround(-2.5), lrint(3.5));
    int ex; double fr = frexp(48.0, &ex); double ip; double fp2 = modf(3.75, &ip);
    printf("frexp=%.3f %d ldexp=%.1f modf=%.2f %.2f cbrt=%.3f\n", fr, ex, ldexp(0.75, 4), ip, fp2, cbrt(27.0));
    volatile double zero = 0.0; printf("isnan=%d isinf=%d\n", isnan(zero/zero) != 0, isinf(1.0/zero) != 0);
    float ff = 1.0f; for (int i = 0; i < 10; i++) ff = ff * 1.1f + 0.3f; printf("float loop %.5f\n", ff);
    double acc = 0; for (int i = 1; i <= 1000; i++) acc += 1.0 / ((double)i * i); printf("basel %.10f\n", acc);
    printf("== control ==\n");
    int r = setjmp(jb); if (r == 0) { jumper(10); printf("not reached\n"); } else printf("longjmp=%d\n", r);
    printf("sum=%d fib30=%llu\n", sum(5, 1, 2, 3, 4, 5), (unsigned long long)fib(30));
    Pt p = mkpt(1.5, -2.5, "origin-ish"); printf("pt %.1f %.1f %s\n", p.x, p.y, p.name);
    uint64_t h = 1469598103934665603ULL; for (int i = 0; i < 100000; i++) { h ^= i; h *= 1099511628211ULL; } printf("fnv=%llx\n", (unsigned long long)h);
    int64_t s64 = -7; printf("div %lld %lld %llu\n", (long long)(s64 / 2), (long long)(s64 % 3), (unsigned long long)(0xFFFFFFFFFFFFFFFFULL / 3));
    printf("argc=%d argv1=%s\n", argc, argc > 1 ? argv[1] : "(none)");
    printf("== files ==\n");
    FILE *fp = fopen("winemu_test.txt", "w"); fprintf(fp, "line one\nline %d\n", 2); fputs("third\n", fp); fclose(fp);
    fp = fopen("winemu_test.txt", "r"); char line[64]; while (fgets(line, sizeof line, fp)) printf("read: %s", line);
    printf("eof=%d\n", feof(fp) != 0); fclose(fp);
    fp = fopen("winemu_test.txt", "a+"); fputs("appended\n", fp); fseek(fp, 0, SEEK_END); printf("size=%ld\n", ftell(fp)); fclose(fp);
    fp = fopen("winemu_test.bin", "wb"); int data[4] = {1, 2, 3, 0x7fffffff}; fwrite(data, sizeof(int), 4, fp); fclose(fp);
    fp = fopen("winemu_test.bin", "rb"); fseek(fp, 4, SEEK_SET); int rd[3]; size_t nr = fread(rd, sizeof(int), 3, fp);
    printf("fread=%zu %d %d %d tell=%ld\n", nr, rd[0], rd[1], rd[2], ftell(fp)); fclose(fp);
    fp = fopen("winemu_test.txt", "r"); int c; int lines = 0; while ((c = fgetc(fp)) != EOF) if (c == '\n') lines++; fclose(fp); printf("lines=%d\n", lines);
    fp = fopen("winemu_test.txt", "r"); fscanf(fp, "%s %s", buf, w); printf("fscanf %s %s\n", buf, w); fclose(fp);
    printf("rename=%d\n", rename("winemu_test.bin", "winemu_test2.bin"));
    printf("remove=%d %d\n", remove("winemu_test.txt"), remove("winemu_test2.bin"));
    printf("missing=%p\n", (void*)fopen("does/not/exist.txt", "r"));
    fprintf(stderr, "to stderr\n");
    return 0;
}
