#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    // sieve + matrix multiply + string hashing
    int n = 2000000; char *s = calloc(n + 1, 1); int primes = 0;
    for (int i = 2; i <= n; i++) if (!s[i]) { primes++; for (long j = (long)i * i; j <= n; j += i) s[j] = 1; }
    enum { N = 120 }; static double A[N][N], B[N][N], C[N][N];
    for (int i = 0; i < N; i++) for (int j = 0; j < N; j++) { A[i][j] = i + j; B[i][j] = i - j; }
    for (int i = 0; i < N; i++) for (int j = 0; j < N; j++) { double acc = 0; for (int k = 0; k < N; k++) acc += A[i][k] * B[k][j]; C[i][j] = acc; }
    unsigned h = 0; char buf[64]; for (int i = 0; i < 200000; i++) { sprintf(buf, "%d", i); for (char *p = buf; *p; p++) h = h * 31 + *p; }
    printf("primes=%d C=%.0f h=%u\n", primes, C[17][42], h);
    return 0;
}
