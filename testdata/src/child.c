#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
int main(int argc, char **argv) {
    printf("child: argc=%d", argc); for (int i = 1; i < argc; i++) printf(" [%s]", argv[i]); printf("\n");
    char v[64]; if (GetEnvironmentVariableA("PARENT_VAR", v, 64)) printf("child: PARENT_VAR=%s\n", v);
    char line[128]; if (argc > 1 && strcmp(argv[1], "echo-stdin") == 0) while (fgets(line, sizeof line, stdin)) printf("child got: %s", line);
    return argc * 10;
}
