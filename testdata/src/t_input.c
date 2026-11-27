#include <stdio.h>
#include <string.h>
int main(void) {
    char name[64]; int age; double h;
    printf("Name? "); if (!fgets(name, sizeof name, stdin)) return 1; name[strcspn(name, "\n")] = 0;
    printf("Age and height? "); if (scanf("%d %lf", &age, &h) != 2) return 2;
    int c; long sum = 0; int lines = 0; char buf[256];
    while ((c = getchar()) != '\n' && c != EOF) {}
    while (fgets(buf, sizeof buf, stdin)) { lines++; sum += strlen(buf); }
    printf("\nHello %s, age %d, height %.2f; rest: %d lines %ld bytes\n", name, age, h, lines, sum);
    return 0;
}
