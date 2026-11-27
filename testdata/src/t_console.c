#include <windows.h>
#include <stdio.h>
#include <conio.h>
int main(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode; BOOL isCon = GetConsoleMode(out, &mode);
    CONSOLE_SCREEN_BUFFER_INFO csbi; GetConsoleScreenBufferInfo(out, &csbi);
    printf("console=%d width=%d\n", isCon, csbi.srWindow.Right - csbi.srWindow.Left + 1);
    SetConsoleTextAttribute(out, FOREGROUND_RED | FOREGROUND_INTENSITY); printf("red"); 
    SetConsoleTextAttribute(out, FOREGROUND_GREEN | BACKGROUND_BLUE); printf(" green-on-blue");
    SetConsoleTextAttribute(out, csbi.wAttributes); printf(" normal\n");
    WriteConsoleW(out, L"unicode: é€☃ ─│\n", 15, NULL, NULL);
    printf("box via cp437 bytes: "); fflush(stdout); DWORD n; WriteFile(out, "\xC9\xCD\xBB\n", 4, &n, NULL);
    printf("press a key: "); int c = _getch(); printf("got '%c'\n", c);
    char line[64]; printf("type a line: "); fgets(line, sizeof line, stdin); printf("line=%s", line);
    return 0;
}
