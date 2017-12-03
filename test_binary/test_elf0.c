#include <unistd.h>

int main(void) {
    char buf[128] = {0, };

    write(1, "input: ", 8);
    read(0, buf, 256);

    write(1, " << your input >>\n", 18);
    write(1, buf, 128);

    return 0;
}

