#include <unistd.h>

int main(void) {
    char buf[128] = {0, };

    write(1, "input: ", 8);
    read(0, buf, 128);

    buf[0] = buf[0] -2;
    buf[2] -= 3;
    buf[4] -= 1;
    buf[6] -= 5;
    buf[8] += 12;

    write(1, " << your input >>\n", 18);
    write(1, buf, 128);

    return 0;
}

