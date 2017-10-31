#include <stdio.h>

int main(void) {
    unsigned age;
    char name[32];

    dup2(2, 1);

    printf("hello world!\n");

    printf("input you age: ");
    scanf("%u", &age);

    age += 123;
    age = age * 2;
    printf("input you name: ");
    scanf("%s", name);

    age = age + 12345678;
    name[0] = 'h';
    printf("your name: %s, age: %u\n", name, age);

    if ( age < 20 + 12345678 ) {
        printf("you are under 20yrd.\n");

    } else if ( age == 20 + 12345678 ) {
        printf("you are 20yrd.\n");

    } else {
        printf("you are more than 20yrd.\n");
    }
    age = age * 123;

    return 0;
}

