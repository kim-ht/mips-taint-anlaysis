#include <stdio.h>
#include <stdlib.h>

///
///
///
void input_lr(int *_l, int *_r, char _op)
{
    printf("[!] L %c R\n", _op);

    printf("[!] L: ");
    scanf("%d", _l);

    printf("[!] R: ");
    scanf("%d", _r);
}

///
///
///
int menu()
{
    int selected = 0;

    printf("==== menu ====\n");
    printf("[1] add\n");
    printf("[2] sub\n");
    printf("[3] mul\n");
    printf("[4] div\n");
    printf("[5] mod\n");
    printf("[6] quit\n");
    printf("[<] ");
    scanf("%d", &selected);

    return selected;
}

///
///
///
int main()
{   
    int l = 0;
    int r = 0;

    int is_quit = 0;

    while (is_quit != 1)
    {
        switch (menu())
        {

        // add
        case 1:
            
            input_lr(&l, &r, '+');

            printf("[!] %d + %d = %d\n", 
                l, 
                r,
                l + r);

            break;

        // sub
        case 2:

            input_lr(&l, &r, '-');

            printf("[!] %d - %d = %d\n", 
                l, 
                r, 
                l - r);

            break;

        // mul
        case 3:

            input_lr(&l, &r, '*');

            printf("[!] %d * %d = %d\n", 
                l,
                r,
                l * r);

            break;

        // div
        case 4:
    
            input_lr(&l, &r, '/');

            printf("[!] %d / %d = %d\n",
                l,
                r,
                l / r);
    
            break;

        // mod
        case 5:

            input_lr(&l, &r, '%');

            printf("[!] %d %% %d = %d\n",
                l,
                r,
                l % r);

            break;

        // quit
        case 6:

            is_quit = 1;

            break;

        default:
            printf("[!] input 1 ~ 6\n");
        } 
    }

    return 0;
}

