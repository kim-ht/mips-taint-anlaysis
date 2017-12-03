#include <stdio.h>
#include <string.h>
#include <stdlib.h>


///
///
///
int main()
{
    //
    char buffer[256] = { 0 };

    //
    int line = 0;

    char lines[10][256] = { 0 };


    int is_quit = 0;
    
    while (is_quit != 1)
    {
        printf("[!] line: %d\n", line);
        printf("[<] ");
        scanf("%s", buffer);

        // command
        if (buffer[0] == '!')
        {
            switch (buffer[1])
            {
            
            // up line
            case 'u':

                if (line > 0)
                {
                    --line;
                }

                break;

            // down line
            case 'd':
            
                if (line < 9)
                {
                    ++line;
                }

                break;

            // view line
            case 'v':
            
                printf("[%d] %s\n", line, lines[line]);

                break;

            // quit
            case 'q':

                is_quit = 1;

                break;

            default:
                printf("[!] nop\n");
            }

        // normal
        } else
        {
            strncpy(lines[line], buffer, 256);
        }
    }

    return 0;
}

