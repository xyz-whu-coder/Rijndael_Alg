#include "../include/Rijndael.h"

extern int count, KC, BC, ROUNDS;
extern double time_cost;
extern int method;

int main(int argc, const char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "wrong argument\n");
        fprintf(stdout, "usage: %s [0 | 1]\n", argv[0]);
        fprintf(stdout, "\t0 - Using MUL_CAL\n");
        fprintf(stdout, "\t1 - Using MUL_LUT\n");
        return 1;
    }
    if (argv[1][0] == '0') {
        method = MUL_CAL;
    } else if (argv[1][0] == '1') { 
        method = MUL_LUT;
    }

    int i, j;
    word8 text[4][MAX_BLOCK_COUNT], round_key[MAX_ROUNDS + 1][4][MAX_BLOCK_COUNT], sk[4][MAX_KEY_COUNT];

    for (KC = 4; KC <= 8; KC++)
    {
        for (BC = 4; BC <= 8; BC++)
        {
            ROUNDS = numrounds[KC - 4][BC - 4];
            /**
             * Initialize Plain Text(all-zero)
             */
            for (j = 0; j < BC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    text[i][j] = 0;
                }
            }
            /**
             * Initialize Key(all-zero)
             */
            for (j = 0; j < KC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    sk[i][j] = 0;
                }
            }
            KeyExpansion(sk, round_key);
            /**
             * Encrypt the text from all-zero text.
             */
            printf("block length %d key length %d\n", 32 * BC, 32 * KC);
            Encrypt(text, round_key);
            print_text(text);
            /**
             * Encrypt the text twice.
             */
            Encrypt(text, round_key);
            print_text(text);
            printf("\n\n");
        }
    }
    printf("Number of times using GF(256)-multiplication: %d\n", count);
    printf("Time Cost: %lf\n", time_cost);

    return 0;
}
