#include "Rijndael.h"

extern int count, KC, BC, ROUNDS;

int main()
{
    int i, j;
    word8 text[4][MAX_BLOCK_COUNT], round_key[MAX_ROUNDS + 1][4][MAX_BLOCK_COUNT], sk[4][MAX_KEY_COUNT];
    for (KC = 4; KC <= 8; KC++)
    {
        for (BC = 4; BC <= 8; BC++)
        {
            // KC = 8;
            // BC = 8;
            ROUNDS = numrounds[KC - 4][BC - 4];
            for (j = 0; j < BC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    text[i][j] = 0;
                }
            }
            for (j = 0; j < KC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    sk[i][j] = 0;
                }
            }
            KeyExpansion(sk, round_key);
            Encrypt(text, round_key);
            printf("block length %d key length %d\n", 32 * BC, 32 * KC);
            for (j = 0; j < BC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    printf("%02X ", text[i][j]);
                }
            }
            printf("\n");
            Encrypt(text, round_key);
            for (j = 0; j < BC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    printf("%02X ", text[i][j]);
                }
            }
            printf("\n\n");
        }
    }
    printf("Number of times using GF(256)-multiplication: %d\n", count);

    return 0;
}