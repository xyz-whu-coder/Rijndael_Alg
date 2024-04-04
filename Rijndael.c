/**
 * Rijndael code August `01
 *
 * author: Vincent Rijmen,
 * This code is based on the official reference code
 * by Paulo Barreto and Vincent Rijmen
 *
 * This code is placed in the public domain.
 * Without any warranty of fitness for any purpose
 */
#include "Rijndael.h"

int BC, KC, ROUNDS;

int count = 0;

word8 Galois_Field_256_multiply(
    word8 left_value,
    word8 right_value)
{
    /**
     * multiply two elements of GF(256)
     * required for MixColumns and InvMixColumns
     */
    word8 result = 0;

    while (left_value)
    {
        // printf("mul result: %0X\n", result);
        // if the lowest bit is 1 (0x01 == b'0000 0001)
        if (left_value & 0x01)
        {
            result ^= right_value;
        }

        left_value = left_value >> 1; // left_value /= 2;

        // if the highest bit is 1 (0x80 == b'1000 0000)
        if (right_value & 0x80)
        {
            right_value = right_value << 1; // right_value *= 2; lost the highest bit，but don't worry~

            right_value ^= 0x1B; // GF-division: b = b / (x^8(lost) + x^4 + x^3 + x^1 + 1) // 1 0001 1011
                                 // 0x1B = b'0001 1011
        }
        else
        {
            right_value = right_value << 1; // right_value *= 2;
        }
    }
    // printf("\n");
    count++;
    return result;
}

void AddRoundKey(
    word8 text[4][MAX_BLOCK_COUNT],
    word8 round_key[4][MAX_BLOCK_COUNT])
{
    /**
     * XOR corresponding text input and round key input bytes
     */
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < BC; j++)
        {
            text[i][j] ^= round_key[i][j];
        }
    }
}

void SubBytes(
    word8 text[4][MAX_BLOCK_COUNT],
    const word8 box[256])
{
    /**
     * Replace every byte of the input by the byte at that place
     * in the non-linear S-box
     */
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < BC; j++)
        {
            text[i][j] = box[text[i][j]];
        }
    }
}

void ShiftRows(
    word8 text[4][MAX_BLOCK_COUNT],
    word8 d)
{
    /**
     * Row 0 remains unchanged
     * The other three rows are shifted a variable amount
     */
    word8 tmp[MAX_BLOCK_COUNT];
    int i, j;
    if (d == 0)
    {
        for (i = 1; i < 4; i++)
        {
            for (j = 0; j < BC; j++)
            {
                tmp[j] = text[i][(j + shifts[BC - 4][i]) % BC];
            }
            for (j = 0; j < BC; j++)
            {
                text[i][j] = tmp[j];
            }
        }
    }
    else
    {
        for (i = 1; i < 4; i++)
        {
            for (j = 0; j < BC; j++)
            {
                tmp[j] = text[i][(BC + j - shifts[BC - 4][i]) % BC];
            }
            for (j = 0; j < BC; j++)
            {
                text[i][j] = tmp[j];
            }
        }
    }
}

void MixColumns(word8 text[4][MAX_BLOCK_COUNT])
{
    /**
     * Mix the four bytes of every column in text linear way
     */
    word8 b[4][MAX_BLOCK_COUNT];
    int i, j;
    for (j = 0; j < BC; j++)
    {
        for (i = 0; i < 4; i++)
        {
            b[i][j] = Galois_Field_256_multiply(2, text[i][j]) ^ // 0010
                      Galois_Field_256_multiply(3, text[(i + 1) % 4][j]) ^ // 0011
                      text[(i + 2) % 4][j] ^ 
                      text[(i + 3) % 4][j]; 
        }
    }
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < BC; j++)
        {
            text[i][j] = b[i][j];
        }
    }
}

void InvMixColumns(word8 text[4][MAX_BLOCK_COUNT])
{
    /**
     * Mix the four bytes of every column ina linear way
     * This is the opposite operation of Mixcolumns
     */
    word8 b[4][MAX_BLOCK_COUNT];
    int i, j;
    for (j = 0; j < BC; j++)
    {
        for (i = 0; i < 4; i++)
        {
            b[i][j] = Galois_Field_256_multiply(0xe, text[i][j]) ^ // 1110
                      Galois_Field_256_multiply(0xb, text[(i + 1) % 4][j]) ^ // 1011
                      Galois_Field_256_multiply(0xd, text[(i + 2) % 4][j]) ^ // 1101
                      Galois_Field_256_multiply(0x9, text[(i + 3) % 4][j]);  // 1001
        }
    }
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < BC; j++)
        {
            text[i][j] = b[i][j];
        }
    }
}

int KeyExpansion(
    word8 original_key[4][MAX_KEY_COUNT],
    word8 expanded_keys[MAX_ROUNDS + 1][4][MAX_BLOCK_COUNT])
{
    /**
     * Calculate the required round Kyes
     */
    int i, j, t, RCpointer = 1;
    word8 temp_key[4][MAX_KEY_COUNT];
    for (j = 0; j < KC; j++)
    {
        for (i = 0; i < 4; i++)
        {
            temp_key[i][j] = original_key[i][j];
        }
    }
    t = 0;
    /**
     * copy values into round key array
     */
    for (j = 0; (j < KC) && (t < (ROUNDS + 1) * BC); j++, t++)
    {
        for (i = 0; i < 4; i++)
        {
            expanded_keys[t / BC][i][t % BC] = temp_key[i][j];
        }
    }
    while (t < (ROUNDS + 1) * BC)
    {
        /**
         * while not enough round key material calculated,
         * calculate new values
         */
        for (i = 0; i < 4; i++)
        {
            temp_key[i][0] ^= S_Box[temp_key[(i + 1) % 4][KC - 1]];
        }
        temp_key[0][0] ^= Rc[RCpointer++];
        if (KC <= 6)
        {
            for (j = 1; j < KC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    temp_key[i][j] ^= temp_key[i][j - 1];
                }
            }
        }
        else
        {
            for (j = 1; j < 4; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    temp_key[i][j] ^= temp_key[i][j - 1];
                }
            }
            for (i = 0; i < 4; i++)
            {
                temp_key[i][4] ^= S_Box[temp_key[i][3]];
            }
            for (j = 5; j < KC; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    temp_key[i][j] ^= temp_key[i][j - 1];
                }
            }
        }
        /**
         * copy values into round key array
         */
        for (j = 0; (j < KC) && (t < (ROUNDS + 1) * BC); j++, t++)
        {
            for (i = 0; i < 4; i++)
            {
                expanded_keys[t / BC][i][t % BC] = temp_key[i][j];
            }
        }
    }
    return 0;
}

int Encrypt(
    word8 text[4][MAX_BLOCK_COUNT], 
    word8 round_key[MAX_ROUNDS + 1][4][MAX_BLOCK_COUNT])
{
    /**
     * Encryption of one block.
     */
    int r;
    /**
     * begin with text key addition
     */
    AddRoundKey(text, round_key[0]);
    /**
     * ROUNDS - 1 ordinary rounds
     */
    for (r = 1; r < ROUNDS; r++)
    {
        SubBytes(text, S_Box);
        ShiftRows(text, 0);
        MixColumns(text);
        AddRoundKey(text, round_key[r]);
    }
    /**
     * Last round is special: there is no MixColumns
     */
    SubBytes(text, S_Box);
    ShiftRows(text, 0);
    AddRoundKey(text, round_key[ROUNDS]);
    return 0;
}

int Decrypt(
    word8 text[4][MAX_BLOCK_COUNT], 
    word8 round_key[MAX_ROUNDS + 1][4][MAX_BLOCK_COUNT])
{
    int r;
    /**
     * To decrypt:
     * apply the inverse operations of the encrypt routine
     * in opposite order
     *
     * - AddRoundKey is equal to its inverse)
     * - the inverse of SubBytes with table S_Box is
     * SubBytes with the inverse table of S_Box)
     * - the inverse of Shiftrows is Shiftrows over
     * text suitable distance)
     */
    /**
     * First the special round:
     * without InvMixcolumns
     * with extra AddRoundKey
     */
    AddRoundKey(text, round_key[ROUNDS]);
    SubBytes(text, S_Box_Inverse);
    ShiftRows(text, 1);
    /**
     * ROUNDS - 1 ordinary rounds
     */
    for (r = ROUNDS - 1; r > 0; r--)
    {
        AddRoundKey(text, round_key[r]);
        InvMixColumns(text);
        SubBytes(text, S_Box_Inverse);
        ShiftRows(text, 1);
    }
    /**
     * End with the extra key addition
     */
    AddRoundKey(text, round_key[0]);
    return 0;
}

