#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./common.h"


void printHexBytes(const byte* src, unsigned len) {
    int i;
    for (i=0; i<len-1; ++i) {
        printf("%02x",src[i] & 0xff);
    }
    printf("%02x\n",src[i] & 0xff);
}

// Returnes src hex chars read, d_len set to byte length
unsigned readHexBytes(byte* dest, unsigned int* d_len, const char* src, unsigned s_len)
{
    unsigned i = 0,j = 0,del;
    while (i<*d_len && j<s_len) {
        del = 0;
        sscanf(src+j,"%2hhx%n",dest+i, &del);
        j+=del;
        i++;
    }
    if (j%2 == 1) {
        fprintf(stderr, "Warning: odd hex length for \"%s\"\n", src);
    }

    *d_len = i;
    return j;
}

byte* allocateHexInputBytes(unsigned int* byte_len, const char* input) {
    unsigned str_input_len = strlen(input);
    *byte_len = (str_input_len+1)/2;
    byte* allocated_bytes = malloc(*byte_len * sizeof(byte));
    readHexBytes(allocated_bytes, byte_len, input, str_input_len);
    allocated_bytes = realloc(allocated_bytes, *byte_len);
    return allocated_bytes;
}