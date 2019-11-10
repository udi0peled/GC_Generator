#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

void printHexBytes_padded(const char * prefix, const byte *src, unsigned len, const char * suffix) {
  if (len == 0) {
    fprintf(PRINT_OUTPUT,"%s <0 len char array> %s", prefix, suffix);
    return;
  }

  fprintf(PRINT_OUTPUT,"%s", prefix);
  int i;
  for (i = 0; i < len-1; ++i) {
    fprintf(PRINT_OUTPUT,"%02x",src[i] & 0xff);
  }
  fprintf(PRINT_OUTPUT,"%02x%s",src[i] & 0xff, suffix);
}

void printHexBytes(const byte* src, unsigned len) {
  printHexBytes_padded("", src, len, "\n");
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
        fprintf(PRINT_OUTPUT, "Warning: odd hex length for \"%s\"\n", src);
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

void print_mpi(const char * prefix, gcry_mpi_t val, const char * suffix) {
  unsigned char * dmi_buf;
  size_t dmi_len;
  gcry_mpi_aprint(GCRYMPI_FMT_USG, &dmi_buf, &dmi_len, val);
  printHexBytes_padded(prefix, dmi_buf, dmi_len, suffix);
  free(dmi_buf);
}

void print_ec_point_gcrypt(const char *prefix, gcry_ctx_t ctx, gcry_mpi_point_t p, const char *suffix) {
  gcry_mpi_t x = gcry_mpi_new(0);
  gcry_mpi_t y = gcry_mpi_new(0);
  gcry_mpi_ec_get_affine(x, y, p, ctx);
  print_mpi(prefix, x, ":");
  print_mpi("", y, suffix);
  gcry_mpi_release(x);
  gcry_mpi_release(y);
}

void print_array(const char * prefix, const char* arr, unsigned int size, unsigned int len, const char * spacer, const char * suffix) {
  fprintf(PRINT_OUTPUT, "%s", prefix);
  int i;
  for (i = 0; i < len - 1; i++) {
    printHexBytes_padded("", arr + size*i, sizeof(byte) * size, spacer);
  }
  printHexBytes_padded("", arr + size*i, sizeof(byte) * size, suffix);
}