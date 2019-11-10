#include <gcrypt.h>

#ifndef _UDI_COMMON_PRINT_H_
#define _UDI_COMMON_PRINT_H_

#define PRINT_OUTPUT stdout

typedef unsigned char byte;
typedef unsigned int word;
typedef unsigned long dword;

void printHexBytes(const byte* src, unsigned len);
void printHexBytes_padded(const char * prefix, const byte *src, unsigned len, const char * suffix);
unsigned int readHexBytes(byte* dest,unsigned* d_len,const char* src,unsigned s_len);
byte* allocateHexInputBytes(unsigned int* byte_len, const char* input);
void print_array(const char * prefix, const char* arr, unsigned int size, unsigned int len, const char * spacer, const char * suffix);

void print_mpi(const char * prefix, gcry_mpi_t val, const char * suffix);
//void print_bn(const char * prefix, const BIGNUM * bn, const char * suffix);
void print_ec_point_gcrypt(const char *prefix, gcry_ctx_t ctx, gcry_mpi_point_t p, const char *suffix);
//void print_ec_point_openssl(const char *prefix, const EC_GROUP *c, const EC_POINT *p, const char *suffix);

#endif //_UDI_COMMON_PRINT_H_