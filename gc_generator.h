#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./common.h"

#define YAO_KEY_BITS 80
#define YAO_KEY_BYTES ((YAO_KEY_BITS+7)/8)
#if YAO_KEY_BITS!=(YAO_KEY_BYTES*8)
#error "Yao key size needs to be a multiple of 8 bits"
#endif

typedef char yao_key_t[YAO_KEY_BYTES];

typedef struct GateInfo {
  unsigned long input1;
  unsigned long input2;
  char ttable;
  yao_key_t key;
} GateInfo;

#define MAX_GATES 100

int read_circuit_from_file(const char* filename, GateInfo** circuit, unsigned long* gate_count);
void print_gate_info(GateInfo* circuit, unsigned long gate_count);
void generate_garbled_circuit(char**** p_gc, unsigned long gc_num, GateInfo* circuit, unsigned long gate_count);
void free_gc(char**** p_gc, unsigned long gc_num, unsigned long gate_count );