#include "gc_generator.h"

int read_circuit_from_file(const char* filename, GateInfo** p_circuit, unsigned long* p_gate_count) {

  FILE* infile = fopen (filename, "rb");

  if (infile == NULL) 
  { 
      fprintf(stderr, "\nError opening file %s\n", filename);
      return 1;
  }

  fread(p_gate_count, sizeof(*p_gate_count), 1, infile);
  *p_circuit = malloc(sizeof(GateInfo) * (*p_gate_count));
  fread(*p_circuit, sizeof(GateInfo), *p_gate_count, infile);
  
  fclose (infile); 

  return 0;
}

void print_gate_info(GateInfo* circuit, unsigned long gate_count) {
  for (unsigned long i=0; i < gate_count; ++i) {
    GateInfo* gate = &(circuit[i]);
    printf("%-10lu%-10lu%-10lu%-4x", i, gate->input1, gate->input2, gate->ttable);
    printHexBytes_padded("", gate->key, sizeof(yao_key_t),"");
    printf("\n");
  }
}

unsigned long count_non_free_gates(GateInfo* circuit, unsigned long gate_count) {

}

void generate_garbled_circuit(char**** p_gc,  unsigned long gc_num, GateInfo* circuit, unsigned long gate_count) {
  
  unsigned long non_free_num = count_non_free_gates(circuit, gate_count);

  *p_gc = malloc(sizeof(char**) * gc_num);

  for (unsigned long j = 0; j < gc_num; ++j) {
    
    (*p_gc)[j] = malloc(sizeof(char *) * gate_count);

    for (unsigned long i = 0; i < gate_count; ++i) {
      (*p_gc)[j][i] = malloc(sizeof(yao_key_t));
      memcpy((*p_gc)[j][i], circuit[i].key, sizeof(yao_key_t));
    }
  }
}

void free_gc(char**** p_gc, unsigned long gc_num, unsigned long gate_count ) {
  for (unsigned long j = 0; j < gc_num; ++j) {
    for (unsigned long i = 0; i < gate_count; ++i) {
      free((*p_gc)[j][i]);
    }
    free((*p_gc)[j]);
  }
  free(*p_gc);
}