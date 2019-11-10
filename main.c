#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "gc_generator.h"

int main(int argc,char* argv[])
{
  if(argc<4)
  {
    printf("Usage: %s <hex key> <hex message> <filename>\n",argv[0]);
    return 1;
  }

  unsigned long gate_count;
  GateInfo* circuit = NULL;

  read_circuit_from_file(argv[3], &circuit, &gate_count);

  print_gate_info(circuit, gate_count);
  
  char*** gc;
  generate_garbled_circuit(&gc, 1, circuit, gate_count);

  printf("gc:\n");
  for (unsigned long j = 0; j < gate_count; ++j) {
    printHexBytes(gc[0][j], YAO_KEY_BYTES);
  }

  //print_array("gc: ", gc, YAO_KEY_BYTES, gate_count, ":", "\n");

  //free_gc(&gc, 1, gate_count);
  free(circuit);

  return 0;
}