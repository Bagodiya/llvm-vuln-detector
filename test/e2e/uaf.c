#include <stdlib.h>

int use_after_free(int n, int **sink) {
  int *p = malloc(sizeof(int) * n);
  free(p);
  *sink = p;
  return p[0];
}
