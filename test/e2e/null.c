#include <stdlib.h>

int unchecked_malloc(int n) {
  int *p = malloc(sizeof(int) * n);
  return p[n - 1];
}

int guarded_malloc(int n) {
  int *p = malloc(sizeof(int) * n);
  if (!p)
    return -1;
  return p[n - 1];
}
