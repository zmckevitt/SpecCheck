all: v1 v2

v1: spectre_v1.c
	gcc spectre_v1.c -o spectre_v1_x86 -static

v2: spectre_v2.c
	gcc -std=c99 -O0 spectre_v2.c -o spectre_v2_x86 -static

clean:
	rm spectre_v1_x86
	rm spectre_v2_x86
