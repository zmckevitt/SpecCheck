all: v1 v2 v3 v4

v1: spectre_v1.c
	gcc spectre_v1.c -o spectre_v1_x86 -static

v2: spectre_v2.cpp
	g++ spectre_v2.cpp -o spectre_v2_x86 -Os -static

v3: spectre_v3.c
	gcc spectre_v3.c -o spectre_v3_x86 -Os -static

v4: spectre_v4.c
	gcc spectre_v4.c -o spectre_v4_x86 -Os -static

clean:
	rm -f *_x86
