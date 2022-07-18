#include <stdio.h>
#include <stdlib.h>

int modexp(int y, int x[], int w, int n)
{
	int R, L, k = 0, s = 1;
	int Stack[10];
	int sp = 0;

	void * prog[] = {
		// if (k >= w) return L
		&&k_ge_w,
		// if (x[k] == 1)
		&&x_k_ne_1, &prog[16],
		// R = (s*y) % n
		&&pusha, &R, &&pushv, &s, &&pushv, &y, &&mul, &&pushv, &n, &&mod, &&store,
		// Jump after if-statement
		&&jump, &prog[21],
		// R = s
		&&pusha, &R, &&pushv, &s,
		// s = R*R % n
		&&pusha, &s, &&pushv, &R, &&pushv, &R, &&mul, &&pushv, &n, &&mod, &&store,
		// L = R
		&&pusha, &L, &&pushv, &R, &&store,
		// k++
		&&inc_k,
		// Jump to top of loop
		&&jump,&prog[0]
	};

	void ** pc = (void**) &prog;

	goto **pc++;

inc_k:	k++; goto **pc++;
pusha:	Stack[sp++]=(int)*pc; pc++; goto **pc++;
}
