#include <stdio.h>
#include <stdlib.h>

unsigned long int tigress_analytica(unsigned long int a)
{
	return a + 53 - 22 + 1223;
}

int main(int argc, char **argv)
{
	unsigned long int a = strtoul(argv[1], NULL, 10);

	unsigned long int result = tigress_analytica(a);
	
	printf("%lu\n", result);

	return 0;
}
