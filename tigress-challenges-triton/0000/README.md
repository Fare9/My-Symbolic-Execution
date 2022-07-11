# Tigress Challenges 0000

Easiest level from [Tigress challenges](http://tigress.cs.arizona.edu/challenges.html#current), in the description we have the next text: *One level of virtualization, random dispatch.*

These are a serie of challenges in this case for Linux x86-64, and are obfuscated using virtualization, the program applies a hash function, and our task will be to extract the algorithm from the obfuscated binary.

## challenge-0

First exercise of Tigress Challenges 0000, if we run it with a number as argument we get the next:

```console
$ ./challenge-0 1234
3035321144166078008
```

If we analyze the binary, we will have a main like the next one:

```c
int main(int argc,char **argv)
{
  ulong array_numbers [4];
  ulong number_from_argv;
  int i;
  int j;
  
  FUN_004006c5();
  FUN_004006cb();
  if (argc != 2) {
    printf("Call this program with %i arguments\n",1);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  for (i = 0; i < 1; i = i + 1) {
    number_from_argv = strtoul(argv[(long)i + 1],(char **)0x0,10);
    array_numbers[i] = number_from_argv;
  }
  VM_Entry(array_numbers,array_numbers + 2);
  for (j = 0; j < 1; j = j + 1) {
    printf("%lu\n",array_numbers[(long)j + 2]);
  }
  return 0;
}
```

The **VM_Entry**, once is executed depending on a table of values, an index to choose the VM handler is calculated, the calculus is the next one:

```c
void VM_Entry(ulong *user_number,ulong *output_hash)
{
  long in_FS_OFFSET;
  undefined local_188 [256];
  undefined *local_88;
  undefined1 *addr_table;
  int i;
  int rounds;
  int x;
  byte local_59;
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_88 = local_188;
  addr_table = &DAT_00602060;
  local_59 = DAT_00602060;
  i = 0;
  rounds = 0x14;
  while (i <= rounds) {
    x = (int)((rounds - i) * ((uint)DAT_00602060 - (uint)(byte)(&DAT_00602400)[(long)i * 0x10])) /
        (int)((uint)(byte)(&DAT_00602400)[(long)rounds * 0x10] -
             (uint)(byte)(&DAT_00602400)[(long)i * 0x10]) + i;
    if ((byte)(&DAT_00602400)[(long)x * 0x10] < DAT_00602060) {
      i = x + 1;
    }
    else if (DAT_00602060 < (byte)(&DAT_00602400)[(long)x * 0x10]) {
      rounds = x + -1;
    }
    else {
      rounds = -1;
    }
  }
  (*(code *)(&function_vtable)[(long)x * 2])();
  return;
}
```

Then the program will go over a set of VM handlers. We will use Triton to emulate the code, and what we will do is to symbolize the value from the user (output of **strtoul**), and with this we will get the expression applied to our input, for getting the output.

Our python script will be the next one [triton-0000-0.py](./triton-0000-0.py). If we emulate the binary until before the **printf** from the hash, the VM code executed to generate the hash contains *39741 assembly instructions*, we can see the code in [tigress-0000-0-instructions.txt](./tigress-0000-0-instructions.txt). We can print the expressions that affect to our value to generate the hash:

```
(bvmul (bvmul (bvmul (_ bv746348727 64) (bvor (bvshl (bvand (_ bv63 64) (bvshl (bvor (_ bv74171520 64) SymVar_0) (bvand ((_ zero_extend 56) ((_ extract 7 0) (bvor (_ bv1 64) (bvand (_ bv7 64) (bvadd (_ bv886599889 64) SymVar_0))))) (_ bv63 64)))) (_ bv4 64)) (bvor (bvshl (bvadd (_ bv500810693 64) SymVar_0) (bvand ((_ zero_extend 56) ((_ extract 7 0) (bvsub (_ bv64 64) (bvor (_ bv1 64) (bvand (_ bv15 64) (bvmul (_ bv951885855 64) (bvadd (_ bv886599889 64) SymVar_0))))))) (_ bv63 64))) (bvlshr (bvadd (_ bv500810693 64) SymVar_0) (bvand ((_ zero_extend 56) ((_ extract 7 0) (bvor (_ bv1 64) (bvand (_ bv15 64) (bvmul (_ bv951885855 64) (bvadd (_ bv886599889 64) SymVar_0)))))) (_ bv63 64)))))) (bvor (_ bv74171520 64) SymVar_0)) (bvadd (bvor (_ bv18446744073071798667 64) (bvor (bvadd (_ bv886599889 64) SymVar_0) SymVar_0)) (bvadd (_ bv886599889 64) SymVar_0)))
```

From this expression, we can apply the **LLVM lifter** from Triton, we would get the next **LLVM IR** code from the expression:

```
define i64 @tigress_analytica_obf(i64 %SymVar_0) {
entry:
  %0 = add i64 886599889, %SymVar_0
  %1 = or i64 %0, %SymVar_0
  %2 = or i64 -637752949, %1
  %3 = add i64 %2, %0
  %4 = or i64 74171520, %SymVar_0
  %5 = mul i64 951885855, %0
  %6 = and i64 15, %5
  %7 = or i64 1, %6
  %8 = trunc i64 %7 to i8
  %9 = zext i8 %8 to i64
  %10 = and i64 %9, 63
  %11 = add i64 500810693, %SymVar_0
  %12 = lshr i64 %11, %10
  %13 = mul i64 951885855, %0
  %14 = and i64 15, %13
  %15 = or i64 1, %14
  %16 = sub i64 64, %15
  %17 = trunc i64 %16 to i8
  %18 = zext i8 %17 to i64
  %19 = and i64 %18, 63
  %20 = add i64 500810693, %SymVar_0
  %21 = shl i64 %20, %19
  %22 = or i64 %21, %12
  %23 = and i64 7, %0
  %24 = or i64 1, %23
  %25 = trunc i64 %24 to i8
  %26 = zext i8 %25 to i64
  %27 = and i64 %26, 63
  %28 = shl i64 %4, %27
  %29 = and i64 63, %28
  %30 = shl i64 %29, 4
  %31 = or i64 %30, %22
  %32 = mul i64 746348727, %31
  %33 = mul i64 %32, %4
  %34 = mul i64 %33, %3
  ret i64 %34
}
```

But we can apply optimization to the code and we would get the next function:

```
define i64 @tigress_analytica(i64 %SymVar_0) local_unnamed_addr #0 {
entry:
  %0 = add i64 %SymVar_0, 886599889
  %1 = or i64 %0, %SymVar_0
  %2 = or i64 %1, -637752949
  %3 = add i64 %2, %0
  %4 = or i64 %SymVar_0, 74171520
  %5 = trunc i64 %0 to i8
  %6 = mul i8 %5, 31
  %7 = and i8 %6, 14
  %8 = or i8 %7, 1
  %9 = zext i8 %8 to i64
  %10 = add i64 %SymVar_0, 500810693
  %11 = lshr i64 %10, %9
  %12 = xor i8 %7, 63
  %13 = zext i8 %12 to i64
  %14 = shl i64 %10, %13
  %15 = or i64 %14, %11
  %16 = and i8 %5, 6
  %17 = or i8 %16, 1
  %18 = zext i8 %17 to i64
  %19 = shl i64 %4, %18
  %20 = shl i64 %19, 4
  %21 = and i64 %20, 992
  %22 = or i64 %15, %21
  %23 = mul i64 %4, 746348727
  %24 = mul i64 %23, %3
  %25 = mul i64 %24, %22
  ret i64 %25
}
```

Once we have the optimized code, we can create a **LLVM IR** code in order to generate a binary, this binary will be just a main function that will call our function, we can find the code in [tigress-0000-0-expression.ll](./tigress-0000-0-expression.ll), then we can use **clang** for compiling it and run it, we will have to see if we get the same output as the original binary:

```console
$ clang tigress-0000-0-expression.ll -O2 -o tigress-0000-0-expression
$ ./tigress-0000-0-expression 12345
10268182430922439165
$ ./challenge-0 12345
10268182430922439165
$ ./tigress-0000-0-expression 6969
16517231144640719311
$ ./challenge-0 6969
16517231144640719311
```

We can load the binary in **Ghidra** to obtain a pseudo-code from the *hashing* algorithm used by the virtualizer:

```c
ulong tigress_analytica(ulong user_number)
{
  byte bVar1;
  ulong uVar2;
  
  uVar2 = user_number + 0x34d870d1;
  bVar1 = (byte)uVar2 * 31 & 0xe;
  return (user_number | 0x46bc480) * 0x2c7c60b7 *
         ((uVar2 | user_number | 0xffffffffd9fca98b) + uVar2) *
         (user_number + 0x1dd9c3c5 << (bVar1 ^ 0x3f) | user_number + 0x1dd9c3c5 >> (bVar1 | 1) |
         ((user_number | 0x46bc480) << ((byte)uVar2 & 6 | 1) & 0x3e) << 4);
}
```

With this, we have already devirtualized the first exercise from Tigress challenges!