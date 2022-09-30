# crackme1

Simple crackme used to test the framework **maat** with symbolic execution, and also used in my case for testing **Triton**.

As **maat** also loads the *loader* from Linux, and the library *libc* it takes longer, in **Triton** we have to write the whole loader with **lief** and also the replacement for **libc** functions, while a little bit more complicated, it also makes **Triton** faster:

```console
$ #execution with Maat
$ time python3 crackme_solver_maat.py 
[Info] Adding object 'ld-linux-x86-64.so.2' to virtual fs at '/usr/lib/ld-linux-x86-64.so.2'
[Info] Adding object 'libc.so.6' to virtual fs at '/usr/lib/libc.so.6'
[Info] Adding object 'crackme1' to virtual fs at '/crackme1'
Let's going to run crackme and find a solution that
solves the constraint on the jump!
Condition of branch is (ITE[0==((0xc87127f3aca5c9d0+(0x100*((0x100*((0x100*((0x100*((0x100*((0x100*((0x100*{0,{0,(0xffffffe0+(0x7*ITE[0==input_0[0x7:0x7]]({0,input_0},{0xffffff,input_0})))[0x7:0]}})+{0,{0,(0xffffffe0+(0x7*ITE[0==input_1[0x7:0x7]]({0,input_1},{0xffffff,input_1})))[0x7:0]}}))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_2[0x7:0x7]]({0,input_2},{0xffffff,input_2})))[0x7:0]}}))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_3[0x7:0x7]]({0,input_3},{0xffffff,input_3})))[0x7:0]}}))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_4[0x7:0x7]]({0,input_4},{0xffffff,input_4})))[0x7:0]}}))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_5[0x7:0x7]]({0,input_5},{0xffffff,input_5})))[0x7:0]}}))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_6[0x7:0x7]]({0,input_6},{0xffffff,input_6})))[0x7:0]}})))+{0,{0,(0xffffffe0+(0x7*ITE[0==input_7[0x7:0x7]]({0,input_7},{0xffffff,input_7})))[0x7:0]}})](0,0x1) != 0)
inverting it...
Is jump taken with our buffer 'aaaaaaaa'? = True
in our execution crackme is not solved...
Found serial: b'1bHt56z0'

real	0m4.743s
user	0m4.494s
sys	0m0.244s
$ # execution with Triton
$ time python3 crackme_solver_triton.py 
[+] Loading 0x000040 - 0x000238
[+] Loading 0x000238 - 0x000254
[+] Loading 0x000000 - 0x000b30
[+] Loading 0x200d98 - 0x201010
[+] Loading 0x200da8 - 0x200f98
[+] Loading 0x000254 - 0x000298
[+] Loading 0x0009c4 - 0x000a08
[+] Loading 0x000000 - 0x000000
[+] Loading 0x200d98 - 0x201000
[+] Applying relocations and extracting the addresses for the external functions
[+] Init PLT for: strlen
[+] Init PLT for: printf
[+] Init PLT for: __isoc99_scanf
[+] Init PLT for: __libc_start_main
[+] Starting emulation from entry point 0x000006A0
[+] __libc_start_main hooked
[+] argv[0] = b'./crackme1'
[+] printf hooked
Enter the 8-characters serial: 
[+] scanf hooked
Symbolizing the user input in the address: 0x9FFFFEC0
[+] strlen hooked
[+] Transforming buffer in address: 0x9FFFFEC0
(bvadd (bvshl (bvadd (bvshl (bvadd (bvshl (bvadd (bvshl (bvadd (bvshl (bvadd (bvshl (bvadd (bvshl ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_0) (_ bv3 32)) ((_ sign_extend 24) SymVar_0)) (_ bv32 32))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_1) (_ bv3 32)) ((_ sign_extend 24) SymVar_1)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_2) (_ bv3 32)) ((_ sign_extend 24) SymVar_2)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_3) (_ bv3 32)) ((_ sign_extend 24) SymVar_3)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_4) (_ bv3 32)) ((_ sign_extend 24) SymVar_4)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_5) (_ bv3 32)) ((_ sign_extend 24) SymVar_5)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_6) (_ bv3 32)) ((_ sign_extend 24) SymVar_6)) (_ bv32 32)))))) (_ bv8 64)) ((_ zero_extend 32) ((_ zero_extend 24) ((_ extract 7 0) (bvsub (bvsub (bvshl ((_ sign_extend 24) SymVar_7) (_ bv3 32)) ((_ sign_extend 24) SymVar_7)) (_ bv32 32))))))
6 = 122
2 = 72
0 = 49
4 = 53
3 = 116
1 = 98
7 = 48
5 = 54
[+] Emulation finished.
[!] String of result: '1bHt56z0'

real	0m0.691s
user	0m0.253s
sys	0m0.096s
```