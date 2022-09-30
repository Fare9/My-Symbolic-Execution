# vm-challenge

Challenge created by Tim Blatzyko with a **VM** probably based in *ollvm*, this challenge takes a *direct threaded interpreter* mechanism, so instead of having a variable in a *program counter* register that decides which handler runs, it uses a *virtual table* with a calculated offset, the challenge apply different calculus to an input, and returns a hash value, what Jonathan did for solving this challenge was running the program as many times as he wanted to obtain the hashes, and then obtain what input he had to enter to get the resulted hashes.

The change I applied in the exercise is to pass all the expected hashes, and once I have the expression for the hash, apply the constraint solving in all the expected values, in this way we do not have to run the binary many times.

```console
$ # Jonathan Salwan version:
$ $ time python3 solver.py 
[+] Loading 0x400040 - 0x400238
[+] Loading 0x400238 - 0x400254
[+] Loading 0x400000 - 0x4799b0
[+] Loading 0x679de0 - 0x67b274
[+] Loading 0x679df0 - 0x679ff0
[+] Loading 0x400254 - 0x400274
[+] Loading 0x470184 - 0x4711d0
[+] Loading 0x000000 - 0x000000
[+] Loading 0x679de0 - 0x67a000
[+] Init PLT for: __errno_location
[+] Init PLT for: printf
[+] Init PLT for: strtoul
[+] Init PLT for: memset
[+] Init PLT for: __libc_start_main
[+] Execution 0, getting hash: 0x6d6972726f725f6d
[+] Execution 1, getting hash: 0x6972726f725f6f6e
[+] Execution 2, getting hash: 0x5f7468655f77616c
[+] Execution 3, getting hash: 0x6c5f77686f735f74
[+] Execution 4, getting hash: 0x68655f75676c6965
[+] Execution 5, getting hash: 0x73745f68616e646c
[+] Execution 6, getting hash: 0x65725f6f665f7468
[+] Execution 7, getting hash: 0x656d5f616c6c3f21
[+] Flag: b'mirror_mirror_on_the_wall_whos_the_ugliest_handler_of_them_all?!'

real	0m8.137s
user	0m8.040s
sys	    0m0.092s
$ # my version of the script:
$ time python3 solver_triton.py 
[+] Loading 0x400040 - 0x400238
[+] Loading 0x400238 - 0x400254
[+] Loading 0x400000 - 0x4799b0
[+] Loading 0x679de0 - 0x67b274
[+] Loading 0x679df0 - 0x679ff0
[+] Loading 0x400254 - 0x400274
[+] Loading 0x470184 - 0x4711d0
[+] Loading 0x000000 - 0x000000
[+] Loading 0x679de0 - 0x67a000
[+] Init PLT for: __errno_location
[+] Init PLT for: printf
[+] Init PLT for: strtoul
[+] Init PLT for: memset
[+] Init PLT for: __libc_start_main
[+] Flag: b'mirror_mirror_on_the_wall_whos_the_ugliest_handler_of_them_all?!'

real	0m3.374s
user	0m3.286s
sys	    0m0.088s
```