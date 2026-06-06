; ModuleID = 'main'
source_filename = "main"

@fmt_good = private constant [7 x i8] c"Good!\0A\00"
@fmt_bad  = private constant [6 x i8] c"Bad!\0A\00"

declare i64 @vm_func(ptr %name_arg, ptr %serial_arg)
declare i32 @printf(ptr, ...)

define i32 @main(i32 %argc, ptr %argv) {
entry:
  ; require exactly 3 args: prog name serial
  %enough = icmp eq i32 %argc, 3
  br i1 %enough, label %call, label %usage

usage:
  ret i32 1

call:
  ; argv[1] = name, argv[2] = serial
  %name_ptr   = getelementptr ptr, ptr %argv, i64 1
  %serial_ptr = getelementptr ptr, ptr %argv, i64 2
  %name   = load ptr, ptr %name_ptr,   align 8
  %serial = load ptr, ptr %serial_ptr, align 8

  %result = call i64 @vm_func(ptr %name, ptr %serial)

  %ok = icmp ne i64 %result, 0
  br i1 %ok, label %good, label %bad

good:
  call i32 (ptr, ...) @printf(ptr @fmt_good)
  ret i32 0

bad:
  call i32 (ptr, ...) @printf(ptr @fmt_bad)
  ret i32 1
}
