; ModuleID = 'tritonModule'
source_filename = "tritonModule"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [5 x i8] c"%lu\0A\00", align 1

; Function Attrs: norecurse nounwind readnone willreturn
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

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 %0, i8** %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca i8**, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  store i32 0, i32* %3, align 4
  store i32 %0, i32* %4, align 4
  store i8** %1, i8*** %5, align 8
  %8 = load i8**, i8*** %5, align 8
  %9 = getelementptr inbounds i8*, i8** %8, i64 1
  %10 = load i8*, i8** %9, align 8
  %11 = call i64 @strtoul(i8* %10, i8** null, i32 10) #3
  store i64 %11, i64* %6, align 8
  %12 = load i64, i64* %6, align 8
  %13 = call i64 @tigress_analytica(i64 %12)
  store i64 %13, i64* %7, align 8
  %14 = load i64, i64* %7, align 8
  %15 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([5 x i8], [5 x i8]* @.str, i64 0, i64 0), i64 %14)
  ret i32 0
}

; Function Attrs: nounwind
declare dso_local i64 @strtoul(i8*, i8**, i32) #1

declare dso_local i32 @printf(i8*, ...) #2

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 10.0.0-4ubuntu1 "}
