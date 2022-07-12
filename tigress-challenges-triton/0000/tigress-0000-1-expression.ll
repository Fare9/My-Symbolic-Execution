; ModuleID = 'tritonModule'
source_filename = "tritonModule"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [5 x i8] c"%lu\0A\00", align 1

; Function Attrs: norecurse nounwind readnone willreturn
define i64 @tigress_analytica(i64 %SymVar_0) local_unnamed_addr #0 {
entry:
  %0 = and i64 %SymVar_0, 573319932
  %1 = add nsw i64 %0, -341319700
  %2 = trunc i64 %1 to i8
  %3 = and i8 %2, 12
  %4 = or i8 %3, 1
  %5 = zext i8 %4 to i64
  %6 = and i64 %SymVar_0, 335886564
  %7 = add nuw nsw i64 %6, -1595821287
  %8 = shl i64 %7, %5
  %9 = xor i8 %3, 63
  %10 = zext i8 %9 to i64
  %11 = lshr i64 %7, %10
  %12 = or i64 %11, %8
  %13 = lshr i64 %7, 3
  %14 = trunc i64 %13 to i8
  %15 = and i8 %14, 6
  %16 = or i8 %15, 1
  %17 = zext i8 %16 to i64
  %18 = mul nsw i64 %1, 502412191
  %19 = add i64 %SymVar_0, 584234876
  %20 = add i64 %19, %18
  %21 = lshr i64 %20, %17
  %22 = add i64 %21, %SymVar_0
  %23 = lshr i64 %22, 16
  %24 = shl nsw i64 %12, 2
  %25 = and i64 %24, 48
  %26 = or i64 %23, %25
  %27 = xor i64 %26, %12
  %28 = lshr i64 %27, 3
  %29 = trunc i64 %28 to i8
  %30 = and i8 %29, 14
  %31 = or i8 %30, 1
  %32 = zext i8 %31 to i64
  %33 = lshr i64 %20, 1
  %34 = trunc i64 %33 to i8
  %35 = and i8 %34, 14
  %36 = or i8 %35, 1
  %37 = zext i8 %36 to i64
  %38 = lshr i64 %1, 48
  %39 = lshr i64 %1, 56
  %40 = lshr i64 %1, 40
  %41 = lshr i64 %1, 24
  %42 = shl nsw i64 %1, 8
  %43 = and i64 %42, 16776192
  %44 = and i64 %41, 239
  %45 = or i64 %43, %44
  %46 = lshr i64 %1, 8
  %47 = and i64 %46, 65280
  %48 = and i64 %40, 255
  %49 = or i64 %48, %47
  %50 = shl nuw nsw i64 %45, 32
  %51 = shl nuw nsw i64 %49, 16
  %52 = or i64 %50, %51
  %53 = and i64 %41, 65280
  %54 = or i64 %53, %39
  %55 = or i64 %54, %52
  %56 = shl nuw i64 %55, 8
  %57 = and i64 %38, 255
  %58 = shl i64 %20, 2
  %59 = and i64 %58, 28
  %60 = or i64 %59, %57
  %61 = or i64 %60, %56
  %62 = lshr i64 %61, %37
  %63 = xor i8 %35, 63
  %64 = zext i8 %63 to i64
  %65 = shl i64 %61, %64
  %66 = or i64 %65, %62
  %67 = shl i64 %66, %32
  %68 = xor i8 %30, 63
  %69 = zext i8 %68 to i64
  %70 = lshr i64 %66, %69
  %71 = or i64 %70, %67
  ret i64 %71
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
