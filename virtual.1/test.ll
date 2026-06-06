; ModuleID = 'vm_lifted'
source_filename = "vm_lifted"

; Function Attrs: nofree norecurse nosync nounwind memory(readwrite, inaccessiblemem: none)
define i64 @vm_func(ptr %name_arg, ptr %serial_arg) local_unnamed_addr #0 {
entry:
  %0 = ptrtoint ptr %name_arg to i64
  %1 = ptrtoint ptr %serial_arg to i64
  %vm_stack = alloca [128 x i8], align 1
  %2 = icmp eq ptr %name_arg, null
  %3 = icmp eq ptr %serial_arg, null
  %or.cond322 = select i1 %2, i1 true, i1 %3
  br i1 %or.cond322, label %common.ret, label %bb_10

bb_10:                                            ; preds = %entry
  %sp_slot = getelementptr inbounds [128 x i8], ptr %vm_stack, i64 0, i64 126
  %4 = load i8, ptr %serial_arg, align 1
  %5 = icmp eq i8 %4, 0
  br i1 %5, label %common.ret.loopexit326, label %bb_280

bb_272.1:                                         ; preds = %bb_287.loopexit
  %6 = load i8, ptr %name_arg, align 1
  %7 = icmp eq i8 %6, 0
  br i1 %7, label %bb_28, label %bb_280.1

bb_280.1:                                         ; preds = %bb_272.1, %bb_280.1
  %R1.6349.1 = phi i64 [ %8, %bb_280.1 ], [ 0, %bb_272.1 ]
  %ACC.7348.1 = phi i64 [ %9, %bb_280.1 ], [ %0, %bb_272.1 ]
  %8 = add i64 %R1.6349.1, 1
  %9 = add i64 %ACC.7348.1, 1
  %10 = inttoptr i64 %9 to ptr
  %11 = load i8, ptr %10, align 1
  %12 = icmp eq i8 %11, 0
  br i1 %12, label %bb_28, label %bb_280.1

bb_28:                                            ; preds = %bb_280.1, %bb_272.1
  %R1.6.lcssa.1 = phi i64 [ 0, %bb_272.1 ], [ %8, %bb_280.1 ]
  store i16 31, ptr %sp_slot, align 2
  %sp_slot125364380 = getelementptr inbounds [128 x i8], ptr %vm_stack, i64 0, i64 124
  %serial_byte99352365381 = load i8, ptr %serial_arg, align 1
  %13 = add i8 %serial_byte99352365381, -48
  %or.cond353366382 = icmp ult i8 %13, 23
  br i1 %or.cond353366382, label %bb_170.lr.ph.lr.ph, label %common.ret.loopexit

bb_170.lr.ph.lr.ph:                               ; preds = %bb_28, %bb_259
  %serial_byte99352365389 = phi i8 [ %serial_byte99352365, %bb_259 ], [ %serial_byte99352365381, %bb_28 ]
  %sp_slot125364388 = phi ptr [ %sp_slot125364, %bb_259 ], [ %sp_slot125364380, %bb_28 ]
  %sp.3.ph387 = phi i64 [ %85, %bb_259 ], [ 126, %bb_28 ]
  %SERIAL.3.ph386 = phi i64 [ %SERIAL.5, %bb_259 ], [ %1, %bb_28 ]
  %NAME.1.ph385 = phi i64 [ %popped171, %bb_259 ], [ %0, %bb_28 ]
  %R1.2.ph383 = phi i64 [ %84, %bb_259 ], [ %R1.6.lcssa.1, %bb_28 ]
  br label %bb_170.lr.ph

bb_31:                                            ; preds = %bb_202
  %14 = icmp eq i64 %R1.2367, %62
  br i1 %14, label %bb_37, label %common.ret

bb_37:                                            ; preds = %bb_31
  store i16 40, ptr %sp_slot133, align 2
  %15 = add i64 %sp.3370, -8
  %sp_slot157 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %15
  store i64 %NAME.1.ph385, ptr %sp_slot157, align 4
  br label %bb_244

bb_43:                                            ; preds = %bb_202
  %.not = icmp eq i64 %R1.2367, %62
  br i1 %.not, label %bb_49, label %common.ret

bb_49:                                            ; preds = %bb_43
  %16 = inttoptr i64 %59 to ptr
  %serial_byte = load i8, ptr %16, align 1
  %.not314 = icmp eq i8 %serial_byte, 45
  br i1 %.not314, label %bb_56, label %common.ret

bb_56:                                            ; preds = %bb_49
  %17 = add i64 %SERIAL.3369, 3
  store i16 59, ptr %sp_slot133, align 2
  br label %bb_81

bb_81:                                            ; preds = %bb_92, %bb_56
  %ACC.0 = phi i64 [ %28, %bb_92 ], [ 0, %bb_56 ]
  %R1.0 = phi i64 [ %29, %bb_92 ], [ 8, %bb_56 ]
  %SERIAL.0 = phi i64 [ %59, %bb_92 ], [ %17, %bb_56 ]
  %sp.0 = phi i64 [ %25, %bb_92 ], [ %sp.3370, %bb_56 ]
  %18 = icmp eq i64 %R1.0, 0
  br i1 %18, label %bb_105, label %bb_87

bb_87:                                            ; preds = %bb_81
  %19 = add i64 %sp.0, -8
  %sp_slot52 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %19
  store i64 %ACC.0, ptr %sp_slot52, align 4
  %20 = add i64 %sp.0, -10
  %sp_slot54 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %20
  store i16 92, ptr %sp_slot54, align 2
  %21 = add i64 %sp.0, -12
  %sp_slot125 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %21
  %22 = inttoptr i64 %SERIAL.0 to ptr
  %serial_byte99352 = load i8, ptr %22, align 1
  %23 = add i8 %serial_byte99352, -48
  %or.cond353 = icmp ult i8 %23, 23
  br i1 %or.cond353, label %bb_170.lr.ph, label %common.ret.loopexit

bb_92:                                            ; preds = %bb_202
  %24 = add i64 %sp.3370, 2
  %sp_slot56 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %24
  %popped57 = load i64, ptr %sp_slot56, align 4
  %25 = add i64 %sp.3370, 10
  %26 = shl i64 %popped57, 8
  %27 = and i64 %62, 255
  %28 = or disjoint i64 %26, %27
  %29 = add i64 %R1.2367, -1
  br label %bb_81

bb_105:                                           ; preds = %bb_81
  %30 = add i64 %sp.0, -6
  %sp_slot38 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %30
  store i64 %ACC.0, ptr %sp_slot38, align 4
  %31 = add i64 %sp.0, -8
  %sp_slot40 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %31
  store i16 64, ptr %sp_slot40, align 2
  br label %bb_116

bb_116:                                           ; preds = %bb_129, %bb_105
  %R1.1 = phi i64 [ %R1.0, %bb_105 ], [ %spec.select.7, %bb_129 ]
  %RESULT.0 = phi i64 [ -5196783011329398166, %bb_105 ], [ %48, %bb_129 ]
  %NAME.0 = phi i64 [ %NAME.1.ph385, %bb_105 ], [ %NAME.2, %bb_129 ]
  %SERIAL.1 = phi i64 [ %SERIAL.0, %bb_105 ], [ %SERIAL.4, %bb_129 ]
  %sp.1 = phi i64 [ %31, %bb_105 ], [ %39, %bb_129 ]
  %32 = inttoptr i64 %NAME.0 to ptr
  %name_byte = load i8, ptr %32, align 1
  %33 = icmp eq i8 %name_byte, 0
  br i1 %33, label %bb_153, label %bb_122

bb_122:                                           ; preds = %bb_116
  %34 = zext i8 %name_byte to i64
  %35 = add i64 %sp.1, -8
  %sp_slot72 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %35
  store i64 %RESULT.0, ptr %sp_slot72, align 4
  %36 = add i64 %sp.1, -16
  %sp_slot75 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %36
  store i64 %34, ptr %sp_slot75, align 4
  %37 = add i64 %sp.1, -18
  br label %bb_206

bb_129:                                           ; preds = %bb_206
  %sp_slot80 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %78
  %popped81 = load i64, ptr %sp_slot80, align 4
  %38 = add i64 %.sink462, 10
  %sp_slot83 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %38
  %popped84 = load i64, ptr %sp_slot83, align 4
  %39 = add i64 %.sink462, 18
  %40 = tail call i64 @llvm.fshl.i64(i64 %popped84, i64 %popped84, i64 %spec.select.7)
  %extract.t = trunc i64 %popped81 to i8
  %41 = trunc i64 %spec.select.7 to i8
  %42 = and i8 %41, 1
  %43 = sub nsw i8 0, %42
  %ACC.1.off0 = xor i8 %extract.t, %43
  %44 = trunc i64 %40 to i8
  %45 = and i64 %40, -256
  %46 = xor i8 %ACC.1.off0, %44
  %47 = zext i8 %46 to i64
  %48 = or disjoint i64 %45, %47
  br label %bb_116

bb_153:                                           ; preds = %bb_116
  %49 = add i64 %sp.1, 2
  %sp_slot42 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %49
  %popped = load i64, ptr %sp_slot42, align 4
  %50 = icmp eq i64 %popped, %RESULT.0
  %spec.select321 = zext i1 %50 to i64
  br label %common.ret

bb_176:                                           ; preds = %bb_170.lr.ph.peel.newph
  %51 = icmp ult i8 %serial_byte99.peel, 65
  br i1 %51, label %common.ret.loopexit, label %bb_202

bb_170.lr.ph:                                     ; preds = %bb_170.lr.ph.lr.ph, %bb_87
  %serial_byte99352372 = phi i8 [ %serial_byte99352365389, %bb_170.lr.ph.lr.ph ], [ %serial_byte99352, %bb_87 ]
  %sp_slot125371 = phi ptr [ %sp_slot125364388, %bb_170.lr.ph.lr.ph ], [ %sp_slot125, %bb_87 ]
  %sp.3370 = phi i64 [ %sp.3.ph387, %bb_170.lr.ph.lr.ph ], [ %20, %bb_87 ]
  %SERIAL.3369 = phi i64 [ %SERIAL.3.ph386, %bb_170.lr.ph.lr.ph ], [ %SERIAL.0, %bb_87 ]
  %R1.2367 = phi i64 [ %R1.2.ph383, %bb_170.lr.ph.lr.ph ], [ %R1.0, %bb_87 ]
  %52 = add i64 %SERIAL.3369, 1
  %53 = icmp ult i8 %serial_byte99352372, 58
  br i1 %53, label %bb_193.peel, label %bb_176.peel

bb_176.peel:                                      ; preds = %bb_170.lr.ph
  %54 = icmp ult i8 %serial_byte99352372, 65
  br i1 %54, label %common.ret.loopexit, label %bb_193.peel

bb_193.peel:                                      ; preds = %bb_170.lr.ph, %bb_176.peel
  %.sink = phi i8 [ -55, %bb_176.peel ], [ -48, %bb_170.lr.ph ]
  %55 = add nsw i8 %serial_byte99352372, %.sink
  %ACC.2.peel = zext i8 %55 to i64
  %56 = shl nuw nsw i64 %ACC.2.peel, 4
  %57 = inttoptr i64 %52 to ptr
  %serial_byte99.peel = load i8, ptr %57, align 1
  %58 = add i8 %serial_byte99.peel, -48
  %or.cond.peel = icmp ult i8 %58, 23
  br i1 %or.cond.peel, label %bb_170.lr.ph.peel.newph, label %common.ret.loopexit

bb_170.lr.ph.peel.newph:                          ; preds = %bb_193.peel
  %59 = add i64 %SERIAL.3369, 2
  %60 = icmp ult i8 %serial_byte99.peel, 58
  br i1 %60, label %bb_202, label %bb_176

bb_202:                                           ; preds = %bb_170.lr.ph.peel.newph, %bb_176
  %.sink460 = phi i8 [ -55, %bb_176 ], [ -48, %bb_170.lr.ph.peel.newph ]
  %61 = add nsw i8 %serial_byte99.peel, %.sink460
  %ACC.3.ph = zext i8 %61 to i64
  store i16 202, ptr %sp_slot125371, align 2
  %62 = add nuw nsw i64 %56, %ACC.3.ph
  %sp_slot133 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %sp.3370
  %popped134 = load i16, ptr %sp_slot133, align 2
  switch i16 %popped134, label %ret_dispatch_default135 [
    i16 31, label %bb_31
    i16 43, label %bb_43
    i16 92, label %bb_92
  ]

bb_206:                                           ; preds = %bb_250, %bb_122
  %.sink462 = phi i64 [ %82, %bb_250 ], [ %37, %bb_122 ]
  %.sink461 = phi i16 [ 253, %bb_250 ], [ 129, %bb_122 ]
  %ACC.4 = phi i64 [ %81, %bb_250 ], [ %34, %bb_122 ]
  %R1.3 = phi i64 [ %R1.5, %bb_250 ], [ %R1.1, %bb_122 ]
  %NAME.2.in = phi i64 [ %NAME.3, %bb_250 ], [ %NAME.0, %bb_122 ]
  %SERIAL.4 = phi i64 [ %SERIAL.5, %bb_250 ], [ %SERIAL.1, %bb_122 ]
  %sp_slot165 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %.sink462
  store i16 %.sink461, ptr %sp_slot165, align 2
  %63 = add i64 %.sink462, -8
  %sp_slot138 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %63
  store i64 %R1.3, ptr %sp_slot138, align 4
  %64 = and i64 %ACC.4, 1
  %65 = lshr i64 %ACC.4, 1
  %66 = and i64 %65, 1
  %67 = lshr i64 %ACC.4, 2
  %spec.select.1 = add nuw nsw i64 %64, %66
  %68 = and i64 %67, 1
  %69 = lshr i64 %ACC.4, 3
  %spec.select.2 = add nuw nsw i64 %spec.select.1, %68
  %70 = and i64 %69, 1
  %71 = lshr i64 %ACC.4, 4
  %spec.select.3 = add nuw nsw i64 %spec.select.2, %70
  %72 = and i64 %71, 1
  %73 = lshr i64 %ACC.4, 5
  %spec.select.4 = add nuw nsw i64 %spec.select.3, %72
  %74 = and i64 %73, 1
  %75 = lshr i64 %ACC.4, 6
  %spec.select.5 = add nuw nsw i64 %spec.select.4, %74
  %76 = and i64 %75, 1
  %77 = lshr i64 %ACC.4, 7
  %spec.select.6 = add nuw nsw i64 %spec.select.5, %76
  %spec.select.7 = add nuw nsw i64 %spec.select.6, %77
  %NAME.2 = add i64 %NAME.2.in, 1
  %sp_slot152 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %.sink462
  %popped153 = load i16, ptr %sp_slot152, align 2
  %78 = add i64 %.sink462, 2
  %switch319 = icmp eq i16 %popped153, 129
  br i1 %switch319, label %bb_129, label %bb_253

bb_244:                                           ; preds = %bb_253, %bb_37
  %R1.5 = phi i64 [ %83, %bb_253 ], [ 0, %bb_37 ]
  %NAME.3 = phi i64 [ %NAME.2, %bb_253 ], [ %NAME.1.ph385, %bb_37 ]
  %SERIAL.5 = phi i64 [ %SERIAL.4, %bb_253 ], [ %59, %bb_37 ]
  %sp.7 = phi i64 [ %78, %bb_253 ], [ %15, %bb_37 ]
  %79 = inttoptr i64 %NAME.3 to ptr
  %name_byte159 = load i8, ptr %79, align 1
  %80 = icmp eq i8 %name_byte159, 0
  br i1 %80, label %bb_259, label %bb_250

bb_250:                                           ; preds = %bb_244
  %81 = zext i8 %name_byte159 to i64
  %82 = add i64 %sp.7, -2
  br label %bb_206

bb_253:                                           ; preds = %bb_206
  %83 = add i64 %spec.select.7, %R1.3
  br label %bb_244

bb_259:                                           ; preds = %bb_244
  %84 = and i64 %R1.5, 255
  %sp_slot170 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %sp.7
  %popped171 = load i64, ptr %sp_slot170, align 4
  %85 = add i64 %sp.7, 8
  %sp_slot173 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %85
  store i16 43, ptr %sp_slot173, align 2
  %86 = add i64 %sp.7, 6
  %sp_slot125364 = getelementptr [128 x i8], ptr %vm_stack, i64 0, i64 %86
  %87 = inttoptr i64 %SERIAL.5 to ptr
  %serial_byte99352365 = load i8, ptr %87, align 1
  %88 = add i8 %serial_byte99352365, -48
  %or.cond353366 = icmp ult i8 %88, 23
  br i1 %or.cond353366, label %bb_170.lr.ph.lr.ph, label %common.ret.loopexit

bb_280:                                           ; preds = %bb_10, %bb_280
  %R1.6349 = phi i64 [ %89, %bb_280 ], [ 0, %bb_10 ]
  %ACC.7348 = phi i64 [ %90, %bb_280 ], [ %1, %bb_10 ]
  %89 = add i64 %R1.6349, 1
  %90 = add i64 %ACC.7348, 1
  %91 = inttoptr i64 %90 to ptr
  %92 = load i8, ptr %91, align 1
  %93 = icmp eq i8 %92, 0
  br i1 %93, label %bb_287.loopexit, label %bb_280

bb_287.loopexit:                                  ; preds = %bb_280
  %94 = icmp eq i64 %89, 21
  br i1 %94, label %bb_272.1, label %common.ret.loopexit326

common.ret.loopexit:                              ; preds = %bb_259, %bb_87, %bb_176, %bb_176.peel, %bb_193.peel, %bb_28
  %sp_slot125.lcssa = phi ptr [ %sp_slot125364380, %bb_28 ], [ %sp_slot125371, %bb_193.peel ], [ %sp_slot125371, %bb_176.peel ], [ %sp_slot125371, %bb_176 ], [ %sp_slot125, %bb_87 ], [ %sp_slot125364, %bb_259 ]
  %storemerge323.lcssa = phi i16 [ 193, %bb_28 ], [ 202, %bb_193.peel ], [ 193, %bb_176.peel ], [ 202, %bb_176 ], [ 193, %bb_87 ], [ 193, %bb_259 ]
  store i16 %storemerge323.lcssa, ptr %sp_slot125.lcssa, align 2
  br label %common.ret

common.ret.loopexit326:                           ; preds = %bb_10, %bb_287.loopexit
  store i16 16, ptr %sp_slot, align 2
  br label %common.ret

common.ret:                                       ; preds = %bb_31, %bb_43, %bb_49, %common.ret.loopexit326, %common.ret.loopexit, %bb_153, %entry
  %common.ret.op = phi i64 [ 0, %entry ], [ %spec.select321, %bb_153 ], [ 0, %common.ret.loopexit ], [ 0, %common.ret.loopexit326 ], [ 0, %bb_49 ], [ 0, %bb_43 ], [ 0, %bb_31 ]
  ret i64 %common.ret.op

ret_dispatch_default135:                          ; preds = %bb_202
  unreachable
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i64 @llvm.fshl.i64(i64, i64, i64) #1

attributes #0 = { nofree norecurse nosync nounwind memory(readwrite, inaccessiblemem: none) }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
