#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VM Analysis Script - Triton + LIEF
====================================
Target  : VirtUAL 1 crackme (bagolymadar 2020)
Goal    : Emulate the VM and print VM-level instructions

Usage   : python3 solve-vm.py [--x86]
            --x86   also print raw x86 instructions
"""

import sys
import lief
from triton import *

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARY_PATH      = "./virtual.1"
BASE_ADDRESS     = 0x400000

# VM struct base
VM_STRUCT        = 0x404230

# VM struct offsets
VM_ACC           = VM_STRUCT + 0x00   # r0 / accumulator
VM_R1            = VM_STRUCT + 0x08   # r1
VM_RESULT        = VM_STRUCT + 0x10   # r2 / result / return value
VM_PC            = VM_STRUCT + 0x18   # r3 / program counter
VM_NAME          = VM_STRUCT + 0x20   # r4 / pointer to name buffer
VM_SERIAL        = VM_STRUCT + 0x28   # r5 / pointer to serial buffer
VM_FLAGS         = VM_STRUCT + 0x30   # r6 / flags
VM_SP            = VM_STRUCT + 0x38   # r7 / stack pointer

# Bytecode base: lea rsi, [rip + 0x28d1] at 0x401830, rip = 0x401837
BYTECODE_BASE    = 0x401837 + 0x28d1

# Emulation range
ADDR_VMSTART     = 0x4017f1
ADDR_VMSTART_RET = 0x40182f

# Map opcode -> x86 handler address (je targets from the switch)
OPCODE_HANDLERS = {
    0x01: 0x401939,   # MOVQ
    0x02: 0x401963,   # MOVB
    0x09: 0x40198d,   # PUSH_IMM8
    0x11: 0x4019a5,   # JMP
    0x14: 0x4019b6,   # DEC
    0x1e: 0x4019d0,   # PTR_NULL
    0x41: 0x401a01,   # INC
    0x4c: 0x401a1b,   # HLT
    0x52: 0x401a1d,   # LOAD_SERIAL
    0x54: 0x401a3e,   # CMPZ
    0x55: 0x401a6e,   # JZ
    0x56: 0x401a96,   # MOV_IMM8
    0x69: 0x401ab5,   # LOAD_NAME
    0x7f: 0x401ad6,   # CMP_IMM8
    0x81: 0x401b12,   # JNZ
    0x8d: 0x401b3a,   # PUSH_REG
    0x8e: 0x401b62,   # POP_REG
    0x8f: 0x401b8a,   # SHR
    0x90: 0x401ba7,   # TEST_IMM8
    0x93: 0x401bda,   # ADD_REG
    0x94: 0x401c07,   # AND_IMM64
    0x95: 0x401c4b,   # JL
    0x96: 0x401c73,   # SUB_IMM8
    0x97: 0x401c8e,   # SHL
    0x98: 0x401cab,   # CMP_REG
    0x99: 0x401cf2,   # MOV_IMM64
    0x9a: 0x401d30,   # ROL
    0x9b: 0x401d5a,   # NOT
    0x9c: 0x401d74,   # XOR
    0xab: 0x401d9e,   # CALL
    0xba: 0x401dc9,   # RET
}

# Reverse map: handler address -> opcode
HANDLER_TO_OPCODE = {v: k for k, v in OPCODE_HANDLERS.items()}
HANDLER_ADDRESSES = set(OPCODE_HANDLERS.values())

# Fake buffers
FAKE_NAME_ADDR   = 0x00200000
FAKE_SERIAL_ADDR = 0x00300000

NAME_VALUE       = b"Pepe\x00"
SERIAL_VALUE     = b"040D-2A2C515DA54FECE9\x00"  # 21 chars

MAX_INSTRUCTIONS = 500_000

# CLI flag
PRINT_X86        = "--x86" in sys.argv


# ---------------------------------------------------------------------------
# Register name helper
# ---------------------------------------------------------------------------

REG_NAMES = {
    0: "r0/ACC",
    1: "r1",
    2: "r2/RESULT",
    3: "r3/PC",
    4: "r4/NAME",
    5: "r5/SERIAL",
    6: "r6/FLAGS",
    7: "r7/SP",
}

def rname(idx):
    return REG_NAMES.get(idx, f"r{idx}")


# ---------------------------------------------------------------------------
# VM-level disassembler
# ---------------------------------------------------------------------------

def print_vm_instruction(ctx, opcode):
    """Print the current VM instruction using the known opcode."""
    pc    = ctx.getConcreteMemoryValue(MemoryAccess(VM_PC,    CPUSIZE.QWORD))
    flags = ctx.getConcreteMemoryValue(MemoryAccess(VM_FLAGS, CPUSIZE.QWORD))
    acc   = ctx.getConcreteMemoryValue(MemoryAccess(VM_ACC,   CPUSIZE.QWORD))

    def bc(offset):
        return ctx.getConcreteMemoryValue(
            MemoryAccess(BYTECODE_BASE + pc + offset, CPUSIZE.BYTE))

    def bc16(offset):
        return (bc(offset) << 8) | bc(offset + 1)   # big-endian

    def bc64(offset):
        val = 0
        for i in range(8):
            val = (val << 8) | bc(offset + i)
        return val

    match opcode:
        case 0x01: s = f"MOVQ      {rname(bc(1))}, {rname(bc(2))}"
        case 0x02: s = f"MOVB      {rname(bc(1))}, {rname(bc(2))}"
        case 0x09: s = f"PUSH_IMM8 0x{bc(1):02x}"
        case 0x11: s = f"JMP       0x{bc16(1):04x}"
        case 0x14: s = f"DEC       {rname(bc(1))}"
        case 0x1e: s = f"PTR_NULL  {rname(bc(1))}"
        case 0x41: s = f"INC       {rname(bc(1))}"
        case 0x4c: s = f"HLT"
        case 0x52: s = f"LOAD_SERIAL                        ; ACC=0x{acc:02x}"
        case 0x54: s = f"CMPZ      {rname(bc(1))}"
        case 0x55: s = f"JZ        0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x56: s = f"MOV_IMM8  {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x69: s = f"LOAD_NAME                          ; ACC=0x{acc:02x}"
        case 0x7f: s = f"CMP_IMM8  {rname(bc(1))}, 0x{bc(2):02x}             ; FLAGS=0x{flags:x}"
        case 0x81: s = f"JNZ       0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x8d: s = f"PUSH_REG  {rname(bc(1))}"
        case 0x8e: s = f"POP_REG   {rname(bc(1))}"
        case 0x8f: s = f"SHR       {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x90: s = f"TEST_IMM8 {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x93: s = f"ADD_REG   {rname(bc(1))}, {rname(bc(2))}"
        case 0x94: s = f"AND_IMM64 {rname(bc(1))}, 0x{bc64(2):016x}"
        case 0x95: s = f"JL        0x{bc16(1):04x}                   ; FLAGS=0x{flags:x}"
        case 0x96: s = f"SUB_IMM8  {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x97: s = f"SHL       {rname(bc(1))}, 0x{bc(2):02x}"
        case 0x98: s = f"CMP_REG   {rname(bc(1))}, {rname(bc(2))}             ; FLAGS=0x{flags:x}"
        case 0x99: s = f"MOV_IMM64 {rname(bc(1))}, 0x{bc64(2):016x}"
        case 0x9a: s = f"ROL       {rname(bc(1))}, {rname(bc(2))}"
        case 0x9b: s = f"NOT       {rname(bc(1))}"
        case 0x9c: s = f"XOR       {rname(bc(1))}, {rname(bc(2))}"
        case 0xab: s = f"CALL      0x{bc16(1):04x}"
        case 0xba: s = f"RET"
        case _:    s = f"UNKNOWN   0x{opcode:02x}"

    print(f"  [VM:{pc:04x}] {s}")


# ---------------------------------------------------------------------------
# Load binary with LIEF
# ---------------------------------------------------------------------------

def load_binary(ctx: TritonContext, path: str) -> lief.Binary:
    binary = lief.parse(path)
    if binary is None:
        raise RuntimeError(f"LIEF could not parse '{path}'")

    for segment in binary.segments:
        if segment.type == lief.ELF.Segment.TYPE.LOAD:
            vaddr   = BASE_ADDRESS + segment.virtual_address
            content = bytes(segment.content)
            ctx.setConcreteMemoryAreaValue(vaddr, content)
            print(f"[LIEF] Mapped segment @ 0x{vaddr:08x}  size=0x{len(content):x}")

    return binary


# ---------------------------------------------------------------------------
# Patch binary — fix movabs addresses missing base
# ---------------------------------------------------------------------------

def patch_binary(ctx: TritonContext) -> None:
    # movabs rdi, 0x404230  at 0x4017f9  (encoding: 48 BF + 8 bytes)
    ctx.setConcreteMemoryAreaValue(0x4017f9 + 2, (0x404230).to_bytes(8, 'little'))
    # movabs r10, 0x404230  at 0x401805  (encoding: 49 BA + 8 bytes)
    ctx.setConcreteMemoryAreaValue(0x401805 + 2, (0x404230).to_bytes(8, 'little'))
    print("[PATCH] Fixed VM struct address in movabs instructions")


# ---------------------------------------------------------------------------
# Setup initial state
# ---------------------------------------------------------------------------

def setup_state(ctx: TritonContext) -> None:
    # name and serial buffers
    ctx.setConcreteMemoryAreaValue(FAKE_NAME_ADDR,   NAME_VALUE)
    ctx.setConcreteMemoryAreaValue(FAKE_SERIAL_ADDR, SERIAL_VALUE)

    # zero VM struct region
    ctx.setConcreteMemoryAreaValue(VM_STRUCT, b"\x00" * 0xc0)

    # registers
    ctx.setConcreteRegisterValue(ctx.registers.rip, ADDR_VMSTART)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7ffff000)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7ffff000)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, FAKE_NAME_ADDR)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, FAKE_SERIAL_ADDR)

    print(f"[SETUP] name         = {NAME_VALUE!r}  @ 0x{FAKE_NAME_ADDR:08x}")
    print(f"[SETUP] serial       = {SERIAL_VALUE!r}  @ 0x{FAKE_SERIAL_ADDR:08x}")
    print(f"[SETUP] BYTECODE_BASE= 0x{BYTECODE_BASE:08x}")
    print(f"[SETUP] Concrete state initialised")


# ---------------------------------------------------------------------------
# Triton context init
# ---------------------------------------------------------------------------

def init_triton() -> TritonContext:
    ctx = TritonContext(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY,    True)
    ctx.setMode(MODE.CONSTANT_FOLDING,  True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx


# ---------------------------------------------------------------------------
# Emulation loop
# ---------------------------------------------------------------------------

SKIP_STDLIB      = "--no-stdlib" in sys.argv

SKIP_SUBROUTINES = {
    0x0110,   # strlen
    0x00ce,   # popcount single char
    0x00ef,   # popcount whole string
    0x009a,   # parse hex digit
    0x00be,   # parse hex byte (2 digits)
}

def emulate(ctx: TritonContext) -> None:
    print(f"\n[EMU] Starting emulation from 0x{ADDR_VMSTART:08x}")
    print(f"[EMU] Printing: VM instructions {'+ x86' if PRINT_X86 else 'only'}\n")

    skip_depth = 0

    for count in range(MAX_INSTRUCTIONS):
        rip = ctx.getConcreteRegisterValue(ctx.registers.rip)

        if rip == ADDR_VMSTART_RET:
            break

        # determine VM instruction BEFORE processing
        should_print_vm = False
        vm_opcode       = None

        if rip in HANDLER_ADDRESSES:
            vm_opcode = HANDLER_TO_OPCODE[rip]
            pc        = ctx.getConcreteMemoryValue(MemoryAccess(VM_PC, CPUSIZE.QWORD))

            if SKIP_STDLIB:
                if pc in SKIP_SUBROUTINES:
                    skip_depth += 1
                if vm_opcode == 0xba and skip_depth > 0:   # RET inside skipped sub
                    skip_depth -= 1
                    # do NOT print, but still process below

            if skip_depth == 0:
                should_print_vm = True

        # print VM instruction BEFORE x86 processing (operands still valid)
        if should_print_vm:
            print_vm_instruction(ctx, vm_opcode)

        # always process the x86 instruction
        opcodes = ctx.getConcreteMemoryAreaValue(rip, 16)
        insn    = Instruction(rip, opcodes)
        ctx.processing(insn)

        if insn.getType() == OPCODE.X86.HLT:
            print(f"[EMU] HLT @ 0x{rip:08x}")
            break

        if PRINT_X86 and skip_depth == 0:
            print(f"    [x86] 0x{rip:08x}  {insn.getDisassembly()}")

    else:
        print(f"[EMU] Reached instruction cap ({MAX_INSTRUCTIONS})")

    # print final VM register state
    print("\n[VM FINAL STATE]")
    print(f"  r0/ACC    = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_ACC,    CPUSIZE.QWORD)):016x}")
    print(f"  r1        = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_R1,     CPUSIZE.QWORD)):016x}")
    print(f"  r2/RESULT = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_RESULT, CPUSIZE.QWORD)):016x}")
    print(f"  r3/PC     = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_PC,     CPUSIZE.QWORD)):016x}")
    print(f"  r4/NAME   = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_NAME,   CPUSIZE.QWORD)):016x}")
    print(f"  r5/SERIAL = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_SERIAL, CPUSIZE.QWORD)):016x}")
    print(f"  r6/FLAGS  = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_FLAGS,  CPUSIZE.QWORD)):016x}")
    print(f"  r7/SP     = 0x{ctx.getConcreteMemoryValue(MemoryAccess(VM_SP,     CPUSIZE.QWORD)):016x}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"[INFO] name         = {NAME_VALUE!r}")
    print(f"[INFO] serial       = {SERIAL_VALUE!r}")
    print(f"[INFO] x86 printing = {PRINT_X86}\n")

    ctx = init_triton()
    load_binary(ctx, BINARY_PATH)
    patch_binary(ctx)
    setup_state(ctx)
    emulate(ctx)


if __name__ == "__main__":
    main()