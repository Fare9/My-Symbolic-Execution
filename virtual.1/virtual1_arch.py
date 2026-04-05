#!/usr/bin/env python3
"""
Binary Ninja Architecture Plugin for Virtual.1 VM (bagolymadar 2020)
=====================================================================
Install: copy this file to ~/.binaryninja/plugins/virtual1_arch.py
         (or use the plugin manager to load it)

Usage:
  1. Open virtual.1 in Binary Ninja
  2. Navigate to the bytecode region (default: 0x404108)
  3. Right-click -> "Make Function" or press 'P'
  4. The bytecode will be disassembled as VM instructions
"""

from binaryninja import (
    Architecture,
    RegisterInfo,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    BranchType,
    LowLevelILOperation,
    LowLevelILLabel,
    BinaryView,
    BinaryViewType,
    Segment,
    SegmentFlag,
    Section,
    SectionSemantics,
    log_info,
    log_error,
)
from binaryninja.enums import (
    Endianness,
    FlagRole,
    LowLevelILFlagCondition,
)
import struct


# ---------------------------------------------------------------------------
# Opcode definitions
# ---------------------------------------------------------------------------

OPCODES = {
    0x01: ("MOVQ",       3),   # MOVQ  r_dst, r_src
    0x02: ("MOVB",       3),   # MOVB  r_dst, r_src
    0x09: ("PUSH_IMM8",  2),   # PUSH_IMM8  imm8
    0x11: ("JMP",        3),   # JMP   imm16
    0x14: ("DEC",        2),   # DEC   r
    0x1e: ("PTR_NULL",   2),   # PTR_NULL  r
    0x41: ("INC",        2),   # INC   r
    0x4c: ("HLT",        1),   # HLT
    0x52: ("LOAD_SERIAL",1),   # LOAD_SERIAL
    0x54: ("CMPZ",       2),   # CMPZ  r
    0x55: ("JZ",         3),   # JZ    imm16
    0x56: ("MOV_IMM8",   3),   # MOV_IMM8  r, imm8
    0x69: ("LOAD_NAME",  1),   # LOAD_NAME
    0x7f: ("CMP_IMM8",   3),   # CMP_IMM8  r, imm8
    0x81: ("JNZ",        3),   # JNZ   imm16
    0x8d: ("PUSH_REG",   2),   # PUSH_REG  r
    0x8e: ("POP_REG",    2),   # POP_REG   r
    0x8f: ("SHR",        3),   # SHR   r, imm8
    0x90: ("TEST_IMM8",  3),   # TEST_IMM8 r, imm8
    0x93: ("ADD_REG",    3),   # ADD_REG   r_dst, r_src
    0x94: ("AND_IMM64", 10),   # AND_IMM64 r, imm64
    0x95: ("JL",         3),   # JL    imm16
    0x96: ("SUB_IMM8",   3),   # SUB_IMM8  r, imm8
    0x97: ("SHL",        3),   # SHL   r, imm8
    0x98: ("CMP_REG",    3),   # CMP_REG   r_dst, r_src
    0x99: ("MOV_IMM64", 10),   # MOV_IMM64 r, imm64
    0x9a: ("ROL",        3),   # ROL   r_dst, r_src
    0x9b: ("NOT",        2),   # NOT   r
    0x9c: ("XOR",        3),   # XOR   r_dst, r_src
    0xab: ("CALL",       3),   # CALL  imm16
    0xba: ("RET",        1),   # RET
}

# Register names indexed by slot (slot N = vm + N*8)
REG_NAMES = {
    0: "ACC",
    1: "r1",
    2: "RESULT",
    3: "PC",
    4: "NAME",
    5: "SERIAL",
    6: "FLAGS",
    7: "SP",
}

def reg_name(idx):
    return REG_NAMES.get(idx, f"r{idx}")


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

T = InstructionTextTokenType

def tok_instr(text):
    return InstructionTextToken(T.InstructionToken, text)

def tok_sep(text=" "):
    return InstructionTextToken(T.OperandSeparatorToken, text)

def tok_reg(name):
    return InstructionTextToken(T.RegisterToken, name)

def tok_imm(value, text=None):
    if text is None:
        text = f"0x{value:x}"
    return InstructionTextToken(T.IntegerToken, text, value)

def tok_addr(value):
    return InstructionTextToken(T.PossibleAddressToken, f"0x{value:04x}", value)


# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------

class Virtual1Arch(Architecture):
    name               = "Virtual1VM"
    endianness         = Endianness.BigEndian
    address_size       = 2          # 16-bit addresses in bytecode
    default_int_size   = 8          # 64-bit registers
    instr_alignment    = 1
    max_instr_length   = 10         # AND_IMM64 / MOV_IMM64 are 10 bytes

    # Registers
    regs = {
        "ACC":    RegisterInfo("ACC",    8),
        "r1":     RegisterInfo("r1",     8),
        "RESULT": RegisterInfo("RESULT", 8),
        "PC":     RegisterInfo("PC",     2),
        "NAME":   RegisterInfo("NAME",   8),
        "SERIAL": RegisterInfo("SERIAL", 8),
        "FLAGS":  RegisterInfo("FLAGS",  8),
        "SP":     RegisterInfo("SP",     8),
    }

    stack_pointer = "SP"

    # Flags — bit0 = zero/equal, bit1 = less-than
    flags = ["z", "lt"]
    flag_write_types = ["none", "zf", "ltf", "all"]

    flags_written_by_flag_write_type = {
        "none": [],
        "zf":   ["z"],
        "ltf":  ["lt"],
        "all":  ["z", "lt"],
    }

    flag_roles = {
        "z":  FlagRole.ZeroFlagRole,
        "lt": FlagRole.NegativeSignFlagRole,
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E:   ["z"],
        LowLevelILFlagCondition.LLFC_NE:  ["z"],
        LowLevelILFlagCondition.LLFC_SLT: ["lt"],
    }

    # ------------------------------------------------------------------
    # Decoding helpers
    # ------------------------------------------------------------------

    def _decode(self, data, addr):
        """Return (mnemonic, length, operands_bytes) or None."""
        if not data:
            return None
        opcode = data[0]
        if opcode not in OPCODES:
            return None
        mnemonic, length = OPCODES[opcode]
        if len(data) < length:
            return None
        operands = data[1:length]
        return mnemonic, length, operands

    def _big_endian_16(self, operands, offset=0):
        return (operands[offset] << 8) | operands[offset + 1]

    def _big_endian_64(self, operands, offset=0):
        val = 0
        for i in range(8):
            val = (val << 8) | operands[offset + i]
        return val

    # ------------------------------------------------------------------
    # get_instruction_info — control flow
    # ------------------------------------------------------------------

    def get_instruction_info(self, data, addr):
        decoded = self._decode(data, addr)
        if decoded is None:
            return None

        mnemonic, length, operands = decoded
        info = InstructionInfo()
        info.length = length

        if mnemonic == "JMP":
            target = self._big_endian_16(operands)
            info.add_branch(BranchType.UnconditionalBranch, target)

        elif mnemonic == "JZ":
            target = self._big_endian_16(operands)
            info.add_branch(BranchType.TrueBranch,  target)
            info.add_branch(BranchType.FalseBranch, addr + length)

        elif mnemonic == "JNZ":
            target = self._big_endian_16(operands)
            info.add_branch(BranchType.TrueBranch,  target)
            info.add_branch(BranchType.FalseBranch, addr + length)

        elif mnemonic == "JL":
            target = self._big_endian_16(operands)
            info.add_branch(BranchType.TrueBranch,  target)
            info.add_branch(BranchType.FalseBranch, addr + length)

        elif mnemonic == "CALL":
            target = self._big_endian_16(operands)
            info.add_branch(BranchType.CallDestination, target)

        elif mnemonic == "RET":
            info.add_branch(BranchType.FunctionReturn)

        elif mnemonic == "HLT":
            info.add_branch(BranchType.FunctionReturn)

        return info

    # ------------------------------------------------------------------
    # get_instruction_text — disassembly
    # ------------------------------------------------------------------

    def get_instruction_text(self, data, addr):
        decoded = self._decode(data, addr)
        if decoded is None:
            return None

        mnemonic, length, operands = decoded
        tokens = [tok_instr(f"{mnemonic:<12}")]

        if mnemonic in ("MOVQ", "MOVB", "ADD_REG", "CMP_REG", "ROL", "XOR"):
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_reg(reg_name(operands[1]))]

        elif mnemonic in ("INC", "DEC", "NOT", "PTR_NULL", "CMPZ",
                          "PUSH_REG", "POP_REG"):
            tokens += [tok_reg(reg_name(operands[0]))]

        elif mnemonic == "PUSH_IMM8":
            tokens += [tok_imm(operands[0])]

        elif mnemonic == "MOV_IMM8":
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_imm(operands[1])]

        elif mnemonic == "MOV_IMM64":
            val = self._big_endian_64(operands, 1)
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_imm(val, f"0x{val:016x}")]

        elif mnemonic in ("SHR", "SHL", "TEST_IMM8", "SUB_IMM8"):
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_imm(operands[1])]

        elif mnemonic == "CMP_IMM8":
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_imm(operands[1])]

        elif mnemonic == "AND_IMM64":
            val = self._big_endian_64(operands, 1)
            tokens += [tok_reg(reg_name(operands[0])), tok_sep(", "),
                       tok_imm(val, f"0x{val:016x}")]

        elif mnemonic in ("JMP", "JZ", "JNZ", "JL", "CALL"):
            target = self._big_endian_16(operands)
            tokens += [tok_addr(target)]

        elif mnemonic in ("HLT", "RET", "LOAD_SERIAL", "LOAD_NAME"):
            pass  # no operands to display

        return tokens, length

    # ------------------------------------------------------------------
    # get_instruction_low_level_il — LLIL lifting
    # ------------------------------------------------------------------

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = self._decode(data, addr)
        if decoded is None:
            il.append(il.undefined())
            return 1

        mnemonic, length, operands = decoded

        def reg(idx):
            return il.reg(8, reg_name(idx))

        def set_reg(idx, expr):
            return il.set_reg(8, reg_name(idx), expr)

        def imm(val, size=8):
            return il.const(size, val)

        # ---- MOV / LOAD ----

        if mnemonic == "MOVQ":
            il.append(set_reg(operands[0], reg(operands[1])))

        elif mnemonic == "MOVB":
            # copy low byte of src into low byte of dst
            src_byte = il.low_part(1, reg(operands[1]))
            dst_rest = il.and_expr(8, reg(operands[0]), imm(0xffffffffffffff00))
            merged   = il.or_expr(8, dst_rest, il.zero_extend(8, src_byte))
            il.append(set_reg(operands[0], merged))

        elif mnemonic == "MOV_IMM8":
            il.append(set_reg(operands[0], imm(operands[1])))

        elif mnemonic == "MOV_IMM64":
            val = self._big_endian_64(operands, 1)
            il.append(set_reg(operands[0], imm(val)))

        elif mnemonic == "LOAD_SERIAL":
            # ACC = zero_extend(*SERIAL);  SERIAL++
            ptr  = il.reg(8, "SERIAL")
            byte = il.zero_extend(8, il.load(1, ptr))
            il.append(il.set_reg(8, "ACC", byte))
            il.append(il.set_reg(8, "SERIAL",
                      il.add(8, ptr, imm(1))))

        elif mnemonic == "LOAD_NAME":
            ptr  = il.reg(8, "NAME")
            byte = il.zero_extend(8, il.load(1, ptr))
            il.append(il.set_reg(8, "ACC", byte))
            il.append(il.set_reg(8, "NAME",
                      il.add(8, ptr, imm(1))))

        # ---- ARITHMETIC ----

        elif mnemonic == "INC":
            il.append(set_reg(operands[0],
                      il.add(8, reg(operands[0]), imm(1))))

        elif mnemonic == "DEC":
            il.append(set_reg(operands[0],
                      il.sub(8, reg(operands[0]), imm(1))))

        elif mnemonic == "ADD_REG":
            il.append(set_reg(operands[0],
                      il.add(8, reg(operands[0]), reg(operands[1]))))

        elif mnemonic == "SUB_IMM8":
            il.append(set_reg(operands[0],
                      il.sub(8, reg(operands[0]), imm(operands[1]))))

        elif mnemonic == "SHL":
            il.append(set_reg(operands[0],
                      il.shift_left(8, reg(operands[0]), imm(operands[1]))))

        elif mnemonic == "SHR":
            il.append(set_reg(operands[0],
                      il.logical_shift_right(8, reg(operands[0]), imm(operands[1]))))

        elif mnemonic == "ROL":
            # ROL(dst, src) — Binary Ninja has no native ROL so we expand it
            val   = reg(operands[0])
            shift = il.reg(8, reg_name(operands[1]))
            left  = il.shift_left(8, val, shift)
            right = il.logical_shift_right(8, val,
                    il.sub(8, imm(64), shift))
            il.append(set_reg(operands[0], il.or_expr(8, left, right)))

        elif mnemonic == "NOT":
            # NOT low byte only
            lo     = il.low_part(1, reg(operands[0]))
            not_lo = il.not_expr(1, lo)
            rest   = il.and_expr(8, reg(operands[0]), imm(0xffffffffffffff00))
            merged = il.or_expr(8, rest, il.zero_extend(8, not_lo))
            il.append(set_reg(operands[0], merged))

        elif mnemonic == "XOR":
            # XOR low byte of dst with low byte of src
            lo_dst = il.low_part(1, reg(operands[0]))
            lo_src = il.low_part(1, reg(operands[1]))
            xored  = il.xor_expr(1, lo_dst, lo_src)
            rest   = il.and_expr(8, reg(operands[0]), imm(0xffffffffffffff00))
            merged = il.or_expr(8, rest, il.zero_extend(8, xored))
            il.append(set_reg(operands[0], merged))

        elif mnemonic == "AND_IMM64":
            val = self._big_endian_64(operands, 1)
            il.append(set_reg(operands[0],
                      il.and_expr(8, reg(operands[0]), imm(val))))

        # ---- COMPARISONS / FLAGS ----

        elif mnemonic == "CMPZ":
            # FLAGS bit0 = (reg == 0)
            result = il.compare_equal(8, reg(operands[0]), imm(0))
            zf     = il.zero_extend(8, result)
            flags  = il.reg(8, "FLAGS")
            new_flags = il.or_expr(8,
                        il.and_expr(8, flags, imm(0xfffffffffffffffe)),
                        zf)
            il.append(il.set_reg(8, "FLAGS", new_flags))

        elif mnemonic == "PTR_NULL":
            # FLAGS bit0 = (*reg == 0)
            byte   = il.zero_extend(8, il.load(1, reg(operands[0])))
            result = il.compare_equal(8, byte, imm(0))
            zf     = il.zero_extend(8, result)
            flags  = il.reg(8, "FLAGS")
            new_flags = il.or_expr(8,
                        il.and_expr(8, flags, imm(0xfffffffffffffffe)),
                        zf)
            il.append(il.set_reg(8, "FLAGS", new_flags))

        elif mnemonic == "CMP_IMM8":
            # FLAGS bit0 = eq, bit1 = lt
            val  = reg(operands[0])
            imm8 = imm(operands[1])
            eq   = il.zero_extend(8, il.compare_equal(8, val, imm8))
            lt   = il.zero_extend(8,
                   il.compare_signed_less_than(8, val, imm8))
            lt2  = il.shift_left(8, lt, imm(1))
            flags = il.reg(8, "FLAGS")
            new_flags = il.or_expr(8,
                        il.and_expr(8, flags, imm(0xfffffffffffffffc)),
                        il.or_expr(8, eq, lt2))
            il.append(il.set_reg(8, "FLAGS", new_flags))

        elif mnemonic == "CMP_REG":
            val  = reg(operands[0])
            src  = reg(operands[1])
            eq   = il.zero_extend(8, il.compare_equal(8, val, src))
            lt   = il.zero_extend(8,
                   il.compare_signed_less_than(8, val, src))
            lt2  = il.shift_left(8, lt, imm(1))
            flags = il.reg(8, "FLAGS")
            new_flags = il.or_expr(8,
                        il.and_expr(8, flags, imm(0xfffffffffffffffc)),
                        il.or_expr(8, eq, lt2))
            il.append(il.set_reg(8, "FLAGS", new_flags))

        elif mnemonic == "TEST_IMM8":
            # FLAGS bit0 = ((reg & imm8) == 0)
            val    = il.and_expr(8, reg(operands[0]), imm(operands[1]))
            result = il.zero_extend(8, il.compare_equal(8, val, imm(0)))
            flags  = il.reg(8, "FLAGS")
            new_flags = il.or_expr(8,
                        il.and_expr(8, flags, imm(0xfffffffffffffffe)),
                        result)
            il.append(il.set_reg(8, "FLAGS", new_flags))

        # ---- STACK ----

        elif mnemonic == "PUSH_IMM8":
            sp = il.reg(8, "SP")
            new_sp = il.sub(8, sp, imm(1))
            il.append(il.set_reg(8, "SP", new_sp))
            il.append(il.store(1, new_sp, imm(operands[0], 1)))

        elif mnemonic == "PUSH_REG":
            sp = il.reg(8, "SP")
            new_sp = il.sub(8, sp, imm(8))
            il.append(il.set_reg(8, "SP", new_sp))
            il.append(il.store(8, new_sp, reg(operands[0])))

        elif mnemonic == "POP_REG":
            sp = il.reg(8, "SP")
            il.append(set_reg(operands[0], il.load(8, sp)))
            il.append(il.set_reg(8, "SP", il.add(8, sp, imm(8))))

        # ---- CONTROL FLOW ----

        elif mnemonic == "JMP":
            target = self._big_endian_16(operands)
            il.append(il.jump(il.const_pointer(2, target)))

        elif mnemonic == "JZ":
            target = self._big_endian_16(operands)
            # jump if FLAGS bit0 == 1
            cond = il.compare_not_equal(8,
                   il.and_expr(8, il.reg(8, "FLAGS"), imm(1)),
                   imm(0))
            t = il.get_label_for_address(Architecture["Virtual1VM"], target)
            f = LowLevelILLabel()
            if t is None:
                t = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(il.const_pointer(2, target)))
            else:
                il.append(il.if_expr(cond, t, f))
            il.mark_label(f)

        elif mnemonic == "JNZ":
            target = self._big_endian_16(operands)
            # jump if FLAGS bit0 == 0
            cond = il.compare_equal(8,
                   il.and_expr(8, il.reg(8, "FLAGS"), imm(1)),
                   imm(0))
            t = il.get_label_for_address(Architecture["Virtual1VM"], target)
            f = LowLevelILLabel()
            if t is None:
                t = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(il.const_pointer(2, target)))
            else:
                il.append(il.if_expr(cond, t, f))
            il.mark_label(f)

        elif mnemonic == "JL":
            target = self._big_endian_16(operands)
            # jump if FLAGS bit1 == 1
            cond = il.compare_not_equal(8,
                   il.and_expr(8, il.reg(8, "FLAGS"), imm(2)),
                   imm(0))
            t = il.get_label_for_address(Architecture["Virtual1VM"], target)
            f = LowLevelILLabel()
            if t is None:
                t = LowLevelILLabel()
                il.append(il.if_expr(cond, t, f))
                il.mark_label(t)
                il.append(il.jump(il.const_pointer(2, target)))
            else:
                il.append(il.if_expr(cond, t, f))
            il.mark_label(f)

        elif mnemonic == "CALL":
            target = self._big_endian_16(operands)
            il.append(il.call(il.const_pointer(2, target)))

        elif mnemonic == "RET":
            il.append(il.ret(il.load(2, il.reg(8, "SP"))))

        elif mnemonic == "HLT":
            il.append(il.no_ret())

        else:
            il.append(il.undefined())

        return length


# ---------------------------------------------------------------------------
# Binary View — points Binary Ninja at the bytecode region
# ---------------------------------------------------------------------------

class Virtual1View(BinaryView):
    name         = "Virtual1VM"
    long_name    = "Virtual.1 VM Bytecode"

    # Bytecode base: 0x401837 + 0x28d1 = 0x404108 inside the ELF
    BYTECODE_OFFSET = 0x404108
    BYTECODE_SIZE   = 0x200        # adjust if needed

    @classmethod
    def is_valid_for_data(cls, data):
        # Only offer this view when the parent is an ELF with the right magic
        return data.read(0, 4) == b'\x7fELF'

    def __init__(self, data):
        super().__init__(file_metadata=data.file, parent_view=data)
        self.raw   = data
        self.arch  = Architecture["Virtual1VM"]
        self.platform = self.arch.standalone_platform

    def init(self):
        try:
            # Read bytecode from the ELF
            bytecode = self.raw.read(self.BYTECODE_OFFSET, self.BYTECODE_SIZE)
            if not bytecode:
                log_error("Virtual1View: could not read bytecode region")
                return False

            # Map bytecode starting at virtual address 0x0000
            self.add_auto_segment(
                0x0000, self.BYTECODE_SIZE,
                self.BYTECODE_OFFSET, self.BYTECODE_SIZE,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
            )
            self.add_auto_section(
                ".bytecode", 0x0000, self.BYTECODE_SIZE,
                SectionSemantics.ReadOnlyCodeSectionSemantics
            )

            # Entry point at bytecode offset 0
            self.add_entry_point(0x0000)
            log_info("Virtual1View: bytecode mapped at 0x0000")
            return True

        except Exception as e:
            log_error(f"Virtual1View: init failed: {e}")
            return False

    def perform_get_address_size(self):
        return 2

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x0000


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

Virtual1Arch.register()
Virtual1View.register()
log_info("Virtual1 VM architecture plugin loaded")