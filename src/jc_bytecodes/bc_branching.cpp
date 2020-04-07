/*
** The MIT License (MIT)
**
** Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
** Author:
**   - Guillaume Bouffard <guillaume.bouffard@ssi.gouv.fr>
*/

#include "../debug.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Branch if short comparison equals zero
 *
 * Format:
 *   ifeq
 *   branch
 *
 * Forms:
 *   ifeq = 96 (0x60)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value = 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifeq instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this ifeq instruction.
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifeq instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifeq() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFEQ 0x%02X", branch);

  if (value == 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison not equals zero
 *
 * Format:
 *   ifne
 *   branch
 *
 * Forms:
 *   ifne = 97 (0x61)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value != 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifne instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this ifne instruction.
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifne instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifne() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFNE 0x%02X", branch);

  if (value != 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison lower than zero
 *
 * Format:
 *   iflt
 *   branch
 *
 * Forms:
 *   iflt = 98 (0x62)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value < 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this iflt instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this iflt instruction.
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this iflt instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_iflt() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFLT 0x%02X", branch);

  if (value < 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison greater or equals to zero
 *
 * Format:
 *   ifge
 *   branch
 *
 * Forms:
 *   ifge = 99 (0x63)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value >= 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifge instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this ifge instruction.
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifge instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifge() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFGE 0x%02X", branch);

  if (value >= 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison greater than zero
 *
 * Format:
 *   ifgt
 *   branch
 *
 * Forms:
 *   ifgt = 100 (0x64)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value > 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifgt instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this ifgt instruction.
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifgt instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifgt() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFGT 0x%02X", branch);

  if (value > 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison lower or equals to zero
 *
 * Format:
 *   ifle
 *   branch
 *
 * Forms:
 *   ifle = 101 (0x65)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value <= 0.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifle instruction. The target address must be that of an opcode
 *   of an instruction within the method that contains this ifle
 *   instruction. Otherwise, execution proceeds at the address of the
 *   instruction following this ifle instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifle() {
  jshort_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFLE 0x%02X", branch);

  if (value <= 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference is null
 *
 * Format:
 *   ifnull
 *   branch
 *
 * Forms:
 *   ifnull = 102 (0x66)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type reference. It is popped from the operand
 *   stack. If the value is null, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifnull instruction. The target address must be that of an opcode
 *   of an instruction within the method that contains this ifnull
 *   instruction.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifnull instruction. The target address must be that of an opcode
 *   of an instruction within the method that contains this ifnull
 *   instruction. Otherwise, execution proceeds at the address of the
 *   instruction following this ifnull instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifnull() {
  jref_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Reference();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFNULL 0x%02X", branch);

  if (value.isNullPointer()) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference not null
 *
 * Format:
 *   ifnonnull
 *   branch
 *
 * Forms:
 *   ifnonnull = 103 (0x67)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type reference. It is popped from the operand
 *   stack. If the value is not null, branch is used as signed 8-bit offset,
 *   and execution proceeds at that offset from the address of the opcode of
 *   this ifnonnull instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this ifnonnull
 *   instruction.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this ifnonnull instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this ifnonnull
 *   instruction. Otherwise, execution proceeds at the address of the
 *   instruction following this ifnonnull instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull instruction.
 */
void Bytecodes::bc_ifnonnull() {
  jref_t value;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Reference();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IFNONNULL 0x%02X", branch);

  if (!(value.isNullPointer())) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_acmpeq
 *   branch
 *
 * Forms:
 *   if_acmpeq = 104 (0x68)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type reference. They are both popped
 *   from the operand stack and compared. The result of the comparison
 *   succeeds if and only if value1 = value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_acmpeq instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_acmpeq
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_acmpeq instruction.
 */
void Bytecodes::bc_if_acmpeq() {
  jref_t value1;
  jref_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Reference();
  value1 = stack.pop_Reference();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_ACMPEQ 0x%02X", branch);

  if (value1 == value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_acmpne
 *   branch
 *
 * Forms:
 *   if_acmpne = 105 (0x69)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type reference. They are both popped
 *   from the operand stack and compared. The result of the comparison
 *   succeeds if and only if value1 != value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_acmpne instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this
 *   if_acmpne instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_acmpne instruction.
 */
void Bytecodes::bc_if_acmpne() {
  jref_t value1;
  jref_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Reference();
  value1 = stack.pop_Reference();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_ACMPNE 0x%02X", branch);

  if (value1 != value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmpeq
 *   branch
 *
 * Forms:
 *   if_scmpeq = 106 (0x6a)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 = value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmpeq instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmpeq
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpeq instruction.
 */
void Bytecodes::bc_if_scmpeq() {
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPEQ 0x%02X", branch);

  if (value1 == value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmpne
 *   branch
 *
 * Forms:
 *   if_scmpne = 107 (0x6b)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 != value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmpne instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmpne
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpne instruction.
 */
void Bytecodes::bc_if_scmpne() /* 0x6b */
{
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPNE 0x%02X", branch);

  if (value1 != value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmplt
 *   branch
 *
 * Forms:
 *   if_scmplt = 108 (0x6c)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 < value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmplt instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmplt
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmplt instruction.
 */
void Bytecodes::bc_if_scmplt() {
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPLT 0x%02X", branch);

  if (value1 < value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmpge
 *   branch
 *
 * Forms:
 *   if_scmpge = 109 (0x6d)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 >= value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmpge instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmpge
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpge instruction.
 */
void Bytecodes::bc_if_scmpge() {
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPGE 0x%02X", branch);

  if (value1 >= value2) {
    pc.updateFromOffset(branch - 2);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmpgt
 *   branch
 *
 * Forms:
 *   if_scmpgt = 110 (0x6e)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 > value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmpgt instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmpgt
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpgt instruction.
 */
void Bytecodes::bc_if_scmpgt() {
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPGT 0x%02X", branch);

  if (value1 > value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds.
 *
 * Format:
 *   if_scmple
 *   branch
 *
 * Forms:
 *   if_scmple = 111 (0x6f)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. All comparisons are signed. The result
 *   of the comparison succeeds if and only if value1 <= value2.
 *
 *   If the comparison succeeds, branch is used as signed 8-bit offset, and
 *   execution proceeds at that offset from the address of the opcode of
 *   this if_scmple instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this if_scmple
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmple instruction.
 */
void Bytecodes::bc_if_scmple() {
  jshort_t value1;
  jshort_t value2;
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("IF_SCMPLE 0x%02X", branch);

  if (value1 <= value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch always.
 *
 * Format:
 *   goto
 *   branch
 *
 * Forms:
 *   goto = 112 (0x70)
 *
 * Stack:
 *   No change.
 *
 * Description:
 *
 *   The value branch is used as a signed 8-bit offset. Execution proceeds
 *   at that offset from the address of the opcode of this goto instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this goto instruction.
 */
void Bytecodes::bc_goto() {
  jbyte_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  branch = pc.getNextByte();

  TRACE_JCVM_DEBUG("GOTO 0x%02X", branch);

  pc.updateFromOffset(branch - sizeof(branch) - 1);
  return;
}

/**
 * Jump subroutine
 *
 * Format:
 *   jsr
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   jsr = 113 (0x71)
 *
 * Stack:
 *   ... -> ..., address
 *
 * Description:
 *
 *   The address of the opcode of the instruction immediately following this
 *   jsr instruction is pushed onto the operand stack as a value of type
 *   returnAddress. The unsigned branchbyte1 and branchbyte2 are used to
 *   construct a signed 16-bit offset, where the offset is (branchbyte1 <<
 *   8) | branchbyte2. Execution proceeds at that offset from the address of
 *   this jsr instruction. The target address must be that of an opcode of
 *   an instruction within the method that contains this jsr instruction.
 *
 * Notes:
 *
 *   The jsr instruction is used with the ret instruction in the
 *   implementation of the finally clause of the Java language. Note that
 *   jsr pushes the address onto the stack and ret gets it out of a local
 *   variable. This asymmetry is intentional.
 */
void Bytecodes::bc_jsr() {
  uint16_t branch;
  Stack &stack = this->context.getStack();
  jreturnaddress_t ret_addr;
  pc_t &pc = stack.getPC();

  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("JSR 0x%04X", branch);

  // NOTE: -2 because of the branch offset value and -1 due to getNextByte
  // function increases the PC after reading.
  pc.updateFromOffset(branch - 3);

  ret_addr = stack.savePC();
  stack.push_ReturnAddress(ret_addr);

  return;
}

/**
 * Return from subroutine
 *
 * Format:
 *   ret
 *   index
 *
 * Forms:
 *   ret = 114 (0x72)
 *
 * Stack:
 *   No change
 *
 * Description:
 *
 *   The index is an unsigned byte that must be a valid index into the local
 *   variables of the current frame (§3.5 Frames). The local variable at
 *   index must contain a value of type returnAddress. The contents of the
 *   local variable are written into the Java Card virtual machine's pc
 *   register, and execution continues there.
 *
 * Notes:
 *
 *   The ret instruction is used with the jsr instruction in the
 *   implementation of the finally keyword of the Java language. Note that
 *   jsr pushes the address onto the stack and ret gets it out of a local
 *   variable. This asymmetry is intentional.
 *
 *   The ret instruction should not be confused with the return instruction.
 *   A return instruction returns control from a Java method to its invoker,
 *   without passing any value back to the invoker.
 */
void Bytecodes::bc_ret() {
  uint8_t index;
  jreturnaddress_t address;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("RET 0x%04X", index);

  address = stack.readLocal_ReturnAddress(index);
  pc_t new_pc = stack.restorePC(address);
  pc.setValue(new_pc);

  return;
}

/**
 * Access jump table by short index and jump
 *
 * Format:
 *   stableswitch
 *   defaultbyte1
 *   defaultbyte2
 *   lowbyte1
 *   lowbyte2
 *   highbyte1
 *   highbyte2
 *   jump offsets ...
 *
 * Offset Format:
 *   offsetbyte1
 *   offsetbyte2
 *
 * Forms:
 *   stableswitch = 115 (0x73)
 *
 * Stack:
 *   ..., index -> ...
 *
 * Description:
 *
 *   A stableswitch instruction is a variable-length instruction.
 *   Immediately after the stableswitch opcode follow a signed 16-bit value
 *   default, a signed 16-bit value low, a signed 16-bit value high, and
 *   then high - low + 1 further signed 16-bit offsets. The value low must
 *   be less than or equal to high. The high - low + 1 signed 16-bit offsets
 *   are treated as a 0-based jump table. Each of the signed 16-bit values
 *   is constructed from two unsigned bytes as (byte1 << 8) | byte2.
 *
 *   The index must be of type short and is popped from the stack. If index
 *   is less than low or index is greater than high, than a target address
 *   is calculated by adding default to the address of the opcode of this
 *   stableswitch instruction. Otherwise, the offset at position index - low
 *   of the jump table is extracted. The target address is calculated by
 *   adding that offset to the address of the opcode of this stableswitch
 *   instruction. Execution then continues at the target address.
 *
 *   The target addresses that can be calculated from each jump table
 *   offset, as well as the one calculated from default, must be the address
 *   of an opcode of an instruction within the method that contains this
 *   stableswitch instruction.
 */
void Bytecodes::bc_stableswitch() {
  jshort_t default_value;
  jshort_t low_value;
  jshort_t high_value;
  jshort_t index;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

#ifdef JCRE_SWITCH_PROTECTION
  jshort_t nb_offsets;
#endif /* JCRE_SWITCH_PROTECTION */

  const uint8_t *base_pc = pc.getValue() - 1, *new_pc = nullptr;

  TRACE_JCVM_DEBUG("STABLESWITCH");

  default_value = pc.getNextShort();
  low_value = pc.getNextShort();
  high_value = pc.getNextShort();

#ifdef JCRE_SWITCH_PROTECTION
  nb_offsets = (jshort_t)(high_value - low_value + 1);
#endif /* JCRE_SWITCH_PROTECTION */

  if (low_value > high_value) {
    // The value low must be less than or equal to high.
    throw Exceptions::RuntimeException;
  }

  index = stack.pop_Short();

  if ((index < low_value) || (index > high_value)) {
    new_pc = base_pc + default_value;
  } else {
    int16_t seek;
    pc.updateFromOffset((index - low_value) * sizeof(jshort_t));
    seek =
        pc.getNextShort(); // FlashMemory_Handler::getShortFromAddr(stack.getPC());
    new_pc = base_pc + seek;
  }

#ifdef JCRE_SWITCH_PROTECTION

  // Naive countermeasure: the offset must point an instruction. The
  // pointed instruction must be out of the stableswitch instruction
  // parameter
  if ((new_pc >= base_pc) &&
      (new_pc <= (base_pc + nb_offsets * sizeof(jshort_t)))) {
    throw Exceptions::SecurityException;
  } else {
#endif /* JCRE_SWITCH_PROTECTION */
    pc.setValue(new_pc);
#ifdef JCRE_SWITCH_PROTECTION
  }

#endif /* JCRE_SWITCH_PROTECTION */

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Access jump table by int index and jump.
 *
 * Format:
 *   itableswitch
 *   defaultbyte1
 *   defaultbyte2
 *   lowbyte1
 *   lowbyte2
 *   lowbyte3
 *   lowbyte4
 *   highbyte1
 *   highbyte2
 *   highbyte3
 *   highbyte4
 *   jump offsets...
 *
 * Offset Format:
 *   offsetbyte1
 *   offsetbyte2
 *
 * Forms:
 *   itableswitch = 116 (0x74)
 *
 * Stack:
 *   ..., index.word1, index.word2 -> ...
 *
 * Description:
 *
 *   An itableswitch instruction is a variable-length instruction.
 *   Immediately after the itableswitch opcode follow a signed 16-bit value
 *   default, a signed 32-bit value low, a signed 32-bit value high, and
 *   then high - low + 1 further signed 16-bit offsets. The value low must
 *   be less than or equal to high. The high - low + 1 signed 16-bit offsets
 *   are treated as a 0-based jump table. Each of the signed 16-bit values
 *   is constructed from two unsigned bytes as (byte1 << 8) | byte2. Each of
 *   the signed 32-bit values is constructed from four unsigned bytes as
 *   (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4.
 *
 *   The index must be of type int and is popped from the stack. If index is
 *   less than low or index is greater than high, then a target address is
 *   calculated by adding default to the address of the opcode of this
 *   itableswitch instruction. Otherwise, the offset at position index - low
 *   of the jump table is extracted. The target address is calculated by
 *   adding that offset to the address of the opcode of this itableswitch
 *   instruction. Execution then continues at the target address.
 *
 *   The target addresses that can be calculated from each jump table
 *   offset, as well as the one calculated from default, must be the address
 *   of an opcode of an instruction within the method that contains this
 *   itableswitch instruction.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the
 *   itableswitch instruction will not be available.
 */
void Bytecodes::bc_itableswitch() {
  jshort_t default_value;
  jint_t low_value;
  jint_t high_value;
  jint_t index;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

#ifdef JCRE_SWITCH_PROTECTION
  jint_t nb_offsets;
#endif /* JCRE_SWITCH_PROTECTION */

  const uint8_t *base_pc = pc.getValue() - 1, *new_pc = nullptr;

  TRACE_JCVM_DEBUG("ITABLESWITCH");

  default_value = pc.getNextShort();

  low_value = pc.getNextShort();

  high_value = pc.getNextShort();

#ifdef JCRE_SWITCH_PROTECTION
  nb_offsets = (jint_t)(high_value - low_value + 1);
#endif /* JCRE_SWITCH_PROTECTION */

  if (low_value > high_value) {
    // The value low must be less than or equal to high.
    throw Exceptions::RuntimeException;
  }

  index = stack.pop_Int();

  if ((index < low_value) || (index > high_value)) {
    new_pc = base_pc + default_value;
  } else {
    int16_t seek;

    pc.updateFromOffset((index - low_value) * sizeof(jshort_t));
    seek = pc.getNextShort();
    new_pc = base_pc + seek;
  }

#ifdef JCRE_SWITCH_PROTECTION

  // Naive countermeasure: the offset must point an instruction. The
  // pointed instruction must be out of the stableswitch instruction
  // parameter
  if ((new_pc >= base_pc) &&
      (new_pc <= (base_pc + nb_offsets * sizeof(jshort_t)))) {
    throw Exceptions::SecurityException;
  } else {
#endif /* JCRE_SWITCH_PROTECTION */
    pc.setValue(new_pc);
#ifdef JCRE_SWITCH_PROTECTION
  }

#endif /* JCRE_SWITCH_PROTECTION */

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Access jump table by key match and jump
 *
 * Format:
 *   slookupswitch
 *   defaultbyte1
 *   defaultbyte2
 *   npairs1
 *   npairs2
 *   match-offset pairs...
 *
 * Pair Format:
 *   matchbyte1
 *   matchbyte2
 *   offsetbyte1
 *   offsetbyte2
 *
 * Forms:
 *   slookupswitch = 117 (0x75)
 *
 * Stack:
 *   ..., key-> ...
 * Description:
 *
 *   A slookupswitch instruction is a variable-length instruction.
 *   Immediately after the slookupswitch opcode follow a signed 16-bit value
 *   default, an unsigned 16-bit value npairs, and then npairs pairs. Each
 *   pair consists of a short match and a signed 16-bit offset. Each of the
 *   signed 16-bit values is constructed from two unsigned bytes as (byte1
 *   << 8) | byte2.
 *
 *   The table match-offset pairs of the slookupswitch instruction must be
 *   sorted in increasing numerical order by match.
 *
 *   The key must be of type short and is popped from the operand stack and
 *   compared against the match values. If it is equal to one of them, then
 *   a target address is calculated by adding the corresponding offset to
 *   the address of the opcode of this slookupswitch instruction. If the key
 *   does not match any of the match values, the target address is
 *   calculated by adding default to the address of the opcode of this
 *   slookupswitch instruction. Execution then continues at the target
 *   address.
 *
 *   The target address that can be calculated from the offset of each
 *   match-offset pair, as well as the one calculated from default, must be
 *   the address of an opcode of an instruction within the method that
 *   contains this slookupswitch instruction.
 *
 * Notes:
 *
 *   The match-offset pairs are sorted to support lookup routines that are
 *   quicker than linear search.
 *
 */
void Bytecodes::bc_slookupswitch() {
  jshort_t default_value;
  uint16_t npairs, foo;
  jshort_t key;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  const uint8_t *base_pc = pc.getValue() - 1, *new_pc = nullptr;

  TRACE_JCVM_DEBUG("SLOOKUPSWITCH");

  default_value = pc.getNextShort();
  npairs = pc.getNextShort();

  // set the new_pc to the default value
  new_pc = base_pc + default_value;

  key = stack.pop_Short();

  for (foo = 0; foo < npairs; foo++) {
    int16_t match, offset;

    match = pc.getNextShort();
    offset = pc.getNextShort();

    if (match == key) { // key found :)
      // set the correct new_pc value.
      new_pc = base_pc + offset;
      break; // quit the loop for ...
    }
  }

#ifdef JCRE_SWITCH_PROTECTION

  // Naive countermeasure: the offset must point an instruction. The
  // pointed instruction must be out of the stableswitch instruction
  // parameter
  if ((new_pc >= base_pc) &&
      (new_pc <= (base_pc + nb_offsets * sizeof(jshort_t)))) {
    throw Exceptions::SecurityException;
  } else {
#endif /* JCRE_SWITCH_PROTECTION */
    pc.setValue(new_pc);
#ifdef JCRE_SWITCH_PROTECTION
  }

#endif /* JCRE_SWITCH_PROTECTION */

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Access jump table by key match and jump
 *
 * Format:
 *   ilookupswitch
 *   defaultbyte1
 *   defaultbyte2
 *   npairs1
 *   npairs2
 *   match-offset pairs...
 *
 * Pair Format:
 *   matchbyte1
 *   matchbyte2
 *   matchbyte3
 *   matchbyte4
 *   offsetbyte1
 *   offsetbyte2
 *
 * Forms:
 *   ilookupswitch = 118 (0x76)
 *
 * Stack:
 *   ..., key.word1, key.word2 -> ...
 *
 * Description:
 *
 *   An ilookupswitch instruction is a variable-length instruction.
 *   Immediately after the ilookupswitch opcode follow a signed 16-bit value
 *   default, an unsigned 16-bit value npairs, and then npairs pairs. Each
 *   pair consists of an int match and a signed 16-bit offset. Each match is
 *   constructed from four unsigned bytes as (matchbyte1 << 24) |
 *   (matchbyte2 << 16) | (matchbyte3 << 8) | matchbyte4. Each offset is
 *   constructed from two unsigned bytes as (offsetbyte1 << 8) |
 *   offsetbyte2.
 *
 *   The table match-offset pairs of the ilookupswitch instruction must be
 *   sorted in increasing numerical order by match.
 *
 *   The key must be of type int and is popped from the operand stack and
 *   compared against the match values. If it is equal to one of them, then
 *   a target address is calculated by adding the corresponding offset to
 *   the address of the opcode of this ilookupswitch instruction. If the key
 *   does not match any of the match values, the target address is
 *   calculated by adding default to the address of the opcode of this
 *   ilookupswitch instruction. Execution then continues at the target
 *   address.
 *
 *   The target address that can be calculated from the offset of each
 *   match-offset pair, as well as the one calculated from default, must be
 *   the address of an opcode of an instruction within the method that
 *   contains this ilookupswitch instruction.
 *
 * Notes:
 *
 *   The match-offset pairs are sorted to support lookup routines that are
 *   quicker than linear search.
 *
 *   If a virtual machine does not support the int data type, the
 *   ilookupswitch instruction will not be available.
 */
void Bytecodes::bc_ilookupswitch() {
  jshort_t default_value;
  uint16_t npairs, foo;
  jint_t key;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  const uint8_t *base_pc = pc.getValue() - 1, *new_pc = nullptr;

  TRACE_JCVM_DEBUG("ILOOKUPSWITCH");

  default_value = pc.getNextShort();
  npairs = pc.getNextShort();

  // set the new_pc to the default value
  new_pc = base_pc + default_value;

  key = stack.pop_Int();

  for (foo = 0; foo < npairs; foo++) { // key found :)
    int32_t match;
    int16_t offset;

    match = pc.getNextInt();
    offset = pc.getNextShort();

    if (match == key) { // key found :)
      new_pc = base_pc + offset;
      break; // quit the loop for ...
    }
  }

#ifdef JCRE_SWITCH_PROTECTION

  // Naive countermeasure: the offset must point an instruction. The
  // pointed instruction must be out of the stableswitch instruction
  // parameter
  if ((new_pc >= base_pc) &&
      (new_pc <= (base_pc + offset * sizeof(jshort_t)))) {
    throw Exceptions::SecurityException;
  } else {
#endif /* JCRE_SWITCH_PROTECTION */
    pc.setValue(new_pc);
#ifdef JCRE_SWITCH_PROTECTION
  }

#endif /* JCRE_SWITCH_PROTECTION */

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   ifeq_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifeq_w = 152 (0x98)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value = 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifeq_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this ifeq_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifeq_w instruction.
 */
void Bytecodes::bc_ifeq_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFEQ_W 0x%04X", branch);

  if (value == 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   ifne_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifne_w = 153 (0x99)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value != 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifne_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this ifne_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifne_w instruction.
 */
void Bytecodes::bc_ifne_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFNE_W 0x%04X", branch);

  if (value != 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   iflt_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   iflt_w = 154 (0x9a)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value < 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this iflt_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this iflt_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this iflt_w instruction.
 */
void Bytecodes::bc_iflt_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFLT_W 0x%04X", branch);

  if (value < 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   ifge_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifge_w = 155 (0x9b)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value > 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifge_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this ifge_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifge_w instruction.
 */
void Bytecodes::bc_ifge_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFGE_W 0x%04X", branch);

  if (value >= 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   ifgt_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifgt_w = 156 (0x9c)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value >= 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifgt_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this ifgt_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifgt_w instruction.
 */
void Bytecodes::bc_ifgt_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFGT_W 0x%04X", branch);

  if (value > 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if short comparison with zero succeeds (wide index).
 *
 * Format:
 *   ifle_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifle_w = 157 (0x9d)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type short. It is popped from the operand stack
 *   and compared against zero. All comparisons are signed. The result of
 *   the comparison succeeds if and only if value <= 0.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifle_w instruction.
 *   The target address must be that of an opcode of an instruction within
 *   the method that contains this ifle_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifle_w instruction.
 */
void Bytecodes::bc_ifle_w() {
  jshort_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFLE_W 0x%04X", branch);

  if (value <= 0x00) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference is null (wide index).
 *
 * Format:
 *   ifnull_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifnull_w = 158 (0x9e)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type reference. It is popped from the operand
 *   stack. If the value is null, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifnull_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this ifnull_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnull_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnull_w instruction.
 */
void Bytecodes::bc_ifnull_w() {
  jref_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Reference();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFNULL_W 0x%04X", branch);

  if (value.isNullPointer()) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference not null (wide index).
 *
 * Format:
 *   ifnonnull_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   ifnonnull_w = 159 (0x9f)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The value must be of type reference. It is popped from the operand
 *   stack. If the value is not null, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this ifnonnull_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this ifnonnull_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull_w instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this ifnonnull_w instruction.
 */
void Bytecodes::bc_ifnonnull_w() {
  jref_t value;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value = stack.pop_Reference();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFNONNULL_W 0x%04X", branch);

  if (!(value.isNullPointer())) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_acmpeq_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_acmpeq_w = 160 (0xa0)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type reference. They are both popped
 *   from the operand stack and compared. The result of the comparison
 *   succeeds if and only if value1 = value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_acmpeq_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_acmpeq_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_acmpeq_w instruction.
 */
void Bytecodes::bc_if_acmpeq_w() {
  jref_t value1;
  jref_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Reference();
  value1 = stack.pop_Reference();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFACMPEQ_W 0x%04X", branch);

  if (value1 == value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_acmpne_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_acmpne_w = 161 (0xa1)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type reference. They are both popped
 *   from the operand stack and compared. The result of the comparison
 *   succeeds if and only if value1 != value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_acmpne_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_acmpne_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_acmpeq_w instruction.
 */
void Bytecodes::bc_if_acmpne_w() {
  jref_t value1;
  jref_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Reference();
  value1 = stack.pop_Reference();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IFACMPNE_W 0x%04X", branch);

  if (value1 != value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmpeq_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmpeq_w = 162 (0xa2)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 = value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmpeq_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmpeq_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpeq_w instruction.
 */
void Bytecodes::bc_if_scmpeq_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPEQ_W 0x%04X", branch);

  if (value1 == value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmpne_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmpne_w = 163 (0xa3)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 = value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmpne_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmpne_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpne_w instruction.
 */
void Bytecodes::bc_if_scmpne_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPNE_W 0x%04X", branch);

  if (value1 != value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmplt_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmpne_w = 164 (0xa4)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 < value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmplt_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmplt_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmplt_w instruction.
 */
void Bytecodes::bc_if_scmplt_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPLT_W 0x%04X", branch);

  if (value1 < value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmpge_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmpge_w = 165 (0xa5)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 <= value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmpge_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmpge_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpge_w instruction.
 */
void Bytecodes::bc_if_scmpge_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPGE_W 0x%04X", branch);

  if (value1 >= value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmpgt_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmpgt_w = 166 (0xa6)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 > value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmpgt_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmpgt_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmpgt_w instruction.
 */
void Bytecodes::bc_if_scmpgt_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPGT_W 0x%04X", branch);

  if (value1 > value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch if reference comparison succeeds (wide index).
 *
 * Format:
 *   if_scmple_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   if_scmple_w = 167 (0xa7)
 *
 * Stack:
 *   ..., value1, value2 -> ...
 *
 * Description:
 *
 *   Both value1 and value2 must be of type short. They are both popped from
 *   the operand stack and compared. Comparison is signed. The result of
 *   the comparison succeeds if and only if value1 <= value2.
 *
 *   If the comparison succeeds, the unsigned bytes branchbyte1 and
 *   branchbyte2 are used to construct a signed 16-bit branchoffset, where
 *   branchoffset is (branchbyte1 << 8) | branchbyte2. Execution proceeds at
 *   that offset from the address of the opcode of this if_scmple_w
 *   instruction. The target address must be that of an opcode of an
 *   instruction within the method that contains this if_scmple_w
 *   instruction.
 *
 *   Otherwise, execution proceeds at the address of the instruction
 *   following this if_scmple_w instruction.
 */
void Bytecodes::bc_if_scmple_w() {
  jshort_t value1;
  jshort_t value2;
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  value2 = stack.pop_Short();
  value1 = stack.pop_Short();
  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("IF_SCMPLE_W 0x%04X", branch);

  if (value1 <= value2) {
    pc.updateFromOffset(branch - sizeof(branch) - 1);
  }

  return;
}

/**
 * Branch always (wide index).
 *
 * Format:
 *   goto_w
 *   branchbyte1
 *   branchbyte2
 *
 * Forms:
 *   goto = 168 (0xa8)
 *
 * Stack:
 *   No change.
 *
 * Description:
 *
 *   The unsigned bytes branchbyte1 and branchbyte2 are used to construct a
 *   signed 16-bit branchoffset, where branchoffset is (branchbyte1 << 8) |
 *   branchbyte2. Execution proceeds at that offset from the address of the
 *   opcode of this goto instruction. The target address must be that of an
 *   opcode of an instruction within the method that contains this goto
 *   instruction.
 */
void Bytecodes::bc_goto_w() {
  jshort_t branch;
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  branch = pc.getNextShort();

  TRACE_JCVM_DEBUG("GOTO_W 0x%04X", branch);

  pc.updateFromOffset(branch - sizeof(branch) - 1);

  return;
}

} // namespace jcvm
