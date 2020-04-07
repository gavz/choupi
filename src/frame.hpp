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

#ifndef _FRAME_HPP
#define _FRAME_HPP

#include "exceptions.hpp"
#include "jc_config.h"
#include "jcvm_types/list.hpp"
#include "jcvm_types/pc_t.hpp"
#include "types.hpp"

namespace jcvm {

class Frame {
private:
  struct old_pc_t {
    bool isUsed;
    pc_t &pc;
  };

  jword_t *fp;  // frame base pointer
  jword_t *op;  // operand stack base pointer
  jword_t *tos; // top of operand stack
  jword_t *eos; // end of operand stack (= last operand stack word)
  pc_t pc;      // method program counter

  List<old_pc_t> old_pcs;

public:
  /// default constructor
  Frame(jword_t *fp, jword_t *op, jword_t *tos, jword_t *eos, pc_t &pc) noexcept
      : fp(fp), op(op), tos(tos), eos(eos), pc(pc) {}
  // Frame(const Frame &frame) noexcept = default;
  Frame &operator=(const Frame &frame) = default;
  /// Return frame base pointer
  jword_t *getFP() const noexcept;
  /// Return operand stack base pointer
  jword_t *getOP() const noexcept;
  /// Return top of operand stack pointer
  jword_t *getTOS() const noexcept;
  /// Return end of operand stack pointer
  jword_t *getEOS() const noexcept;
  /// Return method program counter pointer
  pc_t &getPC() noexcept;
  /// Set frame base pointer
  void setFP(jword_t *fp) noexcept;
  /// Set operand stack base pointer
  void setOP(jword_t *op) noexcept;
  /// Set top of operand stack
  void setTOS(jword_t *tos) noexcept;
  /// Set end of operand stack
  void setEOS(jword_t *eos) noexcept;
  /// Set method program counter pointer
  void setPC(pc_t &pc) noexcept;
  /// Save PC value for jsr instruction
  uint8_t savePC() noexcept;
  /// Restore PC value for ret instruction
  pc_t &restorePC(const uint8_t index)
#if !defined(JCVM_FIREWALL_CHECKS) && !defined(JCVM_ARRAY_SIZE_CHECK)
      noexcept
#endif
      ;
  /// Pushing a value
  void push_Value(const jword_t value)
#ifndef JCRE_STACK_OVERFLOW_PROTECTION
      noexcept
#endif
      ;
  /// Popping a value
  jword_t pop_Value()
#ifndef JCRE_STACK_OVERFLOW_PROTECTION
      noexcept
#endif
      ;
  /// Reading a Local Variable
  jword_t readLocal_Value(const uint8_t local_number)
#ifndef JCRE_STACK_OVERFLOW_PROTECTION
      noexcept
#endif
      ;
  /// Writing to Local Variable
  void writeLocal_Value(const uint8_t local_number, const int16_t value)
#ifndef JCRE_STACK_OVERFLOW_PROTECTION
      noexcept
#endif
      ;
};

} // namespace jcvm

#endif /* _FRAME_HPP */
