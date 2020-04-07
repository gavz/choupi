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

#ifndef _STACK_HPP
#define _STACK_HPP

#include "exceptions.hpp"
#include "frame.hpp"
#include "jc_config.h"
#include "jc_types/jref_t.hpp"
#include "types.hpp"

// TODO: Move the PC to the context.hpp file (in the packagesID list)

namespace jcvm {

/**
 * Checks stack manipulated types size
 */
static_assert(sizeof(jbool_t) == sizeof(jbyte_t),
              "jbool_t class has a wrong size.");
static_assert(sizeof(jbyte_t) == (sizeof(jword_t) / 2),
              "jbyte_t class has a wrong size.");
static_assert(sizeof(jshort_t) == sizeof(jword_t),
              "jshort_t class has a wrong size.");
#ifdef JCVM_INT_SUPPORTED
static_assert(sizeof(jint_t) == (2 * sizeof(jword_t)),
              "jint_t class has a wrong size.");
#endif /* JCVM_INT_SUPPORTED */
static_assert(sizeof(jreturnaddress_t) == sizeof(jword_t),
              "jint_t class has a wrong size.");
static_assert(sizeof(std::declval<jref_t &>().compact()) == sizeof(jword_t),
              "jref_t class has a wrong size.");

class Stack {
private:
  jword_t jc_stack[JCVM_STACK_SIZE];
  List<Frame> frames;

public:
  // Pushing a new frame regarding the invoked method header.
  void push_Frame(const uint8_t nargs, const uint8_t max_locals,
                  const uint8_t max_operand_stack, const uint8_t *pc)
#if !defined(JCRE_STACK_OVERFLOW_PROTECTION) && !defined(JCVM_ARRAY_SIZE_CHECK)
      noexcept
#endif
      ;

  // Popping the current frame without return value
  void pop_Frame();
  // The stack is empty? (no pushed Java Card frame)
  bool empty() noexcept;

  // Pushing a byte to the operand stack
  void push_Byte(const jbyte_t value) noexcept(
      noexcept(std::declval<Frame &>().push_Value(value)));
  // Pushing a short to the operand the stack
  void push_Short(const jshort_t value) noexcept(
      noexcept(std::declval<Frame &>().push_Value(value)));
  // Pushing an integer to the operand the stack
#ifdef JCVM_INT_SUPPORTED
  void push_Int(const jint_t value) noexcept(
      noexcept(std::declval<Frame &>().push_Value(value)));
#endif /* JCVM_INT_SUPPORTED */
  // Pushing a reference to the operand the stack
  void push_Reference(const jref_t value) noexcept(
      noexcept(std::declval<Frame &>().push_Value(value.compact())));
  // Pushing a return address element to the operand the stack
  void push_ReturnAddress(const jreturnaddress_t value) noexcept(
      noexcept(std::declval<Frame &>().push_Value(value)));

  // Popping to the trash, an untyped element
  void pop() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
  // Popping a byte from the stack
  jbyte_t pop_Byte() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
  // Popping a short from the stack
  jshort_t pop_Short() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
#ifdef JCVM_INT_SUPPORTED
  // Popping an integer from the stack
  jint_t pop_Int() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
#endif /* JCVM_INT_SUPPORTED */
  // Popping a reference from the stack
  jref_t
  pop_Reference() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
  // Popping a return address element from the stack
  jreturnaddress_t
  pop_ReturnAddress() noexcept(noexcept(std::declval<Frame &>().pop_Value()));
  // Get a pushing element which as not the last pushed element. This function
  // returns the n-th pushed word without popped it.
  jref_t get_Pushed_Element(uint16_t n)
#if !defined(JCRE_STACK_OVERFLOW_PROTECTION) && !defined(JCVM_ARRAY_SIZE_CHECK)
      noexcept
#endif
      ;

  /// Reading a local variable as a short value
  int16_t readLocal_Short(const uint8_t local_number);
  // /Reading a local variable as an integer value
#ifdef JCVM_INT_SUPPORTED
  int32_t readLocal_Int(const uint8_t local_number);
#endif /* JCVM_INT_SUPPORTED */
  /// Reading a local variable as a reference
  jref_t readLocal_Reference(const uint8_t local_number);
  /// Reading a local variable as a return address element
  jreturnaddress_t readLocal_ReturnAddress(const uint8_t local_number);

  /// Saving a short to a specific local variable
  void writeLocal_Short(const uint8_t local_number, const jshort_t value);
#ifdef JCVM_INT_SUPPORTED
  /// Saving an integer to a specific local variable
  void writeLocal_Int(const uint8_t local_number, const jint_t value);
#endif /* JCVM_INT_SUPPORTED */
  /// Saving a reference to a specific local variable
  void writeLocal_Reference(const uint8_t local_number, const jref_t value);
  /// Saving a return address element to a specific local variable
  void writeLocal_ReturnAddress(const uint8_t local_number,
                                const jreturnaddress_t value);

  /// Duplicate top operand stack words and insert below
  void dup(const uint8_t m, const uint8_t n);

  /// Swap top two operand stack words
  void swap(const uint8_t m, const uint8_t n);

  ///  Get the current PC value
  pc_t &getPC();
  /// Save PC value for jsr instruction
  uint8_t savePC() noexcept;
  /// Restore PC value for ret instruction
  pc_t &restorePC(const uint8_t index);
  /// Get the current frame
  Frame &getCurrentFrame();
};

} // namespace jcvm

#endif /* _STACK_HPP */
