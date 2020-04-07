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

#include "stack.hpp"
#include "jc_utils.hpp"

#include <cassert> // for check when NDEBUG is undefined.

namespace jcvm {

/**
 * Pushing a new frame regarding the invoked method header.
 *
 * @param[nargs] number of Java function parameters.
 * @param[max_locals] number of Java function locals elements without
 * parameters.
 * @param[max_operand_stack] number of max. operand stack element required
 *                           to execute this function.
 * @return void.
 */
void Stack::push_Frame(const uint8_t nargs, const uint8_t max_locals,
                       const uint8_t max_operand_stack, const uint8_t *pc)
#if !defined(JCRE_STACK_OVERFLOW_PROTECTION) && !defined(JCVM_ARRAY_SIZE_CHECK)
    noexcept
#endif
{
  jword_t *new_fp, *new_op, *new_tos, *new_eos;

  if (this->frames.empty()) { // the first frame is pushing.
    new_fp = &(this->jc_stack[0]);
  } else {

    Frame &previous_frame = this->getCurrentFrame();

#ifdef JCRE_STACK_OVERFLOW_PROTECTION

    if ((previous_frame.getTOS() - nargs) < previous_frame.getOP()) {
      // Stack underflow detected!!!!
      throw Exceptions::StackUnderflowException;
    }

#endif /* JCRE_STACK_OVERFLOW_PROTECTION */

    previous_frame.setTOS(previous_frame.getTOS() - nargs);
    new_fp = previous_frame.getTOS();
  }

  pc_t new_pc(pc);

#ifdef JCRE_STACK_OVERFLOW_PROTECTION

  if ((new_fp + nargs + max_locals + max_operand_stack) >
      &(this->jc_stack[JCVM_STACK_SIZE - 1])) {
    // Stack overflow detected!!!!
    throw Exceptions::StackOverflowException;
  }

#endif /* JCRE_STACK_OVERFLOW_PROTECTION */

  new_op = new_fp + nargs + max_locals;
  new_tos = new_op;
  new_eos = new_tos + max_operand_stack;

  this->frames.emplace_front(new_fp, new_op, new_tos, new_eos, new_pc);

  // cleaning the local variables area
  for (auto word = (new_fp + nargs); word < new_op; word++) {
    *word = 0;
  }
}

/**
 * Popping the current frame.
 */
void Stack::pop_Frame() {
  if (this->frames.empty()) {
    throw Exceptions::SecurityException;
  }

  this->frames.pop_front();
  return;
}

/**
 * The stack is empty? (no pushed Java Card frame)
 */
bool Stack::empty() noexcept { return this->frames.empty(); }

/**
 * Pushing a byte to the operand stack
 *
 * @param[value] the byte value to push.
 */
void Stack::push_Byte(const jbyte_t value) noexcept(
    noexcept(std::declval<Frame &>().push_Value(value))) {
  // The Java-language, as the C-language, propagates the sign when a cast
  // arrives. For example, the value 0xFF in byte is casted to the value
  // 0xFFFF in short, and so on.
  Frame &frame = this->getCurrentFrame();
  frame.push_Value((jword_t)value);
}

/**
 * Pushing a short to the operand the stack
 *
 * @param[value] the short value to push.
 */
void Stack::push_Short(const jshort_t value) noexcept(
    noexcept(std::declval<Frame &>().push_Value(value))) {
  Frame &frame = this->getCurrentFrame();
  frame.push_Value((jword_t)value);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Pushing an integer to the operand the stack
 *
 * @param[value] the integer value to push.
 */
void Stack::push_Int(const jint_t value) noexcept(
    noexcept(std::declval<Frame &>().push_Value(value))) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.push_Value((jword_t)INT_2_LSSHORTS(value));
  current_frame.push_Value((jword_t)INT_2_MSSHORTS(value));
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Pushing a reference to the operand the stack
 *
 * @param[value] the reference value to push.
 */
void Stack::push_Reference(const jref_t value) noexcept(
    noexcept(std::declval<Frame &>().push_Value(value.compact()))) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.push_Value(value.compact());
}

/**
 * Pushing a return address element to the operand the stack
 *
 * @param [value] the reference value to push.
 */
void Stack::push_ReturnAddress(const jreturnaddress_t value) noexcept(
    noexcept(std::declval<Frame &>().push_Value(value))) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.push_Value(value);
}

/**
 * Popping to the trash, an untyped element.
 */
void Stack::pop() noexcept(noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.pop_Value(); // The return value is ignored.
}

/**
 * Popping a byte from the stack
 *
 * @return the top of stack element as a short value.
 */
jbyte_t
Stack::pop_Byte() noexcept(noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  return (jbyte_t)current_frame.pop_Value();
}

/**
 * Popping a short from the stack
 *
 * @return the top of stack element as a short value.
 */
jshort_t
Stack::pop_Short() noexcept(noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  return (jshort_t)current_frame.pop_Value();
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Popping an integer from the stack
 *
 * @return the top of stack element as an integer value.
 */
jint_t
Stack::pop_Int() noexcept(noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  return SHORTS_TO_INT(current_frame.pop_Value(), current_frame.pop_Value());
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Popping a reference from the stack
 *
 * @return the top of stack element as a reference value.
 */
jref_t
Stack::pop_Reference() noexcept(noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  return jref_t(current_frame.pop_Value());
}

/**
 * Popping a return address element from the stack
 *
 * @return the top of stack element as a return address value.
 */
jreturnaddress_t Stack::pop_ReturnAddress() noexcept(
    noexcept(std::declval<Frame &>().pop_Value())) {
  Frame &current_frame = this->getCurrentFrame();
  return (jreturnaddress_t)current_frame.pop_Value();
}

/*
 * Get a pushing element which as not the last pushed element. This function
 * returns the n-th pushed word without popped it.
 *
 * @param[n] the n-th pushed element to return.
 * @return the n-th pushed element to return.
 */
jref_t Stack::get_Pushed_Element(uint16_t n)
#if !defined(JCRE_STACK_OVERFLOW_PROTECTION) && !defined(JCVM_ARRAY_SIZE_CHECK)
    noexcept
#endif
{
  assert(n > 0);

  Frame &current_frame = this->getCurrentFrame();
  jword_t *value = current_frame.getTOS() - n;

#ifdef JCRE_STACK_OVERFLOW_PROTECTION

  if (value < current_frame.getOP()) {
    // Stack underflow detected!!!!
    throw Exceptions::StackUnderflowException;
  }

#endif /* JCRE_STACK_OVERFLOW_PROTECTION */

  return jref_t(*value);
}

/**
 * Reading a local variable as a short value
 *
 * @return the local variable value at 'local_number' position.
 */
jshort_t Stack::readLocal_Short(const uint8_t local_number) {
  Frame &current_frame = this->getCurrentFrame();
  return (jshort_t)current_frame.readLocal_Value(local_number);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Reading a local variable as an integer value
 *
 * @return the local variable value at 'local_number' position.
 */
jint_t Stack::readLocal_Int(const uint8_t local_number) {
  Frame &current_frame = this->getCurrentFrame();
  return (jint_t)SHORTS_TO_INT(
      current_frame.readLocal_Value((uint8_t)(local_number + 1)),
      current_frame.readLocal_Value(local_number));
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Reading a local variable as a reference value
 *
 * @return the local variable value at 'local_number' position.
 */
jref_t Stack::readLocal_Reference(const uint8_t local_number) {
  Frame &current_frame = this->getCurrentFrame();
  return jref_t(current_frame.readLocal_Value(local_number));
}

/**
 * Reading a local variable as a return address value
 *
 * @return the local variable value at 'local_number' position.
 */
jreturnaddress_t Stack::readLocal_ReturnAddress(const uint8_t local_number) {
  Frame &current_frame = this->getCurrentFrame();
  return (jreturnaddress_t)current_frame.readLocal_Value(local_number);
}

/**
 * Writing a local variable as a short value
 *
 * @param[value] value to save.
 * @param[local_number] the local variable position.
 */
void Stack::writeLocal_Short(const uint8_t local_number, const jshort_t value) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.writeLocal_Value(local_number, value);
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Writing a local variable as an integer value
 *
 * @param[value] value to save.
 * @param[local_number] the local variable position.
 */
void Stack::writeLocal_Int(const uint8_t local_number, const jint_t value) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.writeLocal_Value(local_number, INT_2_LSSHORTS(value));
  current_frame.writeLocal_Value((uint8_t)(local_number + 1),
                                 INT_2_MSSHORTS(value));
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Writing a local variable as a reference
 *
 * @param[value] value to save.
 * @param[local_number] the local variable position.
 */
void Stack::writeLocal_Reference(const uint8_t local_number,
                                 const jref_t value) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.writeLocal_Value(local_number, value.compact());
}

/**
 * Writing a return address variable as a reference
 *
 * @param[value] value to save.
 * @param[local_number] the local variable position.
 */
void Stack::writeLocal_ReturnAddress(const uint8_t local_number,
                                     const jreturnaddress_t value) {
  Frame &current_frame = this->getCurrentFrame();
  current_frame.writeLocal_Value(local_number, value);
}

/**
 * Duplicate top operand stack words and insert below
 *
 * Stack:
 *   ..., wordN, ..., wordM, ..., word1 ->
 *                  ..., wordM, ..., word1, wordN, ..., wordM, ..., word1
 *
 * Description:
 *
 *   For positive values of n, the top m words on the operand stack are
 *   duplicated and the copied words are inserted n words down in the
 *   operand stack. When n equals 0, the top m words are copied and placed
 *   on top of the stack.
 *
 *   The dup_x instruction must not be used unless the ranges of words 1
 *   through m and words m+1 through n each contain either a 16-bit data
 *   type, two 16-bit data types, a 32-bit data type, a 16-bit data type and
 *   a 32-bit data type (in either order), or two 32-bit data types.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the dup instruction operates on untyped words, ignoring the types of
 *   data they contain.
 *
 * (source: A part of the Java Card Virtual Machine 3.0.5 Specification,
 *  dup_x instruction)
 */
void Stack::dup(const uint8_t m, const uint8_t n) {
  jword_t *mnpart, *old_tos;
  Frame &current_frame = this->getCurrentFrame();

#ifdef JCRE_STACK_OVERFLOW_PROTECTION

  // Checking if the operand stack may store enough words to push the result.
  if ((int16_t *)(current_frame.getTOS() + (m + n)) > current_frame.getEOS()) {
    // Stack overflow detected!!!!
    throw Exceptions::StackOverflowException;
  }

  // Checking if the operand stack has enough words to compute the result.
  if ((jword_t *)(current_frame.getTOS() - (m + n)) < current_frame.getOP()) {
    // Stack underflow detected!!!!
    throw Exceptions::StackUnderflowException;
  }

#endif /* JCRE_STACK_OVERFLOW_PROTECTION */

  // frame->tos points the next empty word from the stack
  mnpart = (jword_t *)(current_frame.getTOS() - (n + m));
  old_tos = current_frame.getTOS();

  // This loop isn't done when n = 0
  for (; mnpart < old_tos; mnpart++) {
#if false
      // XXX: this implementation is disable because the cost is
      // overweight regarding the checks done by the push_Value function
      current_frame.push_Value(*npart);
#else
    *(current_frame.getTOS()) = *mnpart;
    current_frame.setTOS(current_frame.getTOS() + 1);
#endif
  }
}

/**
 * Swap top two operand stack words
 *
 * Stack:
 *   ..., wordM+N, ..., wordM+1, wordM, ..., word1 ->
 *                     ..., wordM, ..., word1, wordM+N, ..., wordM+1
 *
 * Description:
 *
 *  Permissible values for both m and n are 1 and 2. (The values of n and m
 *  are checked in the bc_stack.c file).
 *
 *  The top m words on the operand stack are swapped with the n words
 *  immediately below.
 *
 *  The swap_x instruction must not be used unless the ranges of words 1
 *  through m and words m+1 through n each contain either a 16-bit data
 *  type, two 16-bit data types, a 32-bit data type, a 16-bit data type and
 *  a 32-bit data type (in either order), or two 32-bit data types.
 *
 * Notes:
 *
 *   Except for restrictions preserving the integrity of 32-bit data types,
 *   the swap instruction operates on untyped words, ignoring the types of
 *   data they contain.
 *
 * (source: A part of the Java Card Virtual Machine 3.0.5 Specification,
 *  swap_x instruction)
 */
void Stack::swap(const uint8_t m, const uint8_t n) {
  jword_t tmp[4];
  jword_t *bar;
  uint8_t foo, tmp_index;
  Frame &current_frame = this->getCurrentFrame();

#ifdef JCVM_INT_SUPPORTED

  /*
   * Permissible values for both m and n are 1 and 2.
   */
  if ((m == 0) || (m > 2) || (n == 0) || (n > 2))
#else  /* !JCVM_INT_SUPPORTED */

  /*
   * If a virtual machine does not support the int data type, the only
   * permissible value for both m and n is 1.
   */
  if ((m != 1) || (n != 1))
#endif /* JCVM_INT_SUPPORTED */
  {
    throw Exceptions::RuntimeException;
  }

#ifdef JCRE_STACK_OVERFLOW_PROTECTION

  // Checking if the operand stack has enough words to swap.
  if ((jword_t *)(current_frame.getTOS() - (m + n)) < current_frame.getOP()) {
    // Stack overflow detected!!!!
    throw Exceptions::SecurityException;
  }

#endif /* JCRE_STACK_OVERFLOW_PROTECTION */

  tmp_index = 0;

  // copy m word(s) from the stack to tmp array.
  for (foo = m; foo > 0; foo--) {
    tmp[tmp_index] = *((int16_t *)(current_frame.getTOS() - foo));
    tmp_index++;
  }

  // copy n word(s) from the stack to tmp array.
  for (foo = (uint8_t)(n + m); foo > m; foo--) {
    tmp[tmp_index] = *((int16_t *)(current_frame.getTOS() - foo));
    tmp_index++;
  }

  bar = (int16_t *)(current_frame.getTOS() - (n + m));

  for (foo = 0; foo < n + m; foo++) {
    *bar = tmp[foo];
    bar++;
  }

  return;
}

/**
 * Get the current PC value
 *
 * @return current PC value
 */
pc_t &Stack::getPC() {
  Frame &current_frame = this->getCurrentFrame();
  return current_frame.getPC();
}

/**
 * Save PC value for jsr instruction.
 *
 * @return the saved pc index.
 */
uint8_t Stack::savePC() noexcept {
  Frame &current_frame = this->getCurrentFrame();
  return current_frame.savePC();
}

pc_t &Stack::restorePC(const uint8_t index) {
  Frame &current_frame = this->getCurrentFrame();
  return current_frame.restorePC(index);
}

/**
 * Get the current frame.
 *
 * @return the current frame.
 */
Frame &Stack::getCurrentFrame() { return *(this->frames.begin()); }

} // namespace jcvm
