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
#include "../heap.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../jc_types/jc_array.hpp"
#include "../jc_types/jc_array_type.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Create new array
 *
 * Format:
 *   newarray
 *   atype
 *
 * Forms:
 *   newarray = 144 (0x90)
 *
 * Stack:
 *   ..., count -> ..., arrayref
 *
 * Description:
 *
 *   The count must be of type short. It is popped off the operand stack.
 *   The count represents the number of elements in the array to be created.
 *   The unsigned byte atype is a code that indicates the type of array to
 *   create. It must take one of the following values:
 *
 *   +------------+-------+
 *   | Array Type | atype |
 *   +------------+-------+
 *   | T_BOOLEAN  |    10 |
 *   | T_BYTE     |    11 |
 *   | T_SHORT    |    12 |
 *   | T_INT      |    13 |
 *   +------------+-------+
 *
 *   A new array whose components are of type atype, of length count, is
 *   allocated from the heap. A reference arrayref to this new array object
 *   is pushed onto the operand stack. All of the elements of the new array
 *   are initialized to the default initial value for its type.
 *
 * Runtime Exception:
 *
 *   If count is less than zero, the newarray instruction throws a
 *   NegativeArraySizeException.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the value of
 *   atype may not be 13 (array type = T_INT).
 */
void Bytecodes::bc_newarray() {
  jshort_t count;
  uint8_t atype;
  jref_t array_ref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();
  pc_t &pc = stack.getPC();

  atype = pc.getNextByte();

  TRACE_JCVM_DEBUG("NEWARRAY 0x%2X", atype);

  count = stack.pop_Short();

  // Check if count is > 0
  if (count < 0) {
    throw Exceptions::NegativeArraySizeException;
  }

  array_ref = heap.addArray(count, (jc_array_type)atype);
  stack.push_Reference(array_ref);

  return;
}

/**
 * Create new array of reference
 *
 * Format:
 *   anewarray
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   anewarray = 145 (0x91)
 *
 * Stack:
 *   ..., count -> ..., arrayref
 *
 * Description:
 *
 *   The count must be of type short. It is popped off the operand stack.
 *   The count represents the number of components of the array to be
 *   created. The unsigned indexbyte1 and indexbyte2 are used to construct
 *   an index into the constant pool of the current package (§3.5 Frames),
 *   where the value of the index is (indexbyte1 << 8) | indexbyte2. The
 *   item at that index in the constant pool must be of type
 *   CONSTANT_Classref (§6.8.1 CONSTANT_Classref), a reference to a class or
 *   interface type. The reference is resolved. A new array with components
 *   of that type, of length count, is allocated from the heap, and a
 *   reference arrayref to this new array object is pushed onto the operand
 *   stack. All components of the new array are initialized to null, the
 *   default value for reference types.
 *
 * Runtime Exception:
 *
 *   If count is less than zero, the anewarray instruction throws a
 *   NegativeArraySizeException.
 */
void Bytecodes::bc_anewarray() {
  uint16_t index;
  jshort_t count;
  jref_t array_ref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("ANEWARRAY 0x%2X", index);

  count = stack.pop_Short();

  // Check if count is > 0
  if (count < 0) {
    throw Exceptions::NegativeArraySizeException;
  }

  array_ref = heap.addArray(count, JAVA_ARRAY_T_REFERENCE, index);
  stack.push_Reference(array_ref);

  return;
}

/**
 * Get length of array
 *
 * Format:
 *   arraylength
 *
 * Forms:
 *   arraylength = 146 (0x92)
 *
 * Stack:
 *   ..., arrayref -> ..., length
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array. It
 *   is popped from the operand stack. The length of the array it references
 *   is determined. That length is pushed onto the top of the operand stack
 *   as a short.
 *
 * Runtime Exception:
 *
 *   If arrayref is null, the arraylength instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the arraylength instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_arraylength() {
  jref_t arrayref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("ARRAY_LENGTH");

  arrayref = stack.pop_Reference();
  auto array = heap.getArray(arrayref);

  switch (array->getType()) {
  case JAVA_ARRAY_T_BOOLEAN:
  case JAVA_ARRAY_T_BYTE:
  case JAVA_ARRAY_T_SHORT:

#ifdef JCVM_INT_SUPPORTED

  case JAVA_ARRAY_T_INT:

#endif /* JCVM_INT_SUPPORTED */

  case JAVA_ARRAY_T_REFERENCE:
    stack.push_Short((jshort_t)array->size());
    break;

  default:
    throw Exceptions::SecurityException;
  }

  return;
}

/**
 * Load reference from array
 *
 * Format:
 *   aaload
 *
 * Forms:
 *   aaload = 36 (0x24)
 *
 * Stack:
 *   ..., arrayref, index -> ..., value
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type reference. The index must be of type short. Both
 *   arrayref and index are popped from the operand stack. The reference
 *   value in the component of the array at index is retrieved and pushed
 *   onto the top of the operand stack.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, aaload throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the aaload instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 * Notes:
 *
 *   In some circumstances, the aaload instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_aaload() {
  jshort_t index;
  jref_t arrayref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("AALOAD");

  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  jref_t ref = array->getReferenceEntry(index);
  stack.push_Reference(ref);

  return;
}

/**
 * Store into reference array
 *
 * Format:
 *   aastore
 *
 * Forms:
 *   aastore = 55 (0x37)
 *
 * Stack:
 *   ..., arrayref, index, value -> ...
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type reference. The index must be of type short and
 *   the value must be of type reference. The arrayref, index and value are
 *   popped from the operand stack. The reference value is stored as the
 *   component of the array at index.
 *
 *   If the array referenced by arrayref is integrity-sensitive, its
 *   integrity is checked before the value is stored. The integrity control
 *   element is updated when the value is stored. The whole operation (value
 *   storage and the integrity control element update) is performed
 *   atomically.
 *
 *   At runtime the type of value must be confirmed to be assignment
 *   compatible with the type of the components of the array referenced by
 *   arrayref. Assignment of a value of reference type S (source) to a
 *   variable of reference type T (target) is allowed only when the type S
 *   supports all of the operations defined on type T. The detailed rules
 *   follow:
 *
 *   - If S is a class type, then:
 *       + If T is a class type, then S must be the same class as T, or
 *         S must be a subclass of T;
 *       + If T is an interface type, then S must implement interface T.
 *   - If S is an interface type[13], then:
 *       + If T is a class type, then T must be Object (§2.2.1.4
 *         Unsupported Classes);
 *       + If T is an interface type, T must be the same interface as S
 *         or a superinterface of S.
 *   - If S is an array type, namely the type SC[], that is, an array of
 *     components of type SC, then:
 *       + If T is a class type, then T must be Object.
 *       + If T is an array type, namely the type TC[], an array of
 *         components of type TC, then one of the following must be true:
 *           * TC and SC are the same primitive type (§3.1 Data Types and
 *             Values).
 *           * TC and SC are reference types[14] (§3.1 Data Types and Values)
 *             with type SC assignable to TC, by these rules.
 *       + If T is an interface type, T must be one of the interfaces
 *         implemented by arrays.
 *
 *   13: When both S and T are arrays of reference types, this algorithm is
 *   applied recursively using the types of the arrays, namely SC and TC. In
 *   the recursive call, S, which was SC in the original call, may be an
 *   interface type. This rule can only be reached in this manner.
 *   Similarly, in the recursive call, T, which was TC in the original call,
 *   may be an interface type.
 *
 *   14: This version of the Java Card virtual machine does not support
 *   multi-dimensional arrays. Therefore, neither SC or TC can be an array
 *   type.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, aastore throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the aastore instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 *   Otherwise, if arrayref is not null and the actual type of value is not
 *   assignment compatible with the actual type of the component of the
 *   array, aastore throws an ArrayStoreException.
 *
 *   Otherwise if the array referenced by arrayref is integrity-sensitive
 *   and an inconsistency is detected during the array integrity check, the
 *   aastore instruction throws a SecurityException.
 *
 * Notes:
 *
 *   In some circumstances, the aastore instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_aastore() {
  jshort_t index;
  jref_t arrayref;
  jref_t value;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("AASTORE");

  value = stack.pop_Reference();
  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  array->setReferenceEntry(index, value
#ifdef JCVM_FIREWALL_CHECKS
                           ,
                           this->context
#endif /* JCVM_FIREWALL_CHECKS */
  );

  return;
}

/**
 * Load byte or boolean from array
 *
 * Format:
 *   baload
 *
 * Forms:
 *   baload = 37 (0x25)
 *
 * Stack:
 *   ..., arrayref, index -> ..., value
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type byte or of type boolean. The index must be of
 *   type short. Both arrayref and index are popped from the operand stack.
 *   The byte value in the component of the array at index is retrieved,
 *   sign-extended to a short value, and pushed onto the top of the operand
 *   stack.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, baload throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the baload instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 * Notes:
 *
 *   In some circumstances, the baload instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_baload() {
  jshort_t index;
  jref_t arrayref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("BALOAD");

  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  stack.push_Byte(array->getByteEntry(index));

  return;
}

/**
 * Store into byte or boolean array
 *
 * Format:
 *   bastore
 *
 * Forms:
 *   bastore = 56 (0x38)
 *
 * Stack:
 *   ..., arrayref, index, value -> ...
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type byte or of type boolean. The index and value
 *   must both be of type short. The arrayref, index and value are popped
 *   from the operand stack. The short value is truncated to a byte and
 *   stored as the component of the array indexed by index.
 *
 *   If the array referenced by arrayref is integrity-sensitive, its
 *   integrity is checked before the value is stored. The integrity control
 *   element is updated when the value is stored. The whole operation (value
 *   storage and the integrity control element update) is performed
 *   atomically.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, bastore throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the bastore instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 *   Otherwise if the array referenced by arrayref is integrity-sensitive
 *   and an inconsistency is detected during the array integrity check, the
 *   bastore instruction throws a SecurityException.
 *
 * Notes:
 *
 *   In some circumstances, the bastore instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_bastore() {
  jshort_t index;
  jref_t arrayref;
  jbyte_t value;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("BASTORE");

  value = stack.pop_Byte();
  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  array->setByteEntry(index, value);

  return;
}

/**
 * Load short from array
 *
 * Format:
 *   saload
 *
 * Forms:
 *   saload = 38 (0x26)
 *
 * Stack:
 *   ..., arrayref, index -> ..., value
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type short. The index must be of type short. Both
 *   arrayref and index are popped from the operand stack. The short value
 *   in the component of the array at index is retrieved and pushed onto the
 *   top of the operand stack.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, saload throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the saload instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 * Notes:
 *
 *   In some circumstances, the saload instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_saload() {
  jshort_t index;
  jref_t arrayref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("SALOAD");

  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  stack.push_Short(array->getShortEntry(index));

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Load int from array
 *
 * Format:
 *   iaload
 *
 * Forms:
 *   iaload = 39 (0x27)
 *
 * Stack:
 *   ..., arrayref, index -> ..., value.word1, value.word2
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type int. The index must be of type short. Both
 *   arrayref and index are popped from the operand stack. The int value in
 *   the component of the array at index is retrieved and pushed onto the
 *   top of the operand stack.
 *
 * Runtime Exceptions:
 *
 *   If arrayref is null, iaload throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the iaload instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 * Notes:
 *
 *   In some circumstances, the iaload instruction may throw a
 *   SecurityException if the current context §3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the iaload
 *   instruction will not be available.
 */
void Bytecodes::bc_iaload() {
  jshort_t index;
  jref_t arrayref;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("IALOAD");

  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  stack.push_Int(array->getIntEntry(index));

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Store into short array
 *
 * Format:
 *   sastore
 *
 * Forms:
 *   sastore = 57 (0x39)
 *
 * Stack:
 *   ..., arrayref, index, value -> ...
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type short. The index and value must both be of type
 *   short. The arrayref, index and value are popped from the operand stack.
 *   The short value is stored as the component of the array indexed by
 *   index.
 *
 *   If the array referenced by arrayref is integrity-sensitive, its
 *   integrity is checked before the value is stored. The integrity control
 *   element is updated when the value is stored. The whole operation (value
 *   storage and the integrity control element update) is performed
 *   atomically.
 *
 * Runtime Exception:
 *
 *   If arrayref is null, sastore throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the sastore instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 *   Otherwise if the array referenced by arrayref is integrity-sensitive
 *   and an inconsistency is detected during the array integrity check, the
 *   sastore instruction throws a SecurityException.
 *
 * Notes:
 *
 *   In some circumstances, the sastore instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_sastore() {
  jshort_t index;
  jref_t arrayref;
  jshort_t value;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("SASTORE");

  value = stack.pop_Short();
  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  array->setShortEntry(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Store into int array
 *
 * Format:
 *   iastore
 *
 * Forms:
 *   iastore = 58 (0x3a)
 *
 * Stack:
 *   ..., arrayref, index, value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   The arrayref must be of type reference and must refer to an array whose
 *   components are of type int. The index must be of type short and value
 *   must be of type int. The arrayref, index and value are popped from the
 *   operand stack. The int value is stored as the component of the array
 *   indexed by index.
 *
 *   If the array referenced by arrayref is integrity-sensitive, its
 *   integrity is checked before the value is stored. The integrity control
 *   element is updated when the value is stored. The whole operation (value
 *   storage and the integrity control element update) is performed
 *   atomically.
 *
 * Runtime Exception:
 *
 *   If arrayref is null, iastore throws a NullPointerException.
 *
 *   Otherwise, if index is not within the bounds of the array referenced by
 *   arrayref, the iastore instruction throws an
 *   ArrayIndexOutOfBoundsException.
 *
 *   Otherwise if the array referenced by arrayref is integrity-sensitive
 *   and an inconsistency is detected during the array integrity check, the
 *   iastore instruction throws a SecurityException.
 *
 * Notes:
 *
 *   In some circumstances, the iastore instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the array referenced by arrayref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the iastore
 *   instruction will not be available.
 */
void Bytecodes::bc_iastore() {
  jshort_t index;
  jref_t arrayref;
  jint_t value;
  Context &context = this->context;
  Heap &heap = context.getHeap();
  Stack &stack = context.getStack();

  TRACE_JCVM_DEBUG("IASTORE");

  value = stack.pop_Int();
  index = stack.pop_Short();
  arrayref = stack.pop_Reference();

  // Check if index is >= 0
  if (index < 0) {
    throw Exceptions::ArrayIndexOutOfBoundsException;
  }

  auto array = heap.getArray(arrayref);
  array->setIntEntry(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
