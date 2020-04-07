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

#include "../context.hpp"
#include "../debug.hpp"
#include "../heap.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../jc_handlers/jc_class.hpp"
#include "../jc_handlers/jc_cp.hpp"
#include "../jc_types/jc_array.hpp"
#include "../jc_types/jc_instance.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Create new object
 *
 * Format:
 *   new
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   new = 143 (0x8f)
 *
 * Stack:
 *   ...-> ..., objectref
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The item at that
 *   index in the constant pool must be of type CONSTANT_Classref (§6.8.1
 *   CONSTANT_Classref), a reference to a class or interface type. The
 *   reference is resolved and must result in a class type (it must not
 *   result in an interface type). Memory for a new instance of that class
 *   is allocated from the heap, and the instance variables of the new
 *   object are initialized to their default initial values. The objectref,
 *   a reference to the instance, is pushed onto the operand stack.
 *
 * Notes:
 *
 *   The new instruction does not completely create a new instance; instance
 *   creation is not completed until an instance initialization method has
 *   been invoked on the uninitialized instance.
 *
 */
void Bytecodes::bc_new() {
  Context &context = this->context;
  Stack &stack = context.getStack();
  Heap &heap = context.getHeap();
  pc_t &pc = stack.getPC();

  uint16_t index = pc.getNextShort();

  TRACE_JCVM_DEBUG("NEW 0x%02X", index);

  ConstantPool_Handler cp(context.getCurrentPackage());
  auto instantiated_class = cp.getClassInformation(index);

  jref_t objectref =
      heap.addInstance(instantiated_class.first, instantiated_class.second);
  stack.push_Reference(objectref);

  return;
}

/**
 * Check if two object are type-compatitble
 *
 * @param[objectref]
 * @param[atype] Element object type in case of array.
 * @param[index] constant pool classref to compare to objecref
 */
jbool_t Bytecodes::docheck(const jref_t objectref, const uint8_t atype,
                           const jc_cp_offset_t index) {
  Context &context = this->context;
  Heap &heap = context.getHeap();

  if (objectref.isNullPointer()) {
    throw Exceptions::SecurityException;
  }

  if (atype == 0) {
    auto instance = heap.getInstance(objectref);

    std::pair<jpackage_ID_t, jclass_index_t> type_in_classinfo =
        ConstantPool_Handler(instance->getPackageID())
            .getClassInformation(instance->getClassIndex());
    auto type_in_ref = std::make_pair(
        type_in_classinfo.first,
        reinterpret_cast<const uint8_t *>(
            ConstantPool_Handler(type_in_classinfo.first)
                .getClassFromClassIndex(type_in_classinfo.second)));

    auto type_out_classref =
        ConstantPool_Handler(context.getCurrentPackage()).getClassRef(index);
    auto [type_out_package, type_out_class] =
        ConstantPool_Handler(context.getCurrentPackage())
            .classref2class(type_out_classref);

    auto type_out_ref = std::make_pair(
        type_out_package, reinterpret_cast<const uint8_t *>(type_out_class));

    return Class_Handler::docheckcast(type_in_ref, type_out_ref);

  } else {
    auto array = heap.getArray(objectref);

    auto array_type = static_cast<jc_array_type>(atype);

    if (array->getType() != array_type) {
      return FALSE;
    }

    switch (array_type) {
    case jc_array_type::JAVA_ARRAY_T_BOOLEAN:
    case jc_array_type::JAVA_ARRAY_T_BYTE:
    case jc_array_type::JAVA_ARRAY_T_SHORT:
#ifdef JCVM_INT_SUPPORTED
    case jc_array_type::JAVA_ARRAY_T_INT:
#endif /* JCVM_INT_SUPPORTED */
    {

#ifdef JCVM_DYNAMIC_CHECKS_CAP

      // Security check
      if (index != 0) {
        throw Exceptions::SecurityException;
      }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

      // Ok, the cast is allowed.
      return TRUE;
    }

    case jc_array_type::JAVA_ARRAY_T_REFERENCE: {
      auto type_in = array->getReferenceType();
      auto type_out = index;

      auto current_package = context.getCurrentPackage();
      ConstantPool_Handler constantpool_handler(current_package);

      auto type_in_ref = constantpool_handler.getClassRef(type_in);
      auto type_out_ref = constantpool_handler.getClassRef(type_out);

      return Class_Handler::docheckcast(
          constantpool_handler.resolveClassref(type_in_ref),
          constantpool_handler.resolveClassref(type_out_ref));
    }
    }
  }

  throw Exceptions::SecurityException;
}

/**
 * Check whether object is of given type
 *
 * Format:
 *   checkcast
 *   atype
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   checkcast = 148 (0x94)
 *
 * Stack:
 *   ..., objectref -> ..., objectref
 *
 * Description:
 *
 *   The unsigned byte atype is a code that indicates if the type against
 *   which the object is being checked is an array type or a class type. It
 *   must take one of the following values or zero:
 *
 *   +-------------+-------+
 *   | Array Type  | atype |
 *   +-------------+-------+
 *   | T_BOOLEAN   |    10 |
 *   | T_BYTE      |    11 |
 *   | T_SHORT     |    12 |
 *   | T_INT       |    13 |
 *   | T_REFERENCE |    14 |
 *   +-------------+-------+
 *
 *   If the value of atype is 10, 11, 12, or 13, the values of the
 *   indexbyte1 and indexbyte2 must be zero, and the value of atype
 *   indicates the array type against which to check the object. Otherwise
 *   the unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The item at that
 *   index in the constant pool must be of type CONSTANT_Classref (§6.8.1
 *   CONSTANT_Classref), a reference to a class or interface type. The
 *   reference is resolved. If the value of atype is 14, the object is
 *   checked against an array type that is an array of object references of
 *   the type of the resolved class. If the value of atype is zero, the
 *   object is checked against a class or interface type that is the
 *   resolved class.
 *
 *   The objectref must be of type reference. If objectref is null or can be
 *   cast to the specified array type or the resolved class or interface
 *   type, the operand stack is unchanged; otherwise the checkcast
 *   instruction throws a ClassCastException.
 *
 *   The following rules are used to determine whether an objectref that is
 *   not null can be cast to the resolved type: if S is the class of the
 *   object referred to by objectref and T is the resolved class, array or
 *   interface type, checkcast determines whether objectref can be cast to
 *   type T as follows:
 *
 *   - If S is a class type, then:
 *       + If T is a class type, then S must be the same class as T, or S
 *         must be a subclass of T;
 *       + If T is an interface type, then S must implement interface T.
 *   - If S is an interface type[15], then:
 *       + If T is a class type, then T must be Object (§2.2.1.4
 *         Unsupported Classes);
 *       + If T is an interface type, T must be the same interface as S
 *         or a superinterface of S.
 *   - If S is an array type, namely the type SC[], that is, an array of
 *     components of type SC, then:
 *       + If T is a class type, then T must be Object.
 *       + If T is an array type, namely the type TC[], an array of
 *         components of type TC, then one of the following must be
 *         true:
 *           * TC and SC are the same primitive type (§3.1 Data Types
 *             and Values).
 *           * TC and SC are reference types[16] (§3.1 Data Types and
 *             Values) with type SC assignable to TC, by these rules.
 *       + If T is an interface type, T must be one of the interfaces
 *         implemented by arrays.
 *
 *   15: When both S and T are arrays of reference types, this algorithm is
 *   applied recursively using the types of the arrays, namely SC and TC. In
 *   the recursive call, S, which was SC in the original call, may be an
 *   interface type. This rule can only be reached in this manner. Similarly
 *   ,in the recursive call, T, which was TC in the original call, may be an
 *   interface type.
 *
 *   16: This version of the Java Card virtual machine specification does
 *   not support multi-dimensional arrays. Therefore, neither SC or TC can
 *   be an array type.
 *
 * Runtime Exception:
 *
 *   If objectref cannot be cast to the resolved class, array, or interface
 *   type, the checkcast instruction throws a ClassCastException.
 *
 * Notes:
 *
 *   The checkcast instruction is fundamentally very similar to the
 *   instanceof instruction. It differs in its treatment of null, its
 *   behavior when its test fails (checkcast throws an exception, instanceof
 *   pushes a result code), and its effect on the operand stack.
 *
 *   In some circumstances, the checkcast instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the value of
 *   atype may not be 13 (array type = T_INT).
 *
 */
void Bytecodes::bc_checkcast() {
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  uint8_t atype = pc.getNextByte();
  uint16_t index = pc.getNextShort();
  jref_t objectref = stack.pop_Reference();

  TRACE_JCVM_DEBUG("CHECKCAST 0x%02X 0x%02X", atype, index);

  if ((objectref.isNullPointer() == FALSE) &&
      (this->docheck(objectref, atype, index) == FALSE)) {
    throw Exceptions::ClassCastException;
  }

  stack.push_Reference(objectref);

  return;
}

/**
 * Determine if object is of given type
 *
 * Format:
 *   instanceof
 *   atype
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   instanceof = 149 (0x95)
 *
 * Stack:
 *   ..., objectref -> ..., result
 *
 * Description:
 *
 *   The unsigned byte atype is a code that indicates if the type against
 *   which the object is being checked is an array type or a class type. It
 *   must take one of the following values or zero:
 *
 *   +-------------+-------+
 *   | Array Type  | atype |
 *   +-------------+-------+
 *   | T_BOOLEAN   |    10 |
 *   | T_BYTE      |    11 |
 *   | T_SHORT     |    12 |
 *   | T_INT       |    13 |
 *   | T_REFERENCE |    14 |
 *   +-------------+-------+
 *
 *   If the value of atype is 10, 11, 12, or 13, the values of the
 *   indexbyte1 and indexbyte2 must be zero, and the value of atype
 *   indicates the array type against which to check the object. Otherwise
 *   the unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The item at that
 *   index in the constant pool must be of type CONSTANT_Classref (§6.8.1
 *   CONSTANT_Classref), a reference to a class or interface type. The
 *   reference is resolved. If the value of atype is 14, the object is
 *   checked against an array type that is an array of object references of
 *   the type of the resolved class. If the value of atype is zero, the
 *   object is checked against a class or interface type that is the
 *   resolved class.
 *
 *   The objectref must be of type reference. It is popped from the operand
 *   stack. If objectref is not null and is an instance of the resolved
 *   class, array or interface, the instanceof instruction pushes a short
 *   result of 1 on the operand stack. Otherwise it pushes a short result of
 *   0.
 *
 *   The following rules are used to determine whether an objectref that is
 *   not null is an instance of the resolved type: if S is the class of the
 *   object referred to by objectref and T is the resolved class, array or
 *   interface type, instanceof determines whether objectref is an instance
 *   of T as follows:
 *
 *   - If S is a class type, then:
 *       + If T is a class type, then S must be the same class as T, or S
 *         must be a subclass of T;
 *       + If T is an interface type, then S must implement interface T.
 *   - If S is an interface type[20], then:
 *       + If T is a class type, then T must be Object (§2.2.1.4
 *         Unsupported Classes);
 *       + If T is an interface type, T must be the same interface as S or
 *         a superinterface of S.
 *   - If S is an array type, namely the type SC[], that is, an array of
 *     components of type SC, then:
 *       + If T is a class type, then T must be Object.
 *       + If T is an array type, namely the type TC[], an array of
 *         components of type TC, then one of the following must be true:
 *           * TC and SC are the same primitive type (§3.1 Data Types and
 *             Values).
 *           * TC and SC are reference types[21] (§3.1 Data Types and
 *             Values) with type SC assignable to TC, by these rules.
 *       + If T is an interface type, T must be one of the interfaces
 *         implemented by arrays.
 *
 *   20: When both S and T are arrays of reference types, this algorithm is
 *   applied recursively using the types of the arrays, namely SC and TC. In
 *   the recursive call, S, which was SC in the original call, may be an
 *   interface type. This rule can only be reached in this manner.
 *   Similarly, in the recursive call, T, which was TC in the original call,
 *   may be an interface type.
 *
 *   21: This version of the Java Card virtual machine specification does
 *   not support multi-dimensional arrays. Therefore, neither SC or TC can
 *   be an array type.
 *
 * Notes:
 *
 *   The instanceof instruction is fundamentally very similar to the
 *   checkcast instruction. It differs in its treatment of null, its
 *   behavior when its test fails (checkcast throws an exception, instanceof
 *   pushes a result code), and its effect on the operand stack.
 *
 *   In some circumstances, the instanceof instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the value of
 *   atype may not be 13 (array type = T_INT).
 */
void Bytecodes::bc_instanceof() {
  Stack &stack = this->context.getStack();
  pc_t &pc = stack.getPC();

  uint8_t atype = pc.getNextByte();
  uint16_t index = pc.getNextShort();
  jref_t objectref = stack.pop_Reference();

  TRACE_JCVM_DEBUG("INSTANCEOF 0x%02X 0x%02X", atype, index);

  jbool_t result = docheck(objectref, atype, index);
  stack.push_Byte(result);

  return;
}

} // namespace jcvm
