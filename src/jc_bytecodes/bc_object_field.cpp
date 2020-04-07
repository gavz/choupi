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
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Fetch reference from object
 *
 * Format:
 *   getfield_a
 *   index
 *
 * Forms:
 *   getfield_a = 131 (0x83)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned index is used as an index into the constant
 *   pool of the current package (§3.5 Frames). The constant pool item at
 *   the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset 17 . The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_a instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_a instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_a() {
  jref_t objectref;
  uint8_t index;
  jref_t ref;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_A 0x%02X", index);

  objectref = stack.pop_Reference();
  auto instance = heap.getInstance(objectref);
  ref = instance->getField_Reference(index);
  stack.push_Reference(ref);

  return;
}

/**
 * Fetch byte from object
 *
 * Format:
 *   getfield_b
 *   index
 *
 * Forms:
 *   getfield_b = 132 (0x84)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned index is used as an index into the constant
 *   pool of the current package (§3.5 Frames). The constant pool item at the
 *   index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset 17 . The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_b instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_b instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_b() {
  jref_t objectref;
  uint8_t index;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_B 0x%02X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Byte(index);

  stack.push_Byte(value);

  return;
}

/**
 * Fetch short from object
 *
 * Format:
 *   getfield_s
 *   index
 *
 * Forms:
 *   getfield_b = 133 (0x85)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned index is used as an index into the constant
 *   pool of the current package (§3.5 Frames). The constant pool item at
 *   the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset 17 . The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_s instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_s instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_s() {
  jref_t objectref;
  uint8_t index;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_S 0x%02X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Short(index);

  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Fetch int from object
 *
 * Format:
 *   getfield_i
 *   index
 *
 * Forms:
 *   getfield_i = 134 (0x86)
 *
 * Stack:
 *   ..., objectref -> ..., value.word1, value.word2
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned index is used as an index into the constant
 *   pool of the current package (§3.5 Frames). The constant pool item at the
 *   index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset 17 . The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_i instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_i instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the getfield_i
 *   instruction will not be available.
 */
void Bytecodes::bc_getfield_i() {
  jref_t objectref;
  uint8_t index;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_I 0x%02X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Int(index);

  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Set reference field in object
 *
 * Format:
 *   putfield_a
 *   index
 *
 * Forms:
 *   putfield_a = 135 (0x87)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[22]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   22: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_a instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_a instruction may throw a
 *   SecurityException if the current context §3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 */
void Bytecodes::bc_putfield_a() {
  jref_t objectref;
  uint8_t index;
  jref_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUTFIELD_A 0x%02X", index);

  value = stack.pop_Reference();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Reference(index, value);

  return;
}

/**
 * Set byte field in object
 *
 * Format:
 *   putfield_b
 *   index
 *
 * Forms:
 *   putfield_b = 136 (0x88)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[22]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   22: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_b instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_b instruction may throw a
 *   SecurityException if the current context §3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 */
void Bytecodes::bc_putfield_b() {
  jref_t objectref;
  uint8_t index;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUTFIELD_B 0x%02X", index);

  value = stack.pop_Byte();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Byte(index, value);

  return;
}

/**
 * Set short field in object
 *
 * Format:
 *   putfield_s
 *   index
 *
 * Forms:
 *   putfield_s = 137 (0x89)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[22]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   22: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_s instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_s instruction may throw a
 *   SecurityException if the current context §3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 */
void Bytecodes::bc_putfield_s() {
  jref_t objectref;
  uint8_t index;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUTFIELD_S 0x%02X", index);

  value = stack.pop_Short();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Short(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set int field in object
 *
 * Format:
 *   putfield_i
 *   index
 *
 * Forms:
 *   putfield_i = 138 (0x8a)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[22]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   22: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_i instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_i instruction may throw a
 *   SecurityException if the current context §3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the putfield_i
 *   instruction will not be available.
 *
 */
void Bytecodes::bc_putfield_i() {
  jref_t objectref;
  uint8_t index;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUTFIELD_I 0x%02X", index);

  value = stack.pop_Int();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Int(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Fetch reference field from object (wide index)
 *
 * Format:
 *   getfield_a_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getfield_a_w = 169 (0xa9)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned indexbyte1 and indexbyte2 are used to
 *   construct an index into the constant pool of the current package (§3.5
 *   Frames), where the value of the index is (indexbyte1 << 8) |
 *   indexbyte2. The constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token. The item must resolve to a field of type
 *   reference.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[19]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   19: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_b_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_a_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_a_w() {
  jref_t objectref;
  uint16_t index;
  jref_t ref;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETFIELD_A_W 0x%04X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  ref = instance->getField_Reference(index);

  stack.push_Reference(ref);

  return;
}

/**
 * Fetch byte field from object (wide index)
 *
 * Format:
 *   getfield_b_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getfield_b_w = 170 (0xaa)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned indexbyte1 and indexbyte2 are used to
 *   construct an index into the constant pool of the current package (§3.5
 *   Frames), where the value of the index is (indexbyte1 << 8) |
 *   indexbyte2. The constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token. The item must resolve to a field of type
 *   reference.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[19]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   19: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_b_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_b_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_b_w() {
  jref_t objectref;
  uint16_t index;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETFIELD_B_W 0x%04X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Byte(index);

  stack.push_Byte(value);

  return;
}

/**
 * Fetch short field from object (wide index)
 *
 * Format:
 *   getfield_s_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getfield_s_w = 171 (0xab)
 *
 * Stack:
 *   ..., objectref -> ..., value
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned indexbyte1 and indexbyte2 are used to
 *   construct an index into the constant pool of the current package (§3.5
 *   Frames), where the value of the index is (indexbyte1 << 8) |
 *   indexbyte2. The constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token. The item must resolve to a field of type
 *   reference.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[19]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   19: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_s_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_s_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_s_w() {
  jref_t objectref;
  uint16_t index;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETFIELD_S_W 0x%04X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Short(index);

  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Fetch int field from object (wide index)
 *
 * Format:
 *   getfield_i_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getfield_i_w = 172 (0xac)
 *
 * Stack:
 *   ..., objectref -> ..., value.word1, value.word2
 *
 * Description:
 *
 *   The objectref, which must be of type reference, is popped from the
 *   operand stack. The unsigned indexbyte1 and indexbyte2 are used to
 *   construct an index into the constant pool of the current package (§3.5
 *   Frames), where the value of the index is (indexbyte1 << 8) |
 *   indexbyte2. The constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token. The item must resolve to a field of type
 *   reference.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[19]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   19: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_i_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_i_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 *
 *   If a virtual machine does not support the int data type, the
 *   getfield_i_w instruction will not be available.
 */
void Bytecodes::bc_getfield_i_w() {
  jref_t objectref;
  uint16_t index;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETFIELD_I_W 0x%04X", index);

  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  value = instance->getField_Int(index);

  stack.push_Int(value);

  return;
}

#endif /* JCVM_INT_SUPPORTED */

/**
 * Fetch reference field from current object
 *
 * Format:
 *   getfield_a_this
 *   index
 *
 * Forms:
 *   getfield_a_this = 173 (0xad)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The currently executing method must be an instance method. The local
 *   variable at index 0 must contain a reference objectref to the currently
 *   executing method's this parameter. The unsigned index is used as an
 *   index into the constant pool of the current package (§3.5 Frames). The
 *   constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[18]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   18: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_a_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_a_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_a_this() {
  jref_t objectref;
  uint8_t index;
  jref_t ref;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_A_THIS 0x%02X", index);

  /*
   * To obtain the this reference, the JCVM specification says that "The
   * local variable at index 0 must contain a reference objectref to the
   * currently executing method's this parameter."
   */
  objectref = stack.readLocal_Reference(0);
  auto instance = heap.getInstance(objectref);
  ref = instance->getField_Reference(index);
  stack.push_Reference(ref);

  return;
}

/**
 * Fetch byte field from current object
 *
 * Format:
 *   getfield_b_this
 *   index
 *
 * Forms:
 *   getfield_b_this = 174 (0xae)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The currently executing method must be an instance method. The local
 *   variable at index 0 must contain a reference objectref to the currently
 *   executing method's this parameter. The unsigned index is used as an
 *   index into the constant pool of the current package (§3.5 Frames). The
 *   constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[18]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   18: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_b_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_b_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_b_this() {
  jref_t objectref;
  uint8_t index;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_B_THIS 0x%02X", index);

  /*
   * To obtain the this reference, the JCVM specification says that "The
   * local variable at index 0 must contain a reference objectref to the
   * currently executing method's this parameter."
   */
  objectref = stack.readLocal_Reference(0);
  auto instance = heap.getInstance(objectref);
  value = instance->getField_Byte(index);
  stack.push_Byte(value);

  return;
}

/**
 * Fetch short field from current object
 *
 * Format:
 *   getfield_s_this
 *   index
 *
 * Forms:
 *   getfield_s_this = 175 (0xaf)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The currently executing method must be an instance method. The local
 *   variable at index 0 must contain a reference objectref to the currently
 *   executing method's this parameter. The unsigned index is used as an
 *   index into the constant pool of the current package (§3.5 Frames). The
 *   constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[18]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   18: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_s_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_s_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_s_this() {
  jref_t objectref;
  uint8_t index;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_S_THIS 0x%02X", index);

  /*
   * To obtain the this reference, the JCVM specification says that "The
   * local variable at index 0 must contain a reference objectref to the
   * currently executing method's this parameter."
   */
  objectref = stack.readLocal_Reference(0);
  auto instance = heap.getInstance(objectref);
  value = instance->getField_Short(index);
  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Fetch int field from current object
 *
 * Format:
 *   getfield_i_this
 *   index
 *
 * Forms:
 *   getfield_i_this = 176 (0xb0)
 *
 * Stack:
 *   ... -> ..., value.word1, value.word2
 *
 * Description:
 *
 *   The currently executing method must be an instance method. The local
 *   variable at index 0 must contain a reference objectref to the currently
 *   executing method's this parameter. The unsigned index is used as an
 *   index into the constant pool of the current package (§3.5 Frames). The
 *   constant pool item at the index must be of type
 *   CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[18]. The value at that offset into the class instance
 *   referenced by objectref is fetched. If the value is of type byte or
 *   type boolean, it is sign-extended to a short. The value is pushed onto
 *   the operand stack.
 *
 *   18: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the getfield_i_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the getfield_i_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_getfield_i_this() {
  jref_t objectref;
  uint8_t index;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("GETFIELD_I_THIS 0x%02X", index);

  /*
   * To obtain the this reference, the JCVM specification says that "The
   * local variable at index 0 must contain a reference objectref to the
   * currently executing method's this parameter."
   */
  objectref = stack.readLocal_Reference(0);
  auto instance = heap.getInstance(objectref);
  value = instance->getField_Int(index);
  stack.push_Int(value);

  return;
}

#endif /* JCVM_INT_SUPPORTED */

/**
 * Set reference field in object (wide index)
 *
 * Format:
 *   putfield_a_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putfield_a_w = 177 (0xb1)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[24]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   24: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance. If a
 *   virtual machine does not support the int data type, the putfield_i_w
 *   instruction will not be available.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_a_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_a_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_a_w() {
  jref_t objectref;
  uint16_t index;
  jref_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUFIELD_A_W 0x%04X", index);

  value = stack.pop_Reference();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Reference(index, value);

  return;
}

/**
 * Set byte field in object (wide index)
 *
 * Format:
 *   putfield_b_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putfield_b_w = 178 (0xb2)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[24]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   24: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance. If a
 *   virtual machine does not support the int data type, the putfield_i_w
 *   instruction will not be available.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_b_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_b_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_b_w() {
  jref_t objectref;
  uint16_t index;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUFIELD_B_W 0x%04X", index);

  value = stack.pop_Byte();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Byte(index, value);

  return;
}

/**
 * Set short field in object (wide index)
 *
 * Format:
 *   putfield_s_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putfield_s_w = 179 (0xb3)
 *
 * Stack:
 *   ..., objectref, value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[24]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   24: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance. If a
 *   virtual machine does not support the int data type, the putfield_i_w
 *   instruction will not be available.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_s_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_s_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_s_w() {
  jref_t objectref;
  uint16_t index;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUFIELD_S_W 0x%04X", index);

  value = stack.pop_Short();

  objectref = stack.pop_Reference();
  auto instance = heap.getInstance(objectref);

  instance->setField_Short(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set int field in object (wide index)
 *
 * Format:
 *   putfield_i_w
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putfield_i_w = 180 (0xb4)
 *
 * Stack:
 *   ..., objectref, value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_InstanceFieldref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[24]. The objectref, which must be of type reference,
 *   and the value are popped from the operand stack. If the field is of
 *   type byte or type boolean, the value is truncated to a byte. The field
 *   at the offset from the start of the object referenced by objectref is
 *   set to the value.
 *
 *   24: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance. If a
 *   virtual machine does not support the int data type, the putfield_i_w
 *   instruction will not be available.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_i_w instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_i_w instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_i_w() {
  jref_t objectref;
  uint16_t index;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUFIELD_I_W 0x%04X", index);

  value = stack.pop_Int();
  objectref = stack.pop_Reference();

  auto instance = heap.getInstance(objectref);
  instance->setField_Int(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Set reference field in current object
 *
 * Format:
 *   putfield_a_this
 *   index
 *
 * Forms:
 *   putfield_a_this = 181 (0xb5)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The currently executing method must be an instance method that was
 *   invoked using the invokevirtual, invokeinterface or invokespecial
 *   instruction. The local variable at index 0 must contain a reference
 *   objectref to the currently executing method's this parameter. The
 *   unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[23]. The value is popped from the operand stack. If
 *   the field is of type byte or type boolean, the value is truncated to a
 *   byte. The field at the offset from the start of the object referenced
 *   by objectref is set to the value.
 *
 *   23: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_a_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_a_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_a_this() {
  uint8_t index;
  jref_t objectref, value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUFIELD_A_THIS 0x%02X", index);

  /*
   * To obtain the this reference, the JCVM specification says that "The
   * local variable at index 0 must contain a reference objectref to the
   * currently executing method's this parameter."
   */
  objectref = stack.readLocal_Reference(0);
  value = stack.pop_Reference();
  auto instance = heap.getInstance(objectref);
  instance->setField_Reference(index, value);

  return;
}

/**
 * Set byte field in current object
 *
 * Format:
 *   putfield_b_this
 *   index
 *
 * Forms:
 *   putfield_b_this = 182 (0xb6)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The currently executing method must be an instance method that was
 *   invoked using the invokevirtual, invokeinterface or invokespecial
 *   instruction. The local variable at index 0 must contain a reference
 *   objectref to the currently executing method's this parameter. The
 *   unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[23]. The value is popped from the operand stack. If
 *   the field is of type byte or type boolean, the value is truncated to a
 *   byte. The field at the offset from the start of the object referenced
 *   by objectref is set to the value.
 *
 *   23: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_b_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_b_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_b_this() {
  uint8_t index;
  jref_t objectref;
  jbyte_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUFIELD_B_THIS 0x%02X", index);

  objectref = stack.readLocal_Reference(0);

  value = stack.pop_Byte();
  auto instance = heap.getInstance(objectref);
  instance->setField_Byte(index, value);

  return;
}

/**
 * Set short field in current object
 *
 * Format:
 *   putfield_s_this
 *   index
 *
 * Forms:
 *   putfield_s_this = 183 (0xb7)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The currently executing method must be an instance method that was
 *   invoked using the invokevirtual, invokeinterface or invokespecial
 *   instruction. The local variable at index 0 must contain a reference
 *   objectref to the currently executing method's this parameter. The
 *   unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[23]. The value is popped from the operand stack. If
 *   the field is of type byte or type boolean, the value is truncated to a
 *   byte. The field at the offset from the start of the object referenced
 *   by objectref is set to the value.
 *
 *   23: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_s_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_s_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_s_this() {
  uint8_t index;
  jref_t objectref;
  jshort_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUFIELD_S_THIS 0x%02X", index);

  objectref = stack.readLocal_Reference(0);
  value = stack.pop_Short();

  auto instance = heap.getInstance(objectref);
  instance->setField_Short(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set int field in current object
 *
 * Format:
 *   putfield_i_this
 *   index
 *
 * Forms:
 *   putfield_i_this = 184 (0xb8)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   The currently executing method must be an instance method that was
 *   invoked using the invokevirtual, invokeinterface or invokespecial
 *   instruction. The local variable at index 0 must contain a reference
 *   objectref to the currently executing method's this parameter. The
 *   unsigned index is used as an index into the constant pool of the
 *   current package (§3.5 Frames). The constant pool item at the index must
 *   be of type CONSTANT_InstanceFieldref (§6.8.2 CONSTANT_InstanceFieldref,
 *   CONSTANT_VirtualMethodref, and CONSTANT_SuperMethodref), a reference to
 *   a class and a field token.
 *
 *   The class of objectref must not be an array. If the field is protected,
 *   and it is a member of a superclass of the current class, and the field
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class. If the field is final, it must be declared in the
 *   current class.
 *
 *   The width of a field in a class instance is determined by the field
 *   type specified in the instruction. The item is resolved, determining
 *   the field offset[23]. The value is popped from the operand stack. If
 *   the field is of type byte or type boolean, the value is truncated to a
 *   byte. The field at the offset from the start of the object referenced
 *   by objectref is set to the value.
 *
 *   23: The offset may be computed by adding the field token value to the
 *   size of an instance of the immediate superclass. However, this method
 *   is not required by this specification. A Java Card virtual machine may
 *   define any mapping from token value to offset into an instance.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the putfield_i_this instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the putfield_i_this instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object referenced by objectref.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putfield_i_this() {
  uint8_t index;
  jref_t objectref;
  jint_t value;
  Stack &stack = this->context.getStack();
  Heap &heap = this->context.getHeap();
  pc_t &pc = stack.getPC();

  index = pc.getNextByte();

  TRACE_JCVM_DEBUG("PUFIELD_I_THIS 0x%02X", index);

  objectref = stack.readLocal_Reference(0);
  value = stack.pop_Int();

  auto instance = heap.getInstance(objectref);
  instance->setField_Int(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
