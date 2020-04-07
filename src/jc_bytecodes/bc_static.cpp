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
#include "../jc_cap/jc_cap_cp.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../jc_handlers/jc_cp.hpp"
#include "../jc_handlers/jc_import.hpp"
#include "../jc_handlers/jc_static.hpp"
#include "../jc_types/jc_array.hpp"
#include "../jc_utils.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Get static reference field from class
 *
 * Format:
 *   getstatic_a
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getstatic_a = 123 (0x7b)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the field offset.
 *   The item is resolved, determining the class field. The value of the
 *   class field is fetched. If the value is of type byte or boolean, it is
 *   sign-extended to a short. The value is pushed onto the operand stack.
 */
void Bytecodes::bc_getstatic_a() {
  uint16_t index;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  ConstantPool_Handler cp(context.getCurrentPackage());
  Heap &heap = this->context.getHeap();

  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETSTATIC_A 0x%04X", index);

  jc_cap_static_field_ref_info cp_entry = cp.getStaticFieldRefInfo(index);

  jpackage_ID_t packageID;
  uint8_t fieldNumber;

  if (IS_CP_INTERNAL_REF(cp_entry.static_field_ref)) {
    packageID = this->context.getCurrentPackageID();
    fieldNumber = NTOHS(cp_entry.static_field_ref.internal_ref.offset);
  } else {
    jc_cap_external_ref external_ref = cp_entry.static_field_ref.external_ref;

    /// Searching the Package number in the flash.
    Import_Handler imp(context.getCurrentPackage());
    auto package_info =
        imp.getPackageAID(CLEAR_BYTE_MSB(external_ref.package_token));
    auto package_index = imp.getPackageIndex(package_info);

    packageID = package_index;

    /// Looking for the static field nomber in the package.
    auto export_comp = Package(package_index).getCap().getExport();

#if defined(JCVM_DYNAMIC_CHECKS_CAP) & defined(JCVM_ARRAY_SIZE_CHECK)

    if (export_comp->class_count <= external_ref.class_token) {
      throw Exceptions::SecurityException;
    }

#endif /* defined (JCVM_DYNAMIC_CHECKS_CAP) & defined (JCVM_ARRAY_SIZE_CHECK)  \
        */

    auto exported_class = export_comp->classexport(external_ref.class_token);
    auto static_field_offsets = exported_class.static_field_offsets();
    const uint16_t static_field_offset =
        static_field_offsets[external_ref.token];
    fieldNumber = static_field_offset;
  }

  fs::Tag tag = FlashMemory_Handler::getStaticFieldTag(packageID, fieldNumber);

  jref_t static_field =
      FlashMemory_Handler::getPersistentField_Reference(tag, heap);

  stack.push_Reference(static_field);

  return;
}

/**
 * Get static byte field from class
 *
 * Format:
 *   getstatic_b
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getstatic_b = 124 (0x7c)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the field offset.
 *   The item is resolved, determining the class field. The value of the
 *   class field is fetched. If the value is of type byte or boolean, it is
 *   sign-extended to a short. The value is pushed onto the operand stack.
 */
void Bytecodes::bc_getstatic_b() {
  uint16_t index;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETSTATIC_B 0x%04X", index);

  auto value = static_handler.getPersistentByte(index);
  stack.push_Byte(value);

  return;
}

/**
 * Get static short field from class
 *
 * Format:
 *   getstatic_s
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getstatic_s = 125 (0x7d)
 *
 * Stack:
 *   ... -> ..., value
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the field offset.
 *   The item is resolved, determining the class field. The value of the
 *   class field is fetched. If the value is of type byte or boolean, it is
 *   sign-extended to a short. The value is pushed onto the operand stack.
 */
void Bytecodes::bc_getstatic_s() {
  uint16_t index;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETSTATIC_S 0x%04X", index);

  auto value = static_handler.getPersistentShort(index);
  stack.push_Short(value);

  return;
}

#ifdef JCVM_INT_SUPPORTED

/**
 * Get static int field from class
 *
 * Format:
 *   getstatic_i
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getstatic_i = 126 (0x7e)
 *
 * Stack:
 *   ... -> ..., value.word1, value.word2
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the field offset.
 *   The item is resolved, determining the class field. The value of the
 *   class field is fetched. If the value is of type byte or boolean, it is
 *   sign-extended to a short. The value is pushed onto the operand stack.
 *
 * Note:
 *
 *   If a virtual machine does not support the int data type, the
 *   getstatic_i instruction will not be available.
 */
void Bytecodes::bc_getstatic_i() {
  uint16_t index;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("GETSTATIC_I 0x%04X", index);

  auto value = static_handler.getPersistentInt(index);
  stack.push_Int(value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

/**
 * Set static reference field in class
 *
 * Format:
 *   putstatic_a
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putstatic_a = 127 (0x7f)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field. If the field is final, it must be declared in the current
 *   class.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the class field. The
 *   value is popped from the operand stack. If the field is of type byte or
 *   type boolean, the value is truncated to a byte. The field is set to the
 *   value.
 *
 * Notes:
 *
 *   In some circumstances, the putstatic_a instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   owning context (§3.4 Contexts) of the object being stored in the field.
 *   The exact circumstances when the exception will be thrown are specified
 *   in Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition.
 */
void Bytecodes::bc_putstatic_a() {
  uint16_t index;
  jref_t value;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUTSTATIC_A 0x%04X", index);

  value = stack.pop_Reference();

  // TODO: TO IMPLEMENTS
  // static_handler.setPersistentReference(index, value);
  throw Exceptions::NotYetImplemented;

  return;
}

/**
 * Get static byte field from class
 *
 * Format:
 *   getstatic_b
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   getstatic_b = 128 (0x80)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the field offset.
 *   The item is resolved, determining the class field. The value of the
 *   class field is fetched. If the value is of type byte or boolean, it is
 *   sign-extended to a short. The value is pushed onto the operand stack.
 */
void Bytecodes::bc_putstatic_b() {
  uint16_t index;
  jbyte_t value;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUTSTATIC_B 0x%04X", index);

  value = stack.pop_Byte();

  static_handler.setPersistentByte(index, value);

  return;
}

/**
 * Set static short field in class
 *
 * Format:
 *   putstatic_s
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putstatic_s = 129 (0x81)
 *
 * Stack:
 *   ..., value -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field. If the field is final, it must be declared in the current
 *   class.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the class field. The
 *   value is popped from the operand stack. If the field is of type byte or
 *   type boolean, the value is truncated to a byte. The field is set to the
 *   value.
 */
void Bytecodes::bc_putstatic_s() {
  uint16_t index;
  jshort_t value;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUTSTATIC_S 0x%04X", index);

  value = stack.pop_Short();
  static_handler.setPersistentShort(index, value);

  return;
}

#ifdef JCVM_INT_SUPPORTED
/**
 * Set static int field in class
 *
 * Format:
 *   putstatic_i
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   putstatic_i = 130 (0x82)
 *
 * Stack:
 *   ..., value.word1, value.word2 -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at the index must be of type CONSTANT_StaticFieldref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static field. If the field is final, it must be declared in the current
 *   class.
 *
 *   The width of a class field is determined by the field type specified in
 *   the instruction. The item is resolved, determining the class field. The
 *   value is popped from the operand stack. If the field is of type byte or
 *   type boolean, the value is truncated to a byte. The field is set to the
 *   value.
 *
 * Notes:
 *
 *   If a virtual machine does not support the int data type, the
 *   putstatic_i instruction will not be available.
 */
void Bytecodes::bc_putstatic_i() {
  uint16_t index;
  jint_t value;

  Stack &stack = this->context.getStack();
  Static_Handler static_handler(context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  index = pc.getNextShort();

  TRACE_JCVM_DEBUG("PUTSTATIC_I 0x%04X", index);

  value = stack.pop_Int();
  static_handler.setPersistentInt(index, value);

  return;
}
#endif /* JCVM_INT_SUPPORTED */

} // namespace jcvm
