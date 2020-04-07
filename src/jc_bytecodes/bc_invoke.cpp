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

#include "../jc_config.h"

#include "../types.hpp"

#include "../context.hpp"
#include "../debug.hpp"
#include "../exceptions.hpp"
#include "../heap.hpp"
#include "../jc_handlers/flashmemory.hpp"
#include "../jc_handlers/jc_class.hpp"
#include "../jc_handlers/jc_cp.hpp"
#include "../jc_handlers/jc_export.hpp"
#include "../jc_handlers/jc_import.hpp"
#include "../jc_handlers/jc_method.hpp"
#include "../jc_handlers/package.hpp"
#include "../stack.hpp"
#include "bytecodes.hpp"

namespace jcvm {

/**
 * Invoke instance method; dispatch based on class
 *
 * Format:
 *   invokevirtual
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   invokevirtual = 139 (0x8b)
 *
 * Stack:
 *   ..., objectref, [arg1, [arg2 ...]] -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at that index must be of type CONSTANT_VirtualMethodref (§6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to a class and a virtual method
 *   token. The specified method is resolved. The method must not be <init>,
 *   an instance initialization method, or <clinit>, a class or interface
 *   initialization method. Finally, if the resolved method is protected,
 *   and it is a member of a superclass of the current class, and the method
 *   is not declared in the same package as the current class, then the
 *   class of objectref must be either the current class or a subclass of
 *   the current class.
 *
 *   The resolved method reference includes an unsigned index into the
 *   method table of the resolved class and an unsigned byte nargs that must
 *   not be zero.
 *
 *   The objectref must be of type reference. The index is an unsigned byte
 *   that is used as an index into the method table of the class of the type
 *   of objectref. If the objectref is an array type, then the method table
 *   of class Object (§2.2.1.4 Unsupported Classes) is used. The table entry
 *   at that index includes a direct reference to the method's code and
 *   modifier information.
 *
 *   The objectref must be followed on the operand stack by nargs - 1 words of
 *   arguments, where the number of words of arguments and the type and order of
 *   the values they represent must be consistent with those of the selected
 *   instance method.
 *
 *   The nargs - 1 words of arguments and objectref are popped from the
 *   operand stack. A new stack frame is created for the method being
 *   invoked, and objectref and the arguments are made the values of its
 *   first nargs words of local variables, with objectref in local variable
 *   0, arg1 in local variable 1, and so on. The new stack frame is then
 *   made current, and the Java Card virtual machine pc is set to the opcode
 *   of the first instruction of the method to be invoked. Execution
 *   continues with the first instruction of the method.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the invokevirtual instruction throws a
 *   NullPointerException.
 *
 *   In some circumstances, the invokevirtual instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   context (§3.4 Contexts) of the object referenced by objectref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition. If the current context is not the
 *   object's context and the Java Card RE permits invocation of the method,
 *   the invokevirtual instruction will cause a context switch (§3.4
 *   Contexts) to the object's context before invoking the method, and will
 *   cause a return context switch to the previous context when the invoked
 *   method returns.
 *
 */
void Bytecodes::bc_invokevirtual() {
  Stack &stack = this->context.getStack();
  ConstantPool_Handler cp_handler(this->context.getCurrentPackage());
  Method_Handler method_handler(this->context);
  Class_Handler class_handler(this->context.getCurrentPackage());
  pc_t &pc = stack.getPC();

  uint16_t index = pc.getNextShort();

  TRACE_JCVM_DEBUG("INVOKEVIRTUAL 0x%04X", index);

  auto virtual_method_ref_info = cp_handler.getVirtualMethodRef(index);
  auto method_offset = class_handler.getMethodOffset(virtual_method_ref_info);

  // Calling the method and updating PC value
  method_handler.setPackage(method_offset.first);
  method_handler.callVirtualMethod(method_offset.second);

  // checking if the this reference is non NULL
  jref_t objectref = stack.readLocal_Reference((uint8_t)0);

  if (objectref.isNullPointer()) {
    throw Exceptions::NullPointerException;
  }

  auto instance = context.getHeap().getInstance(objectref);

  return;
}

/**
 * Invoke instance method; special handling for superclass, private, and
 * instance initialization method invocations
 *
 * Format:
 *   invokespecial
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   invokespecial = 140 (0x8c)
 *
 * Stack:
 *   ..., objectref, [arg1, [arg2 ...]] -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. If the invoked
 *   method is a private instance method or an instance initialization
 *   method, the constant pool item at index must be of type
 *   CONSTANT_StaticMethodref (§6.8.3 CONSTANT_StaticFieldref and
 *   CONSTANT_StaticMethodref), a reference to a statically linked instance
 *   method. If the invoked method is a superclass method, the constant pool
 *   item at index must be of type CONSTANT_SuperMethodref (6.8.2
 *   CONSTANT_InstanceFieldref, CONSTANT_VirtualMethodref, and
 *   CONSTANT_SuperMethodref), a reference to an instance method of a
 *   specified class. The reference is resolved. The resolved method must
 *   not be <clinit>, a class or interface initialization method. If the
 *   method is <init>, an instance initialization method, then the method
 *   must only be invoked once on an uninitialized object, and before the
 *   first backward branch following the execution of the new instruction
 *   that allocated the object. Finally, if the resolved method is
 *   protected, and it is a member of a superclass of the current class, and
 *   the method is not declared in the same package as the current class,
 *   then the class of objectref must be either the current class or a
 *   subclass of the current class.
 *
 *   The resolved method includes the code for the method, an unsigned byte
 *   nargs that must not be zero, and the method's modifier information.
 *
 *   The objectref must be of type reference, and must be followed on the
 *   operand stack by nargs - 1 words of arguments, where the number of
 *   words of arguments and the type and order of the values they represent
 *   must be consistent with those of the selected instance method.
 *
 *   The nargs - 1 words of arguments and objectref are popped from the
 *   operand stack. A new stack frame is created for the method being
 *   invoked, and objectref and the arguments are made the values of its
 *   first nargs words of local variables, with objectref in local variable
 *   0, arg1 in local variable 1, and so on. The new stack frame is then
 *   made current, and the Java Card virtual machine pc is set to the opcode
 *   of the first instruction of the method to be invoked. Execution
 *   continues with the first instruction of the method.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the invokespecial instruction throws a
 *   NullPointerException.
 */
void Bytecodes::bc_invokespecial() {
  Context &context = this->context;
  Stack &stack = context.getStack();
  ConstantPool_Handler cp_handler(context.getCurrentPackage());
  Method_Handler method_handler(context);
  Class_Handler class_handler(context.getCurrentPackage());

  uint16_t method_offset;
  pc_t &pc = stack.getPC();

  uint16_t index = pc.getNextShort();

  TRACE_JCVM_DEBUG("INVOKESPECIAL 0x%04X", index);

  auto cp_entry = cp_handler.getCPEntry(index);

  switch (cp_entry.tag) {
  case JC_CP_TAG_CONSTANT_STATICMETHODREF:
    /*
     * The invoked method is a private instance method or an instance
     * initialization method.
     */
    {
      jc_cap_static_method_ref_info method_ref =
          cp_entry.info.static_method_ref_info;

      if (IS_CP_INTERNAL_REF(method_ref.static_method_ref)) {
        method_offset = HTONS(method_ref.static_method_ref.internal_ref.offset);
      } else { // Is external static method ref
        Import_Handler imported(context.getCurrentPackage());
        const jc_cap_package_info *package_aid = imported.getPackageAID(
            method_ref.static_method_ref.external_ref.package_token & 0x7F);

        Package exported_package(imported.getPackageIndex(package_aid));
        Export_Handler export_handler(exported_package);

        method_offset = export_handler.getExportedStaticMethodOffset(
            method_ref.static_method_ref.external_ref.class_token,
            method_ref.static_method_ref.external_ref.token);
        method_handler.setPackage(exported_package);
      }
    }
    break;

  case JC_CP_TAG_CONSTANT_SUPERMETHODREF: {
    /*
     * The invoked method is a superclass method.
     */
    auto virtual_method_ref_info = cp_handler.getVirtualMethodRef(index);

#ifdef JCVM_DYNAMIC_CHECKS_CAP

    /*
     * The class referenced in the CONSTANT_SuperMethodref_info structure must
     * always be internal to the class that defines the method that contains
     * the Java language-level super invocation. The class must be defined in
     * this package.
     */
    if (virtual_method_ref_info.class_ref.isExternalClassRef()) {
      // TODO
      throw Exceptions::SecurityException;
    }

#endif /* JCVM_DYNAMIC_CHECKS_CAP */

    auto method = class_handler.getMethodOffset(virtual_method_ref_info);
    method_handler.setPackage(method.first);
    method_offset = method.second;
  } break;

  default:
    // NOTE: Wrong invokestatic method type
    throw Exceptions::SecurityException;
    break;
  }

  //  Calling the method
  method_handler.callVirtualMethod(method_offset);

  // checking if the this reference is non NULL
  jref_t objectref = stack.readLocal_Reference((uint8_t)0);

  if (objectref.isNullPointer()) {
    // NOTE: Manipulated objectref is null
    throw Exceptions::NullPointerException;
  }

  // auto instance = context.getHeap().getInstance(objectref);

  // instance->setInitialized(true);

  return;
}

/**
 * Invoke a class (static) method
 *
 * Format:
 *   invokestatic
 *   indexbyte1
 *   indexbyte2
 *
 * Forms:
 *   invokestatic = 141 (0x8d)
 *
 * Stack:
 *   ..., [arg1, [arg2 ...]] -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at that index must be of type CONSTANT_StaticMethodref (§6.8.3
 *   CONSTANT_StaticFieldref and CONSTANT_StaticMethodref), a reference to a
 *   static method. The method must not be <init>, an instance
 *   initialization method, or <clinit>, a class or interface initialization
 *   method. It must be static, and therefore cannot be abstract.
 *
 *   The resolved method includes the code for the method, an unsigned byte
 *   nargs that may be zero, and the method's modifier information.
 *
 *   The operand stack must contain nargs words of arguments, where the
 *   number of words of arguments and the type and order of the values they
 *   represent must be consistent with those of the resolved method.
 *
 *   The nargs words of arguments are popped from the operand stack. A new
 *   stack frame is created for the method being invoked, and the words of
 *   arguments are made the values of its first nargs words of local
 *   variables, with arg1 in local variable 0, arg2 in local variable 1, and
 *   so on. The new stack frame is then made current, and the Java Card
 *   virtual machine pc is set to the opcode of the first instruction of the
 *   method to be invoked. Execution continues with the first instruction of
 *   the method.
 *
 */
void Bytecodes::bc_invokestatic() {
  Context &context = this->context;
  Stack &stack = context.getStack();
  ConstantPool_Handler cp_handler(context.getCurrentPackage());
  Method_Handler method_handler(context);
  Class_Handler class_handler(context.getCurrentPackage());

  uint16_t method_offset;
  pc_t &pc = stack.getPC();

  uint16_t index = pc.getNextShort();

  TRACE_JCVM_DEBUG("INVOKESTATIC 0x%04X", index);

  auto cp_entry = cp_handler.getCPEntry(index);

  if (cp_entry.tag != JC_CP_TAG_CONSTANT_STATICMETHODREF) {
    throw Exceptions::SecurityException;
  }

  jc_cap_static_method_ref_info method_ref =
      cp_entry.info.static_method_ref_info;

  if (IS_CP_INTERNAL_REF(method_ref.static_method_ref)) {
    method_offset = method_ref.static_method_ref.internal_ref.offset
                    // remove handler_count element's size
                    - sizeof(jc_cap_method_component::handler_count);
  } else { // Is external static method ref
    Import_Handler imported(context.getCurrentPackage());
    const jc_cap_package_info *package_aid = imported.getPackageAID(
        method_ref.static_method_ref.external_ref.package_token & 0x7F);

    Package exported_package(imported.getPackageIndex(package_aid));
    Export_Handler export_handler(exported_package);

    method_offset = export_handler.getExportedStaticMethodOffset(
        method_ref.static_method_ref.external_ref.class_token,
        method_ref.static_method_ref.external_ref.token);

    method_handler.setPackage(exported_package);
  }

  // Calling the method
  method_handler.callStaticMethod(method_offset);

  return;
}

/**
 * Invoke interface method
 *
 * Format:
 *   invokeinterface
 *   nargs
 *   indexbyte1
 *   indexbyte2
 *   method
 *
 * Forms:
 *   invokeinterface = 142 (0x8e)
 *
 * Stack:
 *   ..., objectref, [arg1, [arg2 ...]] -> ...
 *
 * Description:
 *
 *   The unsigned indexbyte1 and indexbyte2 are used to construct an index
 *   into the constant pool of the current package (§3.5 Frames), where the
 *   value of the index is (indexbyte1 << 8) | indexbyte2. The constant pool
 *   item at that index must be of type CONSTANT_Classref (§6.8.1
 *   CONSTANT_Classref), a reference to an interface class. The specified
 *   interface is resolved.
 *
 *   The nargs operand is an unsigned byte that must not be zero.
 *
 *   The method operand is an unsigned byte that is the interface method
 *   token for the method to be invoked. The interface method must not be
 *   <init> or an instance initialization method.
 *
 *   The object-ref must be of type reference and must be followed on the
 *   operand stack by nargs - 1 words of arguments. The number of words of
 *   arguments and the type and order of the values they represent must be
 *   consistent with those of the selected interface method.
 *
 *   The interface table of the class of the type of objectref is
 *   determined. If objectref is an array type, then the interface table of
 *   class Object (§2.2.1.4 Unsupported Classes) is used. The interface
 *   table is searched for the resolved interface. The result of the search
 *   is a table that is used to map the method token to a index.
 *
 *   The index is an unsigned byte that is used as an index into the method
 *   table of the class of the type of objectref. If the objectref is an
 *   array type, then the method table of class Object is used. The table
 *   entry at that index includes a direct reference to the method's code
 *   and modifier information.
 *
 *   The nargs - 1 words of arguments and objectref are popped from the
 *   operand stack. A new stack frame is created for the method being
 *   invoked, and objectref and the arguments are made the values of its
 *   first nargs words of local variables, with objectref in local variable
 *   0, arg1 in local variable 1, and so on. The new stack frame is then
 *   made current, and the Java Card virtual machine pc is set to the opcode
 *   of the first instruction of the method to be invoked. Execution
 *   continues with the first instruction of the method.
 *
 * Runtime Exception:
 *
 *   If objectref is null, the invokeinterface instruction throws a
 *   NullPointerException.
 *
 * Notes:
 *
 *   In some circumstances, the invokeinterface instruction may throw a
 *   SecurityException if the current context (§3.4 Contexts) is not the
 *   context (§3.4 Contexts) of the object referenced by objectref. The
 *   exact circumstances when the exception will be thrown are specified in
 *   Chapter 6 of the Runtime Environment Specification, Java Card 3
 *   Platform, v3.0.5, Classic Edition. If the current context is not the
 *   object's context and the Java Card RE permits invocation of the method,
 *   the invokeinterface instruction will cause a context switch (§3.4
 *   Contexts) to the object's context before invoking the method, and will
 *   cause a return context switch to the previous context when the invoked
 *   method returns.
 *
 */
void Bytecodes::bc_invokeinterface() {
  Context &context = this->context;
  Stack &stack = context.getStack();
  ConstantPool_Handler cp_handler(context.getCurrentPackage());
  Method_Handler method_handler(context);
  Class_Handler class_handler(context.getCurrentPackage());

  pc_t &pc = stack.getPC();

  TRACE_JCVM_DEBUG("INVOKEINTERFACE");

  uint8_t nargs = pc.getNextByte();
  uint16_t index = pc.getNextShort();
  uint8_t method = pc.getNextByte();

  if (nargs == 0) {
    throw Exceptions::SecurityException;
  }

  auto interface_ref = cp_handler.getClassRef(index);

  // nargs-th arguments should be popped to access the objectref.
  jref_t objectref = stack.get_Pushed_Element(nargs);

  if (objectref.isNullPointer()) {
    throw Exceptions::NullPointerException;
  }

  if (objectref.isArray()) { // Is an array
    // class variable must point to Object class.
    jref_t thisref = stack.readLocal_Reference((uint8_t)0);
    auto instance = context.getHeap().getInstance(thisref);
    auto classref = ConstantPool_Handler(instance->getPackageID())
                        .getClassRefFromClassIndex(instance->getClassIndex());
    auto method_offset = class_handler.getImplementedInterfaceMethodOffset(
        classref, interface_ref, method, true);
    // Calling the method
    method_handler.setPackage(method_offset.first);
    method_handler.callVirtualMethod(method_offset.second);

  } else { // is an interface
    auto instance = context.getHeap().getInstance(objectref);

    auto classref = ConstantPool_Handler(instance->getPackageID())
                        .getClassRefFromClassIndex(instance->getClassIndex());

    auto method_offset = class_handler.getImplementedInterfaceMethodOffset(
        classref, interface_ref, method);
    // Calling the method
    method_handler.setPackage(method_offset.first);
    method_handler.callVirtualMethod(method_offset.second);
  }

  return;
}

} // namespace jcvm
