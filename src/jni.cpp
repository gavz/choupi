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

#include "context.hpp"
#include "exceptions.hpp"
#include "jc_types/jc_array.hpp"
#include "jc_types/jc_array_type.hpp"
#include "jc_types/jref_t.hpp"
#include "types.hpp"

namespace jcvm {
jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayCopyRepack(
    jref_t, jshort_t, jshort_t, jref_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
};

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayCopyRepackNonAtomic(
    jref_t, jshort_t, jshort_t, jref_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayFillGeneric(
    jref_t, jshort_t, jshort_t, jref_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayFillGenericNonAtomic(
    jref_t, jshort_t, jshort_t, jref_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbyte_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayCompareGeneric(
    jref_t, jshort_t, jref_t, jshort_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_arrayFindGeneric(
    jref_t, jshort_t, std::shared_ptr<JC_Array>, jbyte_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbool_t fr_gouv_ssi_nativeimpl_NativeImplementation_selectingApplet() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbyte_t fr_gouv_ssi_nativeimpl_NativeImplementation_isTransient(jref_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

std::shared_ptr<JC_Array>
fr_gouv_ssi_nativeimpl_NativeImplementation_makeTransientBooleanArray(jshort_t,
                                                                      jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

std::shared_ptr<JC_Array>
fr_gouv_ssi_nativeimpl_NativeImplementation_makeTransientByteArray(jshort_t,
                                                                   jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

std::shared_ptr<JC_Array>
fr_gouv_ssi_nativeimpl_NativeImplementation_makeTransientShortArray(jshort_t,
                                                                    jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

std::shared_ptr<JC_Array>
fr_gouv_ssi_nativeimpl_NativeImplementation_makeTransientObjectArray(jshort_t,
                                                                     jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jref_t fr_gouv_ssi_nativeimpl_NativeImplementation_makeGlobalArray(jbyte_t,
                                                                   jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jref_t fr_gouv_ssi_nativeimpl_NativeImplementation_getAID() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_beginTransaction() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_abortTransaction() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_commitTransaction() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbyte_t fr_gouv_ssi_nativeimpl_NativeImplementation_getTransactionDepth() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_getUnusedCommitCapacity() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_getMaxCommitCapacity() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jref_t fr_gouv_ssi_nativeimpl_NativeImplementation_getPreviousContextAID() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t
fr_gouv_ssi_nativeimpl_NativeImplementation_getAvailableMemory(jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_getAvailableMemory(
    std::shared_ptr<JC_Array>, jshort_t, jshort_t, jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jref_t
fr_gouv_ssi_nativeimpl_NativeImplementation_getAppletShareableInterfaceObject(
    jref_t, jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbool_t
fr_gouv_ssi_nativeimpl_NativeImplementation_isObjectDeletionSupported() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_requestObjectDeletion() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbyte_t fr_gouv_ssi_nativeimpl_NativeImplementation_getAssignedChannel() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbool_t fr_gouv_ssi_nativeimpl_NativeImplementation_isAppletActive(jref_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

void fr_gouv_ssi_nativeimpl_NativeImplementation_assertIntegrity(jref_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbool_t
fr_gouv_ssi_nativeimpl_NativeImplementation_isIntegritySensitive(jref_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jbool_t
fr_gouv_ssi_nativeimpl_NativeImplementation_isIntegritySensitiveArraysSupported() {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jref_t fr_gouv_ssi_nativeimpl_NativeImplementation_makeIntegritySensitiveArray(
    jbyte_t, jbyte_t, jshort_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

jshort_t fr_gouv_ssi_nativeimpl_NativeImplementation_clearArray(jref_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

std::shared_ptr<JC_Array>
fr_gouv_ssi_nativeimpl_NativeImplementation_makeTransientIntArray(jshort_t,
                                                                  jbyte_t) {
  // TODO: to implement;
  throw Exceptions::NotYetImplemented;
}

} // namespace jcvm
