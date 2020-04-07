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

#ifndef _CONTEXT_HPP
#define _CONTEXT_HPP

#include "heap.hpp"
#include "jc_config.h"
#include "jc_handlers/package.hpp"
#include "jcvm_types/list.hpp"
#include "stack.hpp"
#include "types.hpp"

namespace jcvm {

class Context {
private:
  /// Applet ID.
  japplet_ID_t applet_ID;
  /// Current Java Card stack.
  Stack stack;
  /// Linked-list where the executed Packages ID is stored. The Head of the
  /// linked-list is the current executed package ID.
  List<jpackage_ID_t> packagesID;
  /// Context's heap
  Heap heap;

public:
  /// Default constructor
  Context(const uint8_t appletID, const jpackage_ID_t packageID) noexcept;
  /// Get the context ID.
  jpackage_ID_t getCurrentPackageID() noexcept;
  /// Get applet ID
  japplet_ID_t getAppletID() noexcept;
  /// Get context Java Card stack.
  Stack &getStack() noexcept;
  /// Get context heap.
  Heap &getHeap() noexcept;
  /// Get current current package.
  Package getCurrentPackage();
  /// Shift context package ID
  void changePackageID(const uint8_t packageID) noexcept;
  /// Back to the previous package ID.
  void backToPreviousPackageID() noexcept;
};

} // namespace jcvm

#endif /* _CONTEXT_HPP */
