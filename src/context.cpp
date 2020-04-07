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

namespace jcvm {

/**
 * Default constructor
 *
 * @param[packageID] Starting package ID.
 */
Context::Context(const japplet_ID_t appletID,
                 const jpackage_ID_t packageID) noexcept
    : applet_ID(appletID), stack(), packagesID(), heap(appletID) {
  this->packagesID.push_front(packageID);
}

/**
 * Get current context ID.
 *
 * @return current context ID
 */
jpackage_ID_t Context::getCurrentPackageID() noexcept {
  return *(this->packagesID.cbegin());
}

/**
 * Get applet class ID.
 *
 * @return current applet class ID
 */
jpackage_ID_t Context::getAppletID() noexcept { return this->applet_ID; }

/**
 * Get context Java Card stack.
 *
 * @return context Java Card stack.
 */
Stack &Context::getStack() noexcept { return this->stack; }

/**
 * Get context heap.
 *
 * @return context Java Card stack.
 */
Heap &Context::getHeap() noexcept { return this->heap; }

/**
 * Get current package.
 *
 * @return current package.
 */
Package Context::getCurrentPackage() {
  return Package(this->getCurrentPackageID());
}

/**
 * Shift the context package ID. This function is call when an invoke
 * instruction is invoked. There, the security context ID does not change but
 * the executed package changed.
 *
 * @param[packageID] new executed package ID.
 */
void Context::changePackageID(const jpackage_ID_t packageID) noexcept {
  this->packagesID.push_front(packageID);
}

/**
 * Shift the context package ID to the caller one. This function is call when
 * a return instruction is executed. There, the security context ID does not
 * change but the executed package changed.
 */
void Context::backToPreviousPackageID() noexcept {
  this->packagesID.pop_front();
}

} // namespace jcvm
