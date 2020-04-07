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

#ifndef _JC_INTERPRETOR_HPP
#define _JC_INTERPRETOR_HPP

#include "context.hpp"
#include "exceptions.hpp"
#include "jc_config.h"
#include "jcvm_types/list.hpp"
#include "types.hpp"

namespace jcvm {

class Interpretor {
public:
  /// Default constructor.
  Interpretor(
      const japplet_ID_t appletID, const jpackage_ID_t selectedPackageID,
      const uint8_t selectedClass, const uint8_t method,
      bool isStaticMethod) noexcept(noexcept(std::declval<List<Context> &>()
                                                 .push_back(std::declval<
                                                            Context &>())));

  /// Run the Java Card Interpretor.
  void run() noexcept; // All exceptions must be handling there.

  /// Get the current context
  Context &getCurrentContext() noexcept(
      noexcept(std::declval<List<Context> &>().at(std::declval<uint8_t &>())));

  void startJCVMException(Exceptions);

private:
  /// List of Java Card contexts.
  List<Context> contexts;
  /// Class and method where the interpretor start.
  uint8_t startingClass, startingMethod;
  bool isStaticStatingMethod;
};

} // namespace jcvm

#endif /* _JC_INTERPRETOR_HPP */
