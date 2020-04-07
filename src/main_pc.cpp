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

#ifdef PC_VERSION

#include "debug.hpp"
#include "ffi.h"
#include "interpretor.hpp"
#include "jc_config.h"
#include "jni.hpp"
#include "types.hpp"

#ifdef DEBUG
#include <iomanip>
#include <iostream>
#endif /* DEBUG */

#include "jc_handlers/flashmemory.hpp"
#include <algorithm>
#include <boost/program_options.hpp>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

bool isSaving = false;
uint8_t *flash = nullptr;
uint32_t flash_length = 0;
std::string flash_filename;

int main_pc(int argc, char *argv[]) {

  /** Define and parse the program options
   */
  boost::program_options::options_description desc("Options");
  desc.add_options()
#ifdef DEBUG
      ("help,h", "Print help messages")
#endif /* DEBUG */
          ("memory,m",
           boost::program_options::value<std::string>(&flash_filename)
               ->required()
               ->value_name("MEMORY_FILENAME"),
           "Flash Memory")("save,s", "Save modifications on MEMORY_FILENAME");

  boost::program_options::variables_map parameters;

  try {
    boost::program_options::store(
        boost::program_options::parse_command_line(argc, argv, desc),
        parameters); // can throw

#ifdef DEBUG

    /**
     * --help option
     */
    if (parameters.count("help")) {
      std::cout
          << "USAGE: " << argv[0] << " [OPTION] -m MEMORY_FILENAME" << std::endl
          << std::endl
          << "CHOUPI is a secure Java Card open-source implementation."
          << std::endl
          << "This proof of concept is powered by ANSSI (www.ssi.gouv.fr)."
          << std::endl
          << "Last update: " << __DATE__ << " - " << __TIME__ << std::endl
          << std::endl
          << desc << std::endl;
      return EXIT_SUCCESS;
    }

#endif /* DEBUG */

    boost::program_options::notify(parameters);

  } catch (boost::program_options::error &e) {
#ifdef DEBUG
    std::cerr << "ERROR: " << e.what() << std::endl
              << std::endl
              << "USAGE: " << argv[0] << " [OPTION] -m MEMORY_FILENAME"
              << std::endl
              << std::endl
              << "CHOUPI is a secure Java Card open-source implementation."
              << std::endl
              << "This proof of concept is powered by ANSSI (www.ssi.gouv.fr)."
              << std::endl
              << "Last update: " << __DATE__ << " - " << __TIME__ << std::endl
              << std::endl
              << desc << std::endl;
#endif /* DEBUG */
    return EXIT_FAILURE;
  }

#ifdef DEBUG
  std::cout << "Welcome to CHOUPI implementation!" << std::endl
            << "CHOUPI is a secure Java Card open-source implementation."
            << std::endl
            << "This proof of concept is powered by ANSSI (www.ssi.gouv.fr)."
            << std::endl
            << "Last update: " << __DATE__ << " - " << __TIME__ << std::endl
            << std::endl
            << "CHOUPI is starting :)" << std::endl
            << std::endl;
#endif /* DEBUG */

  auto file_memory_in = std::ifstream(flash_filename, std::ifstream::binary);
  flash = flash_pointer();

  if (file_memory_in.is_open()) {
    uint8_t *last = std::copy(std::istreambuf_iterator<char>(file_memory_in),
                              std::istreambuf_iterator<char>(), flash);
    flash_length = (last - flash);

#ifdef DEBUG
    TRACE_JCVM_ERR("Flash length = %u Byte", flash_length);
#endif /* DEBUG */
  } else {
#ifdef DEBUG
    TRACE_JCVM_ERR("ERROR: Unable to open %s", flash_filename);
#endif /* DEBUG */
    return EXIT_FAILURE;
  }

  file_memory_in.close();

  isSaving = parameters.count("save");

  // running emulator
  run_emulator();

  return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

//  The runtime_main function is called in the context 0.
int starting_jcre() {

  TRACE_JCVM_DEBUG("Starting JCRE");

  //  Call GP applet => main security domain
  uint32_t arg = (STARTING_JAVACARD_PACKAGE << 16) |
                 (STARTING_JAVACARD_CLASS << 8) | (STARTING_JAVACARD_METHOD);
  remote_call(2, arg, 0);

  if (isSaving) {
    TRACE_JCVM_DEBUG("Saving memory in FLASH_MEMORY file");

    auto flash_memory_out =
        std::ofstream(flash_filename, std::ofstream::binary);
    std::ostream_iterator<char> output(flash_memory_out);
    std::copy(flash, flash + flash_length, output);
    flash_memory_out.close();
  }

  return 0;
}
#ifdef __cplusplus
}
#endif

#endif /* PC_VERSION */
