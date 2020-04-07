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

#ifndef _JC_BYTECODES_HPP
#define _JC_BYTECODES_HPP

#include "../context.hpp"
#include "../jc_config.h"
#include "../types.hpp"

namespace jcvm {

class Bytecodes {
private:
  /// Current context
  Context &context;

public:
  // Default constructor
  Bytecodes(Context &context) noexcept : context(context){};

  // decode a bytecode
  auto decode(const uint8_t value) -> void (Bytecodes::*)();

  /// do checkcast
  jbool_t docheck(const jref_t objectref, const uint8_t atype,
                  const jc_cp_offset_t index);

  void bc_nop();         /* 0x00 */
  void bc_aconst_null(); /* 0x01 */
  void bc_sconst_m1();   /* 0x02 */
  void bc_sconst_0();    /* 0x03 */
  void bc_sconst_1();    /* 0x04 */
  void bc_sconst_2();    /* 0x05 */
  void bc_sconst_3();    /* 0x06 */
  void bc_sconst_4();    /* 0x07 */
  void bc_sconst_5();    /* 0x08 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iconst_m1(); /* 0x09 */
  void bc_iconst_0();  /* 0x0a */
  void bc_iconst_1();  /* 0x0b */
  void bc_iconst_2();  /* 0x0c */
  void bc_iconst_3();  /* 0x0d */
  void bc_iconst_4();  /* 0x0e */
  void bc_iconst_5();  /* 0x0f */
#endif                 /* JCVM_INT_SUPPORTED */

  void bc_bspush(); /* 0x10 */
  void bc_sspush(); /* 0x11 */

#ifdef JCVM_INT_SUPPORTED
  void bc_bipush(); /* 0x12 */
  void bc_sipush(); /* 0x13 */
  void bc_iipush(); /* 0x14 */
#endif              /* JCVM_INT_SUPPORTED */

  void bc_aload(); /* 0x15 */
  void bc_sload(); /* 0x16 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iload(); /* 0x17 */
#endif             /* JCVM_INT_SUPPORTED */

  void bc_aload_0(); /* 0x18 */
  void bc_aload_1(); /* 0x19 */
  void bc_aload_2(); /* 0x1a */
  void bc_aload_3(); /* 0x1b */
  void bc_sload_0(); /* 0x1c */
  void bc_sload_1(); /* 0x1d */
  void bc_sload_2(); /* 0x1e */
  void bc_sload_3(); /* 0x1f */

#ifdef JCVM_INT_SUPPORTED
  void bc_iload_0(); /* 0x20 */
  void bc_iload_1(); /* 0x21 */
  void bc_iload_2(); /* 0x22 */
  void bc_iload_3(); /* 0x23 */
#endif               /* JCVM_INT_SUPPORTED */

  void bc_aaload(); /* 0x24 */
  void bc_baload(); /* 0x25 */
  void bc_saload(); /* 0x26 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iaload(); /* 0x27 */
#endif              /* JCVM_INT_SUPPORTED */

  void bc_astore(); /* 0x28 */
  void bc_sstore(); /* 0x29 */

#ifdef JCVM_INT_SUPPORTED
  void bc_istore(); /* 0x2a */
#endif              /* JCVM_INT_SUPPORTED */

  void bc_astore_0(); /* 0x2b */
  void bc_astore_1(); /* 0x2c */
  void bc_astore_2(); /* 0x2d */
  void bc_astore_3(); /* 0x2e */
  void bc_sstore_0(); /* 0x2f */
  void bc_sstore_1(); /* 0x30 */
  void bc_sstore_2(); /* 0x31 */
  void bc_sstore_3(); /* 0x32 */

#ifdef JCVM_INT_SUPPORTED
  void bc_istore_0(); /* 0x33 */
  void bc_istore_1(); /* 0x34 */
  void bc_istore_2(); /* 0x35 */
  void bc_istore_3(); /* 0x36 */
#endif                /* JCVM_INT_SUPPORTED */

  void bc_aastore(); /* 0x37 */
  void bc_bastore(); /* 0x38 */
  void bc_sastore(); /* 0x39 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iastore(); /* 0x3a */
#endif               /* JCVM_INT_SUPPORTED */

  void bc_pop();    /* 0x3b */
  void bc_pop2();   /* 0x3c */
  void bc_dup();    /* 0x3d */
  void bc_dup2();   /* 0x3e */
  void bc_dup_x();  /* 0x3f */
  void bc_swap_x(); /* 0x40 */
  void bc_sadd();   /* 0x41 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iadd(); /* 0x42 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_ssub(); /* 0x43 */

#ifdef JCVM_INT_SUPPORTED
  void bc_isub(); /* 0x44 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_smul(); /* 0x45 */

#ifdef JCVM_INT_SUPPORTED
  void bc_imul(); /* 0x46 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sdiv(); /* 0x47 */

#ifdef JCVM_INT_SUPPORTED
  void bc_idiv(); /* 0x48 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_srem(); /* 0x49 */

#ifdef JCVM_INT_SUPPORTED
  void bc_irem(); /* 0x4a */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sneg(); /* 0x4b */

#ifdef JCVM_INT_SUPPORTED
  void bc_ineg(); /* 0x4c */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sshl(); /* 0x4d */

#ifdef JCVM_INT_SUPPORTED
  void bc_ishl(); /* 0x4e */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sshr(); /* 0x4f */

#ifdef JCVM_INT_SUPPORTED
  void bc_ishr(); /* 0x50 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sushr(); /* 0x51 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iushr(); /* 0x52 */
#endif             /* JCVM_INT_SUPPORTED */

  void bc_sand(); /* 0x53 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iand(); /* 0x54 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sor(); /* 0x55 */

#ifdef JCVM_INT_SUPPORTED
  void bc_ior(); /* 0x56 */
#endif           /* JCVM_INT_SUPPORTED */

  void bc_sxor(); /* 0x57 */

#ifdef JCVM_INT_SUPPORTED
  void bc_ixor(); /* 0x58 */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_sinc(); /* 0x59 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iinc(); /* 0x5a */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_s2b(); /* 0x5b */

#ifdef JCVM_INT_SUPPORTED
  void bc_s2i();  /* 0x5c */
  void bc_i2b();  /* 0x5d */
  void bc_i2s();  /* 0x5e */
  void bc_icmp(); /* 0x5f */
#endif            /* JCVM_INT_SUPPORTED */

  void bc_ifeq();         /* 0x60 */
  void bc_ifne();         /* 0x61 */
  void bc_iflt();         /* 0x62 */
  void bc_ifge();         /* 0x63 */
  void bc_ifgt();         /* 0x64 */
  void bc_ifle();         /* 0x65 */
  void bc_ifnull();       /* 0x66 */
  void bc_ifnonnull();    /* 0x67 */
  void bc_if_acmpeq();    /* 0x68 */
  void bc_if_acmpne();    /* 0x69 */
  void bc_if_scmpeq();    /* 0x6a */
  void bc_if_scmpne();    /* 0x6b */
  void bc_if_scmplt();    /* 0x6c */
  void bc_if_scmpge();    /* 0x6d */
  void bc_if_scmpgt();    /* 0x6e */
  void bc_if_scmple();    /* 0x6f */
  void bc_goto();         /* 0x70 */
  void bc_jsr();          /* 0x71 */
  void bc_ret();          /* 0x72 */
  void bc_stableswitch(); /* 0x73 */

#ifdef JCVM_INT_SUPPORTED
  void bc_itableswitch(); /* 0x74 */
#endif                    /* JCVM_INT_SUPPORTED */

  void bc_slookupswitch(); /* 0x75 */

#ifdef JCVM_INT_SUPPORTED
  void bc_ilookupswitch(); /* 0x76 */
#endif                     /* JCVM_INT_SUPPORTED */

  void bc_areturn(); /* 0x77 */
  void bc_sreturn(); /* 0x78 */

#ifdef JCVM_INT_SUPPORTED
  void bc_ireturn(); /* 0x79 */
#endif               /* JCVM_INT_SUPPORTED */

  void bc_return();      /* 0x7a */
  void bc_getstatic_a(); /* 0x7b */
  void bc_getstatic_b(); /* 0x7c */
  void bc_getstatic_s(); /* 0x7d */

#ifdef JCVM_INT_SUPPORTED
  void bc_getstatic_i(); /* 0x7e */
#endif                   /* JCVM_INT_SUPPORTED */

  void bc_putstatic_a(); /* 0x7f */
  void bc_putstatic_b(); /* 0x80 */
  void bc_putstatic_s(); /* 0x81 */

#ifdef JCVM_INT_SUPPORTED
  void bc_putstatic_i(); /* 0x82 */
#endif                   /* JCVM_INT_SUPPORTED */

  void bc_getfield_a(); /* 0x83 */
  void bc_getfield_b(); /* 0x84 */
  void bc_getfield_s(); /* 0x85 */

#ifdef JCVM_INT_SUPPORTED
  void bc_getfield_i(); /* 0x86 */
#endif                  /* JCVM_INT_SUPPORTED */

  void bc_putfield_a(); /* 0x87 */
  void bc_putfield_b(); /* 0x88 */
  void bc_putfield_s(); /* 0x89 */

#ifdef JCVM_INT_SUPPORTED
  void bc_putfield_i(); /* 0x8a */
#endif                  /* JCVM_INT_SUPPORTED */

  void bc_invokevirtual();   /* 0x8b */
  void bc_invokespecial();   /* 0x8c */
  void bc_invokestatic();    /* 0x8d */
  void bc_invokeinterface(); /* 0x8e */
  void bc_new();             /* 0x8f */
  void bc_newarray();        /* 0x90 */
  void bc_anewarray();       /* 0x91 */
  void bc_arraylength();     /* 0x92 */
  void bc_athrow();          /* 0x93 */
  void bc_checkcast();       /* 0x94 */
  void bc_instanceof();      /* 0x95 */
  void bc_sinc_w();          /* 0x96 */

#ifdef JCVM_INT_SUPPORTED
  void bc_iinc_w(); /* 0x97 */
#endif              /* JCVM_INT_SUPPORTED */

  void bc_ifeq_w();       /* 0x98 */
  void bc_ifne_w();       /* 0x99 */
  void bc_iflt_w();       /* 0x9a */
  void bc_ifge_w();       /* 0x9b */
  void bc_ifgt_w();       /* 0x9c */
  void bc_ifle_w();       /* 0x9d */
  void bc_ifnull_w();     /* 0x9e */
  void bc_ifnonnull_w();  /* 0x9f */
  void bc_if_acmpeq_w();  /* 0xa0 */
  void bc_if_acmpne_w();  /* 0xa1 */
  void bc_if_scmpeq_w();  /* 0xa2 */
  void bc_if_scmpne_w();  /* 0xa3 */
  void bc_if_scmplt_w();  /* 0xa4 */
  void bc_if_scmpge_w();  /* 0xa5 */
  void bc_if_scmpgt_w();  /* 0xa6 */
  void bc_if_scmple_w();  /* 0xa7 */
  void bc_goto_w();       /* 0xa8 */
  void bc_getfield_a_w(); /* 0xa9 */
  void bc_getfield_b_w(); /* 0xaa */
  void bc_getfield_s_w(); /* 0xab */

#ifdef JCVM_INT_SUPPORTED
  void bc_getfield_i_w(); /* 0xac */
#endif                    /* JCVM_INT_SUPPORTED */

  void bc_getfield_a_this(); /* 0xad */
  void bc_getfield_b_this(); /* 0xae */
  void bc_getfield_s_this(); /* 0xaf */

#ifdef JCVM_INT_SUPPORTED
  void bc_getfield_i_this(); /* 0xb0 */
#endif                       /* JCVM_INT_SUPPORTED */

  void bc_putfield_a_w(); /* 0xb1 */
  void bc_putfield_b_w(); /* 0xb2 */
  void bc_putfield_s_w(); /* 0xb3 */

#ifdef JCVM_INT_SUPPORTED
  void bc_putfield_i_w(); /* 0xb4 */
#endif                    /* JCVM_INT_SUPPORTED */

  void bc_putfield_a_this(); /* 0xb5 */
  void bc_putfield_b_this(); /* 0xb6 */
  void bc_putfield_s_this(); /* 0xb7 */

#ifdef JCVM_INT_SUPPORTED
  void bc_putfield_i_this(); /* 0xb8 */
#endif                       /* JCVM_INT_SUPPORTED */

  void bc_impdep1(); /* 0xfe */
  void bc_impdep2(); /* 0xff */

  void doThrow(jref_t objectref);
};

} // namespace jcvm

#endif /* _JC_BYTECODES_HPP */
