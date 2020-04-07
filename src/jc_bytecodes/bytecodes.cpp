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

#include "bytecodes.hpp"
#include "../exceptions.hpp"
#include "bytecode_values.hpp"

namespace jcvm {

auto Bytecodes::decode(const uint8_t value) -> void (Bytecodes::*)() {
  bytecode_type bc = bytecodes[value];

  switch (bc) {
  case BC_NOP:
    return &Bytecodes::bc_nop;
    break;

  case BC_ACONST_NULL:
    return &Bytecodes::bc_aconst_null;
    break;

  case BC_SCONST_M1:
    return &Bytecodes::bc_sconst_m1;
    break;

  case BC_SCONST_0:
    return &Bytecodes::bc_sconst_0;
    break;

  case BC_SCONST_1:
    return &Bytecodes::bc_sconst_1;
    break;

  case BC_SCONST_2:
    return &Bytecodes::bc_sconst_2;
    break;

  case BC_SCONST_3:
    return &Bytecodes::bc_sconst_3;
    break;

  case BC_SCONST_4:
    return &Bytecodes::bc_sconst_4;
    break;

  case BC_SCONST_5:
    return &Bytecodes::bc_sconst_5;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ICONST_M1:
    return &Bytecodes::bc_iconst_m1;
    break;

  case BC_ICONST_0:
    return &Bytecodes::bc_iconst_0;
    break;

  case BC_ICONST_1:
    return &Bytecodes::bc_iconst_1;
    break;

  case BC_ICONST_2:
    return &Bytecodes::bc_iconst_2;
    break;

  case BC_ICONST_3:
    return &Bytecodes::bc_iconst_3;
    break;

  case BC_ICONST_4:
    return &Bytecodes::bc_iconst_4;
    break;

  case BC_ICONST_5:
    return &Bytecodes::bc_iconst_5;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_BSPUSH:
    return &Bytecodes::bc_bspush;
    break;

  case BC_SSPUSH:
    return &Bytecodes::bc_sspush;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_BIPUSH:
    return &Bytecodes::bc_bipush;
    break;

  case BC_SIPUSH:
    return &Bytecodes::bc_sipush;
    break;

  case BC_IIPUSH:
    return &Bytecodes::bc_iipush;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_ALOAD:
    return &Bytecodes::bc_aload;
    break;

  case BC_SLOAD:
    return &Bytecodes::bc_sload;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ILOAD:
    return &Bytecodes::bc_iload;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_ALOAD_0:
    return &Bytecodes::bc_aload_0;
    break;

  case BC_ALOAD_1:
    return &Bytecodes::bc_aload_1;
    break;

  case BC_ALOAD_2:
    return &Bytecodes::bc_aload_2;
    break;

  case BC_ALOAD_3:
    return &Bytecodes::bc_aload_3;
    break;

  case BC_SLOAD_0:
    return &Bytecodes::bc_sload_0;
    break;

  case BC_SLOAD_1:
    return &Bytecodes::bc_sload_1;
    break;

  case BC_SLOAD_2:
    return &Bytecodes::bc_sload_2;
    break;

  case BC_SLOAD_3:
    return &Bytecodes::bc_sload_3;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ILOAD_0:
    return &Bytecodes::bc_iload_0;
    break;

  case BC_ILOAD_1:
    return &Bytecodes::bc_iload_1;
    break;

  case BC_ILOAD_2:
    return &Bytecodes::bc_iload_2;
    break;

  case BC_ILOAD_3:
    return &Bytecodes::bc_iload_3;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_AALOAD:
    return &Bytecodes::bc_aaload;
    break;

  case BC_BALOAD:
    return &Bytecodes::bc_baload;
    break;

  case BC_SALOAD:
    return &Bytecodes::bc_saload;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IALOAD:
    return &Bytecodes::bc_iaload;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_ASTORE:
    return &Bytecodes::bc_astore;
    break;

  case BC_SSTORE:
    return &Bytecodes::bc_sstore;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ISTORE:
    return &Bytecodes::bc_istore;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_ASTORE_0:
    return &Bytecodes::bc_astore_0;
    break;

  case BC_ASTORE_1:
    return &Bytecodes::bc_astore_1;
    break;

  case BC_ASTORE_2:
    return &Bytecodes::bc_astore_2;
    break;

  case BC_ASTORE_3:
    return &Bytecodes::bc_astore_3;
    break;

  case BC_SSTORE_0:
    return &Bytecodes::bc_sstore_0;
    break;

  case BC_SSTORE_1:
    return &Bytecodes::bc_sstore_1;
    break;

  case BC_SSTORE_2:
    return &Bytecodes::bc_sstore_2;
    break;

  case BC_SSTORE_3:
    return &Bytecodes::bc_sstore_3;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ISTORE_0:
    return &Bytecodes::bc_istore_0;
    break;

  case BC_ISTORE_1:
    return &Bytecodes::bc_istore_1;
    break;

  case BC_ISTORE_2:
    return &Bytecodes::bc_istore_2;
    break;

  case BC_ISTORE_3:
    return &Bytecodes::bc_istore_3;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_AASTORE:
    return &Bytecodes::bc_aastore;
    break;

  case BC_BASTORE:
    return &Bytecodes::bc_bastore;
    break;

  case BC_SASTORE:
    return &Bytecodes::bc_sastore;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IASTORE:
    return &Bytecodes::bc_iastore;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_POP:
    return &Bytecodes::bc_pop;
    break;

  case BC_POP2:
    return &Bytecodes::bc_pop2;
    break;

  case BC_DUP:
    return &Bytecodes::bc_dup;
    break;

  case BC_DUP2:
    return &Bytecodes::bc_dup2;
    break;

  case BC_DUP_X:
    return &Bytecodes::bc_dup_x;
    break;

  case BC_SWAP_X:
    return &Bytecodes::bc_swap_x;
    break;

  case BC_SADD:
    return &Bytecodes::bc_sadd;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IADD:
    return &Bytecodes::bc_iadd;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SSUB:
    return &Bytecodes::bc_ssub;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ISUB:
    return &Bytecodes::bc_isub;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SMUL:
    return &Bytecodes::bc_smul;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IMUL:
    return &Bytecodes::bc_imul;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SDIV:
    return &Bytecodes::bc_sdiv;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IDIV:
    return &Bytecodes::bc_idiv;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SREM:
    return &Bytecodes::bc_srem;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IREM:
    return &Bytecodes::bc_irem;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SNEG:
    return &Bytecodes::bc_sneg;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_INEG:
    return &Bytecodes::bc_ineg;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SSHL:
    return &Bytecodes::bc_sshl;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ISHL:
    return &Bytecodes::bc_ishl;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SSHR:
    return &Bytecodes::bc_sshr;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ISHR:
    return &Bytecodes::bc_ishr;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SUSHR:
    return &Bytecodes::bc_sushr;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IUSHR:
    return &Bytecodes::bc_iushr;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SAND:
    return &Bytecodes::bc_sand;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IAND:
    return &Bytecodes::bc_iand;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SOR:
    return &Bytecodes::bc_sor;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IOR:
    return &Bytecodes::bc_ior;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SXOR:
    return &Bytecodes::bc_sxor;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IXOR:
    return &Bytecodes::bc_ixor;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SINC:
    return &Bytecodes::bc_sinc;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IINC:
    return &Bytecodes::bc_iinc;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_S2B:
    return &Bytecodes::bc_s2b;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_S2I:
    return &Bytecodes::bc_s2i;
    break;

  case BC_I2B:
    return &Bytecodes::bc_i2b;
    break;

  case BC_I2S:
    return &Bytecodes::bc_i2s;
    break;

  case BC_ICMP:
    return &Bytecodes::bc_icmp;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_IFEQ:
    return &Bytecodes::bc_ifeq;
    break;

  case BC_IFNE:
    return &Bytecodes::bc_ifne;
    break;

  case BC_IFLT:
    return &Bytecodes::bc_iflt;
    break;

  case BC_IFGE:
    return &Bytecodes::bc_ifge;
    break;

  case BC_IFGT:
    return &Bytecodes::bc_ifgt;
    break;

  case BC_IFLE:
    return &Bytecodes::bc_ifle;
    break;

  case BC_IFNULL:
    return &Bytecodes::bc_ifnull;
    break;

  case BC_IFNONNULL:
    return &Bytecodes::bc_ifnonnull;
    break;

  case BC_IF_ACMPEQ:
    return &Bytecodes::bc_if_acmpeq;
    break;

  case BC_IF_ACMPNE:
    return &Bytecodes::bc_if_acmpne;
    break;

  case BC_IF_SCMPEQ:
    return &Bytecodes::bc_if_scmpeq;
    break;

  case BC_IF_SCMPNE:
    return &Bytecodes::bc_if_scmpne;
    break;

  case BC_IF_SCMPLT:
    return &Bytecodes::bc_if_scmplt;
    break;

  case BC_IF_SCMPGE:
    return &Bytecodes::bc_if_scmpge;
    break;

  case BC_IF_SCMPGT:
    return &Bytecodes::bc_if_scmpgt;
    break;

  case BC_IF_SCMPLE:
    return &Bytecodes::bc_if_scmple;
    break;

  case BC_GOTO:
    return &Bytecodes::bc_goto;
    break;

  case BC_JSR:
    return &Bytecodes::bc_jsr;
    break;

  case BC_RET:
    return &Bytecodes::bc_ret;
    break;

  case BC_STABLESWITCH:
    return &Bytecodes::bc_stableswitch;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ITABLESWITCH:
    return &Bytecodes::bc_itableswitch;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_SLOOKUPSWITCH:
    return &Bytecodes::bc_slookupswitch;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_ILOOKUPSWITCH:
    return &Bytecodes::bc_ilookupswitch;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_ARETURN:
    return &Bytecodes::bc_areturn;
    break;

  case BC_SRETURN:
    return &Bytecodes::bc_sreturn;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IRETURN:
    return &Bytecodes::bc_ireturn;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_RETURN:
    return &Bytecodes::bc_return;
    break;

  case BC_GETSTATIC_A:
    return &Bytecodes::bc_getstatic_a;
    break;

  case BC_GETSTATIC_B:
    return &Bytecodes::bc_getstatic_b;
    break;

  case BC_GETSTATIC_S:
    return &Bytecodes::bc_getstatic_s;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_GETSTATIC_I:
    return &Bytecodes::bc_getstatic_i;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_PUTSTATIC_A:
    return &Bytecodes::bc_putstatic_a;
    break;

  case BC_PUTSTATIC_B:
    return &Bytecodes::bc_putstatic_b;
    break;

  case BC_PUTSTATIC_S:
    return &Bytecodes::bc_putstatic_s;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_PUTSTATIC_I:
    return &Bytecodes::bc_putstatic_i;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_GETFIELD_A:
    return &Bytecodes::bc_getfield_a;
    break;

  case BC_GETFIELD_B:
    return &Bytecodes::bc_getfield_b;
    break;

  case BC_GETFIELD_S:
    return &Bytecodes::bc_getfield_s;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_GETFIELD_I:
    return &Bytecodes::bc_getfield_i;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_PUTFIELD_A:
    return &Bytecodes::bc_putfield_a;
    break;

  case BC_PUTFIELD_B:
    return &Bytecodes::bc_putfield_b;
    break;

  case BC_PUTFIELD_S:
    return &Bytecodes::bc_putfield_s;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_PUTFIELD_I:
    return &Bytecodes::bc_putfield_i;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_INVOKEVIRTUAL:
    return &Bytecodes::bc_invokevirtual;
    break;

  case BC_INVOKESPECIAL:
    return &Bytecodes::bc_invokespecial;
    break;

  case BC_INVOKESTATIC:
    return &Bytecodes::bc_invokestatic;
    break;

  case BC_INVOKEINTERFACE:
    return &Bytecodes::bc_invokeinterface;
    break;

  case BC_NEW:
    return &Bytecodes::bc_new;
    break;

  case BC_NEWARRAY:
    return &Bytecodes::bc_newarray;
    break;

  case BC_ANEWARRAY:
    return &Bytecodes::bc_anewarray;
    break;

  case BC_ARRAYLENGTH:
    return &Bytecodes::bc_arraylength;
    break;

  case BC_ATHROW:
    return &Bytecodes::bc_athrow;
    break;

  case BC_CHECKCAST:
    return &Bytecodes::bc_checkcast;
    break;

  case BC_INSTANCEOF:
    return &Bytecodes::bc_instanceof;
    break;

  case BC_SINC_W:
    return &Bytecodes::bc_sinc_w;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_IINC_W:
    return &Bytecodes::bc_iinc_w;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_IFEQ_W:
    return &Bytecodes::bc_ifeq_w;
    break;

  case BC_IFNE_W:
    return &Bytecodes::bc_ifne_w;
    break;

  case BC_IFLT_W:
    return &Bytecodes::bc_iflt_w;
    break;

  case BC_IFGE_W:
    return &Bytecodes::bc_ifge_w;
    break;

  case BC_IFGT_W:
    return &Bytecodes::bc_ifgt_w;
    break;

  case BC_IFLE_W:
    return &Bytecodes::bc_ifle_w;
    break;

  case BC_IFNULL_W:
    return &Bytecodes::bc_ifnull_w;
    break;

  case BC_IFNONNULL_W:
    return &Bytecodes::bc_ifnonnull_w;
    break;

  case BC_IF_ACMPEQ_W:
    return &Bytecodes::bc_if_acmpeq_w;
    break;

  case BC_IF_ACMPNE_W:
    return &Bytecodes::bc_if_acmpne_w;
    break;

  case BC_IF_SCMPEQ_W:
    return &Bytecodes::bc_if_scmpeq_w;
    break;

  case BC_IF_SCMPNE_W:
    return &Bytecodes::bc_if_scmpne_w;
    break;

  case BC_IF_SCMPLT_W:
    return &Bytecodes::bc_if_scmplt_w;
    break;

  case BC_IF_SCMPGE_W:
    return &Bytecodes::bc_if_scmpge_w;
    break;

  case BC_IF_SCMPGT_W:
    return &Bytecodes::bc_if_scmpgt_w;
    break;

  case BC_IF_SCMPLE_W:
    return &Bytecodes::bc_if_scmple_w;
    break;

  case BC_GOTO_W:
    return &Bytecodes::bc_goto_w;
    break;

  case BC_GETFIELD_A_W:
    return &Bytecodes::bc_getfield_a_w;
    break;

  case BC_GETFIELD_B_W:
    return &Bytecodes::bc_getfield_b_w;
    break;

  case BC_GETFIELD_S_W:
    return &Bytecodes::bc_getfield_s_w;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_GETFIELD_I_W:
    return &Bytecodes::bc_getfield_i_w;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_GETFIELD_A_THIS:
    return &Bytecodes::bc_getfield_a_this;
    break;

  case BC_GETFIELD_B_THIS:
    return &Bytecodes::bc_getfield_b_this;
    break;

  case BC_GETFIELD_S_THIS:
    return &Bytecodes::bc_getfield_s_this;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_GETFIELD_I_THIS:
    return &Bytecodes::bc_getfield_i_this;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_PUTFIELD_A_W:
    return &Bytecodes::bc_putfield_a_w;
    break;

  case BC_PUTFIELD_B_W:
    return &Bytecodes::bc_putfield_b_w;
    break;

  case BC_PUTFIELD_S_W:
    return &Bytecodes::bc_putfield_s_w;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_PUTFIELD_I_W:
    return &Bytecodes::bc_putfield_i_w;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_PUTFIELD_A_THIS:
    return &Bytecodes::bc_putfield_a_this;
    break;

  case BC_PUTFIELD_B_THIS:
    return &Bytecodes::bc_putfield_s_this;
    break;

  case BC_PUTFIELD_S_THIS:
    return &Bytecodes::bc_putfield_b_this;
    break;

#ifdef JCVM_INT_SUPPORTED
  case BC_PUTFIELD_I_THIS:
    return &Bytecodes::bc_putfield_i_this;
    break;
#endif /* JCVM_INT_SUPPORTED */

  case BC_IMPDEP1:
    return &Bytecodes::bc_impdep1;
    break;

  case BC_IMPDEP2:
    return &Bytecodes::bc_impdep2;
    break;

  case BC_UNSUPPORTED:
  default:
    throw Exceptions::SecurityException;
  }

  throw Exceptions::SecurityException;
}

} // namespace jcvm
