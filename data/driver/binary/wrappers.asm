
=== ProbeWrapper  0x1400dd470..0x1400dd507 (151 字节) ===
0x1400dd470: mov      qword ptr [rsp + 8], rbx 
0x1400dd475: mov      qword ptr [rsp + 0x10], rsi 
0x1400dd47a: push     rdi 
0x1400dd47b: sub      rsp, 0x20 
0x1400dd47f: mov      rbx, r8 
0x1400dd482: mov      rsi, rdx 
0x1400dd485: mov      rdi, rcx 
0x1400dd488: test     rcx, rcx 
0x1400dd48b: jne      0x1400dd4a2 
0x1400dd48d: mov      eax, 0x3d 
0x1400dd492: mov      rbx, qword ptr [rsp + 0x30] 
0x1400dd497: mov      rsi, qword ptr [rsp + 0x38] 
0x1400dd49c: add      rsp, 0x20 
0x1400dd4a0: pop      rdi 
0x1400dd4a1: ret       
0x1400dd4a2: test     rbx, rbx 
0x1400dd4a5: jne      0x1400dd4bc 
0x1400dd4a7: mov      eax, 0x1f 
0x1400dd4ac: mov      rbx, qword ptr [rsp + 0x30] 
0x1400dd4b1: mov      rsi, qword ptr [rsp + 0x38] 
0x1400dd4b6: add      rsp, 0x20 
0x1400dd4ba: pop      rdi 
0x1400dd4bb: ret       
0x1400dd4bc: mov      r8d, 1 
0x1400dd4c2: mov      rdx, rbx 
0x1400dd4c5: mov      rcx, rsi 
0x1400dd4c8: call     qword ptr [rip + 0xd29cfa] 
0x1400dd4ce: mov      r9, rbx 
0x1400dd4d1: mov      r8, rdi 
0x1400dd4d4: mov      rdx, rbx 
0x1400dd4d7: mov      rcx, rsi 
0x1400dd4da: call     0x1400dd360 
0x1400dd4df: nop       
0x1400dd4e0: xor      eax, eax 
0x1400dd4e2: mov      rbx, qword ptr [rsp + 0x30] 
0x1400dd4e7: mov      rsi, qword ptr [rsp + 0x38] 
0x1400dd4ec: add      rsp, 0x20 
0x1400dd4f0: pop      rdi 
0x1400dd4f1: ret       
0x1400dd4f2: mov      eax, 0x3d 
0x1400dd4f7: mov      rbx, qword ptr [rsp + 0x30] 
0x1400dd4fc: mov      rsi, qword ptr [rsp + 0x38] 
0x1400dd501: add      rsp, 0x20 
0x1400dd505: pop      rdi 
0x1400dd506: ret       

=== AllocWrapper  0x1400dbc10..0x1400dbcbd (173 字节) ===
0x1400dbc10: push     rbx 
0x1400dbc12: sub      rsp, 0x20 
0x1400dbc16: mov      edx, 0x78 
0x1400dbc1b: mov      r8d, 0x706d6c44 
0x1400dbc21: mov      ecx, 0x401 
0x1400dbc26: call     qword ptr [rip + 0xd2bbb3] 
0x1400dbc2d: nop      dword ptr [rax + rax] 
0x1400dbc32: cmp      byte ptr [rip + 0x126ced3], 0 
0x1400dbc39: mov      rbx, rax 
0x1400dbc3c: jne      0x1400dbcb4 
0x1400dbc3e: test     rax, rax 
0x1400dbc41: je       0x1400dbcb9 
0x1400dbc43: xor      edx, edx 
0x1400dbc45: mov      rcx, rax 
0x1400dbc48: lea      r8d, [rdx + 0x78] 
0x1400dbc4c: call     0x140cf13c0 
0x1400dbc51: movaps   xmm0, xmmword ptr [rip + 0xd7dcc8] 
0x1400dbc58: mov      rax, rbx 
0x1400dbc5b: movups   xmmword ptr [rbx], xmm0 
0x1400dbc5e: movaps   xmm1, xmmword ptr [rip + 0xd7dccb] 
0x1400dbc65: movups   xmmword ptr [rbx + 0x10], xmm1 
0x1400dbc69: movaps   xmm0, xmmword ptr [rip + 0xd7dcd0] 
0x1400dbc70: movups   xmmword ptr [rbx + 0x20], xmm0 
0x1400dbc74: movaps   xmm1, xmmword ptr [rip + 0xd7dcd5] 
0x1400dbc7b: movups   xmmword ptr [rbx + 0x30], xmm1 
0x1400dbc7f: movaps   xmm0, xmmword ptr [rip + 0xd7dcda] 
0x1400dbc86: movups   xmmword ptr [rbx + 0x40], xmm0 
0x1400dbc8a: movaps   xmm1, xmmword ptr [rip + 0xd7dcdf] 
0x1400dbc91: movups   xmmword ptr [rbx + 0x50], xmm1 
0x1400dbc95: movaps   xmm0, xmmword ptr [rip + 0xd7dce4] 
0x1400dbc9c: movups   xmmword ptr [rbx + 0x60], xmm0 
0x1400dbca0: movsd    xmm0, qword ptr [rip + 0xd7dce8] 
0x1400dbca8: movsd    qword ptr [rbx + 0x70], xmm0 
0x1400dbcad: add      rsp, 0x20 
0x1400dbcb1: pop      rbx 
0x1400dbcb2: ret       
0x1400dbcb3: int3      
0x1400dbcb4: test     rbx, rbx 
0x1400dbcb7: jne      0x1400dbc51 
0x1400dbcb9: xor      eax, eax 
0x1400dbcbb: jmp      0x1400dbcad 

=== caller1  0x1403ca889..0x1403ca8bb (50 字节) ===
0x1403ca889: mov      r8d, r9d 
0x1403ca88c: mov      rdx, rax 
0x1403ca88f: mov      rcx, r10 
0x1403ca892: call     0x1400dd470 
0x1403ca897: mov      ebx, eax 
0x1403ca899: test     eax, eax 
0x1403ca89b: je       0x1403ca8af 
0x1403ca89d: mov      r8d, eax 
0x1403ca8a0: mov      edx, 0x12a1000 
0x1403ca8a5: mov      ecx, 0xedcbd99 
0x1403ca8aa: call     0x1400de810 
0x1403ca8af: mov      eax, ebx 
0x1403ca8b1: mov      rbx, qword ptr [rsp + 0x20] 
0x1403ca8b6: add      rsp, 0x28 
0x1403ca8ba: ret       

=== caller2  0x1403ca8e0..0x1403ca968 (136 字节) ===
0x1403ca8e0: mov      qword ptr [rsp + 8], rbx 
0x1403ca8e5: push     rdi 
0x1403ca8e6: sub      rsp, 0x20 
0x1403ca8ea: mov      rax, qword ptr [rcx + 8] 
0x1403ca8ee: xor      edi, edi 
0x1403ca8f0: mov      rbx, rcx 
0x1403ca8f3: test     rax, rax 
0x1403ca8f6: jne      0x1403ca903 
0x1403ca8f8: mov      rbx, qword ptr [rsp + 0x30] 
0x1403ca8fd: add      rsp, 0x20 
0x1403ca901: pop      rdi 
0x1403ca902: ret       
0x1403ca903: mov      r8d, dword ptr [rcx + 0x14] 
0x1403ca907: test     r8b, 1 
0x1403ca90b: jne      0x1403ca950 
0x1403ca90d: mov      rcx, qword ptr [rax] 
0x1403ca910: test     rcx, rcx 
0x1403ca913: je       0x1403ca950 
0x1403ca915: mov      rdx, qword ptr [rbx] 
0x1403ca918: test     rdx, rdx 
0x1403ca91b: je       0x1403ca944 
0x1403ca91d: test     r8b, 4 
0x1403ca921: jne      0x1403ca944 
0x1403ca923: mov      r8d, dword ptr [rbx + 0x10] 
0x1403ca927: call     0x1400dd470 
0x1403ca92c: mov      edi, eax 
0x1403ca92e: test     eax, eax 
0x1403ca930: je       0x1403ca944 
0x1403ca932: mov      r8d, eax 
0x1403ca935: mov      edx, 0xb81000 
0x1403ca93a: mov      ecx, 0xedcbd99 
0x1403ca93f: call     0x1400de810 
0x1403ca944: mov      rcx, qword ptr [rbx + 8] 
0x1403ca948: mov      rcx, qword ptr [rcx] 
0x1403ca94b: call     0x1400fe840 
0x1403ca950: mov      rax, qword ptr [rbx + 8] 
0x1403ca954: mov      rbx, qword ptr [rsp + 0x30] 
0x1403ca959: mov      qword ptr [rax], 0 
0x1403ca960: mov      eax, edi 
0x1403ca962: add      rsp, 0x20 
0x1403ca966: pop      rdi 
0x1403ca967: ret       

=== caller3  0x1403caa05..0x1403cac6d (616 字节) ===
0x1403caa05: mov      qword ptr [rsp + 0x140], rbx 
0x1403caa0d: mov      r8, rax 
0x1403caa10: test     r9d, r9d 
0x1403caa13: je       0x1403caa61 
0x1403caa15: test     rax, rax 
0x1403caa18: je       0x1403caa66 
0x1403caa1a: cmp      dword ptr [rdx + 4], esi 
0x1403caa1d: jne      0x1403caa7f 
0x1403caa1f: xor      edx, edx 
0x1403caa21: lea      rcx, [rsp + 0x60] 
0x1403caa26: call     0x140128460 
0x1403caa2b: mov      ecx, dword ptr [rdi + 0x18] 
0x1403caa2e: call     0x1400fe880 
0x1403caa33: mov      rsi, rax 
0x1403caa36: test     rax, rax 
0x1403caa39: jne      0x1403caa45 
0x1403caa3b: mov      ebx, 0x51 
0x1403caa40: jmp      0x1403cac05 
0x1403caa45: mov      r8d, dword ptr [rdi + 0x18] 
0x1403caa49: mov      rdx, rax 
0x1403caa4c: mov      rcx, qword ptr [rdi + 0x10] 
0x1403caa50: call     0x1400dd3d0 
0x1403caa55: mov      ebx, eax 
0x1403caa57: test     eax, eax 
0x1403caa59: jne      0x1403cac05 
0x1403caa5f: jmp      0x1403caa92 
0x1403caa61: test     rax, rax 
0x1403caa64: je       0x1403caa7f 
0x1403caa66: mov      edx, 0x434100 
0x1403caa6b: mov      ecx, 0xe22d648 
0x1403caa70: call     0x1400de810 
0x1403caa75: mov      ebx, 0x1f 
0x1403caa7a: jmp      0x1403cac05 
0x1403caa7f: xor      edx, edx 
0x1403caa81: lea      rcx, [rsp + 0x60] 
0x1403caa86: mov      bpl, 1 
0x1403caa89: call     0x140128460 
0x1403caa8e: mov      rsi, qword ptr [rdi + 0x10] 
0x1403caa92: mov      edx, 0x200 
0x1403caa97: mov      ecx, 2 
0x1403caa9c: call     0x140115030 
0x1403caaa1: mov      ebx, eax 
0x1403caaa3: test     eax, eax 
0x1403caaa5: jne      0x1403cac05 
0x1403caaab: mov      edx, dword ptr [rdi] 
0x1403caaad: lea      r8, [rsp + 0x50] 
0x1403caab2: lea      rcx, [rip + 0x1014be7] 
0x1403caab9: mov      r14b, 1 
0x1403caabc: call     0x1402728e0 
0x1403caac1: mov      ebx, eax 
0x1403caac3: test     eax, eax 
0x1403caac5: je       0x1403caaf0 
0x1403caac7: mov      r8d, eax 
0x1403caaca: mov      edx, 0x671000 
0x1403caacf: mov      ecx, 0xe22d648 
0x1403caad4: call     0x1400de7e0 
0x1403caad9: mov      r8d, 0x67 
0x1403caadf: mov      edx, ebx 
0x1403caae1: mov      ecx, 2 
0x1403caae6: call     0x140006190 
0x1403caaeb: jmp      0x1403cac05 
  ... (61 条)

=== caller4  0x14042fddf..0x1404300fa (795 字节) ===
0x14042fddf: mov      qword ptr [rsp + 0xf0], rbx 
0x14042fde7: call     0x140390580 
0x14042fdec: mov      ebx, eax 
0x14042fdee: test     eax, eax 
0x14042fdf0: je       0x14042fe1d 
0x14042fdf2: mov      r8d, eax 
0x14042fdf5: mov      edx, 0x651000 
0x14042fdfa: mov      ecx, 0xe8497f9 
0x14042fdff: call     0x1400de840 
0x14042fe04: mov      r8d, 0x65 
0x14042fe0a: mov      edx, ebx 
0x14042fe0c: mov      ecx, 4 
0x14042fe11: call     0x140006190 
0x14042fe16: mov      eax, ebx 
0x14042fe18: jmp      0x1404300f2 
0x14042fe1d: mov      eax, r12d 
0x14042fe20: mov      dword ptr [rsp + 0x34], eax 
0x14042fe24: test     ebp, ebp 
0x14042fe26: je       0x140430133 
0x14042fe2c: nop      dword ptr [rax] 
0x14042fe30: lea      rcx, [rax + rax*2] 
0x14042fe34: mov      rax, qword ptr [rsp + 0x60] 
0x14042fe39: mov      r12, qword ptr [r15 + rcx*8 + 8] 
0x14042fe3e: mov      r15, qword ptr [r15 + rcx*8 + 0x10] 
0x14042fe43: mov      ebp, dword ptr [rax + rcx*8 + 0x18] 
0x14042fe47: test     rbp, rbp 
0x14042fe4a: je       0x14043011d 
0x14042fe50: mov      rcx, qword ptr [rdi + 0x140] 
0x14042fe57: mov      rax, qword ptr [rsp + 0x70] 
0x14042fe5c: mov      edi, dword ptr [rax + 0x268] 
0x14042fe62: mov      rax, qword ptr [rcx + 0x48] 
0x14042fe66: mov      rcx, qword ptr [rax + 0x18] 
0x14042fe6a: mov      ebx, dword ptr [rcx + 0x10] 
0x14042fe6d: mov      ecx, dword ptr [r14 + 0xcc4] 
0x14042fe74: call     0x140106490 
0x14042fe79: lea      rcx, [rsp + 0x68] 
0x14042fe7e: mov      r9, r12 
0x14042fe81: mov      qword ptr [rsp + 0x28], rcx 
0x14042fe86: mov      r8d, edi 
0x14042fe89: mov      rcx, rsi 
0x14042fe8c: mov      dword ptr [rsp + 0x20], eax 
0x14042fe90: mov      edx, ebx 
0x14042fe92: call     0x1403dcb30 
0x14042fe97: test     al, al 
0x14042fe99: je       0x1404300cf 
0x14042fe9f: mov      rax, qword ptr [rsp + 0x68] 
0x14042fea4: xorps    xmm0, xmm0 
0x14042fea7: mov      rdx, r12 
0x14042feaa: mov      rcx, qword ptr [rax + 0xd0] 
0x14042feb1: sub      rdx, qword ptr [rax] 
0x14042feb4: mov      rbx, qword ptr [rcx + 0x30] 
0x14042feb8: sub      rbx, rdx 
0x14042febb: mov      qword ptr [rsp + 0x78], rcx 
0x14042fec0: cmp      rbp, rbx 
0x14042fec3: mov      qword ptr [rsp + 0x80], rdx 
0x14042fecb: movdqu   xmmword ptr [rsp + 0x88], xmm0 
0x14042fed4: cmovb    rbx, rbp 
0x14042fed8: mov      rcx, rbx 
0x14042fedb: call     0x1400fe880 
0x14042fee0: mov      rsi, rax 
0x14042fee3: test     rax, rax 
  ... (61 条)

=== allocCaller1  0x1400dbcc0..0x1400dbdf1 (305 字节) ===
0x1400dbcc0: mov      rax, rsp 
0x1400dbcc3: mov      qword ptr [rax + 8], rbx 
0x1400dbcc7: mov      qword ptr [rax + 0x10], rbp 
0x1400dbccb: push     rsi 
0x1400dbccc: push     rdi 
0x1400dbccd: push     r12 
0x1400dbccf: push     r14 
0x1400dbcd1: push     r15 
0x1400dbcd3: sub      rsp, 0x40 
0x1400dbcd7: xorps    xmm0, xmm0 
0x1400dbcda: xorps    xmm1, xmm1 
0x1400dbcdd: movups   xmmword ptr [rax - 0x48], xmm0 
0x1400dbce1: mov      r14, rdx 
0x1400dbce4: mov      r15, rcx 
0x1400dbce7: movups   xmmword ptr [rax - 0x38], xmm1 
0x1400dbceb: mov      ebp, 0xa 
0x1400dbcf0: call     0x1400dbc10 
0x1400dbcf5: mov      rdi, rax 
0x1400dbcf8: test     rax, rax 
0x1400dbcfb: jne      0x1400dbd07 
0x1400dbcfd: mov      ebx, 0xc0000017 
0x1400dbd02: jmp      0x1400dbdd7 
0x1400dbd07: mov      rdx, rdi 
0x1400dbd0a: lea      rcx, [rsp + 0x20] 
0x1400dbd0f: call     qword ptr [rip + 0xd2bc82] 
0x1400dbd16: nop      dword ptr [rax + rax] 
0x1400dbd1b: lea      rcx, [rsp + 0x20] 
0x1400dbd20: call     qword ptr [rip + 0xd2b789] 
0x1400dbd27: nop      dword ptr [rax + rax] 
0x1400dbd2c: xor      edx, edx 
0x1400dbd2e: mov      rcx, rdi 
0x1400dbd31: mov      ebx, eax 
0x1400dbd33: mov      esi, eax 
0x1400dbd35: call     qword ptr [rip + 0xd2b734] 
0x1400dbd3c: nop      dword ptr [rax + rax] 
0x1400dbd41: mov      ecx, 0x80000000 
0x1400dbd46: mov      r12d, 0xc000010e 
0x1400dbd4c: lea      eax, [rbx + rcx] 
0x1400dbd4f: test     ecx, eax 
0x1400dbd51: jne      0x1400dbd58 
0x1400dbd53: cmp      ebx, r12d 
0x1400dbd56: jne      0x1400dbdd7 
0x1400dbd58: lea      rdx, [rip + 0xd7dba1] 
0x1400dbd5f: lea      rcx, [rsp + 0x30] 
0x1400dbd64: call     qword ptr [rip + 0xd2bc2d] 
0x1400dbd6b: nop      dword ptr [rax + rax] 
0x1400dbd70: mov      r9, r14 
0x1400dbd73: lea      rcx, [rsp + 0x30] 
0x1400dbd78: mov      r8, r15 
0x1400dbd7b: mov      edx, 0xc0000000 
0x1400dbd80: call     qword ptr [rip + 0xd2b721] 
0x1400dbd87: nop      dword ptr [rax + rax] 
0x1400dbd8c: mov      edi, eax 
0x1400dbd8e: test     eax, eax 
0x1400dbd90: jns      0x1400dbdce 
0x1400dbd92: cmp      ebx, r12d 
0x1400dbd95: jne      0x1400dbdc0 
0x1400dbd97: lea      r8, [rsp + 0x80] 
0x1400dbd9f: mov      qword ptr [rsp + 0x80], 0xffffffffffff3cb0 
0x1400dbdab: xor      edx, edx 
0x1400dbdad: xor      ecx, ecx 
  ... (61 条)

=== allocCaller2  0x1400dbdf4..0x1400dbe4c (88 字节) ===
0x1400dbdf4: push     rbx 
0x1400dbdf6: sub      rsp, 0x30 
0x1400dbdfa: xorps    xmm0, xmm0 
0x1400dbdfd: movups   xmmword ptr [rsp + 0x20], xmm0 
0x1400dbe02: call     0x1400dbc10 
0x1400dbe07: mov      rbx, rax 
0x1400dbe0a: test     rax, rax 
0x1400dbe0d: je       0x1400dbe45 
0x1400dbe0f: mov      rdx, rax 
0x1400dbe12: lea      rcx, [rsp + 0x20] 
0x1400dbe17: call     qword ptr [rip + 0xd2bb7a] 
0x1400dbe1e: nop      dword ptr [rax + rax] 
0x1400dbe23: lea      rcx, [rsp + 0x20] 
0x1400dbe28: call     qword ptr [rip + 0xd2b689] 
0x1400dbe2f: nop      dword ptr [rax + rax] 
0x1400dbe34: xor      edx, edx 
0x1400dbe36: mov      rcx, rbx 
0x1400dbe39: call     qword ptr [rip + 0xd2b630] 
0x1400dbe40: nop      dword ptr [rax + rax] 
0x1400dbe45: add      rsp, 0x30 
0x1400dbe49: pop      rbx 
0x1400dbe4a: ret       
0x1400dbe4b: int3      