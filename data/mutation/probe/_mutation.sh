#!/bin/sh
crashcap=''
if [ ! -f ./crashcap.so ] && [ -f ./crashcap.c ] && command -v gcc >/dev/null 2>&1; then
  gcc -shared -fPIC -O1 -o ./crashcap.so ./crashcap.c -ldl >/dev/null 2>&1 || true
fi
[ -f ./crashcap.so ] && crashcap='./crashcap.so'
f='hdr_shoff_e_shoff_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shoff_e_shoff_8.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shoff_e_shoff_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shnum_e_shnum_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shnum_e_shnum_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shnum_e_shnum_4096.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shentsize_e_shentsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shentsize_e_shentsize_8.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shentsize_e_shentsize_4096.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shstrndx_e_shstrndx_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='hdr_shstrndx_e_shstrndx_99.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8_link_sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8_link_sh_link_99.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" cuobjdump --dump-elf "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::cuobjdump exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
true
