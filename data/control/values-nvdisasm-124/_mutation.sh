#!/bin/sh
crashcap=''
if [ ! -f ./crashcap.so ] && [ -f ./crashcap.c ] && command -v gcc >/dev/null 2>&1; then
  gcc -shared -fPIC -O1 -o ./crashcap.so ./crashcap.c -ldl >/dev/null 2>&1 || true
fi
[ -f ./crashcap.so ] && crashcap='./crashcap.so'
f='seed_(unchanged)_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shoff_e_shoff_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shoff_e_shoff_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shoff_e_shoff_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shoff_e_shoff_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shoff_e_shoff_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shentsize_e_shentsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shentsize_e_shentsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shentsize_e_shentsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shentsize_e_shentsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shnum_e_shnum_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shnum_e_shnum_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shnum_e_shnum_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shnum_e_shnum_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shstrndx_e_shstrndx_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shstrndx_e_shstrndx_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shstrndx_e_shstrndx_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='e_shstrndx_e_shstrndx_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_type_sec0.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_type_sec0.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_type_sec0.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_type_sec0.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_type_sec0.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_offset_sec0.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_offset_sec0.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_offset_sec0.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_offset_sec0.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_offset_sec0.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_size_sec0.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_size_sec0.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_size_sec0.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_size_sec0.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_size_sec0.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_link_sec0.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_link_sec0.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_link_sec0.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_link_sec0.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_link_sec0.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_info_sec0.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_info_sec0.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_info_sec0.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_info_sec0.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_info_sec0.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_entsize_sec0.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_entsize_sec0.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_entsize_sec0.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_entsize_sec0.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec0.sh_entsize_sec0.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_type_sec1.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_type_sec1.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_type_sec1.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_type_sec1.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_type_sec1.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_offset_sec1.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_offset_sec1.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_offset_sec1.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_offset_sec1.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_offset_sec1.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_size_sec1.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_size_sec1.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_size_sec1.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_size_sec1.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_size_sec1.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_link_sec1.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_link_sec1.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_link_sec1.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_link_sec1.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_link_sec1.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_info_sec1.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_info_sec1.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_info_sec1.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_info_sec1.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_info_sec1.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_entsize_sec1.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_entsize_sec1.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_entsize_sec1.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_entsize_sec1.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec1.sh_entsize_sec1.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_type_sec2.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_type_sec2.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_type_sec2.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_type_sec2.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_type_sec2.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_offset_sec2.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_offset_sec2.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_offset_sec2.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_offset_sec2.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_offset_sec2.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_size_sec2.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_size_sec2.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_size_sec2.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_size_sec2.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_size_sec2.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_link_sec2.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_link_sec2.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_link_sec2.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_link_sec2.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_link_sec2.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_info_sec2.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_info_sec2.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_info_sec2.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_info_sec2.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_info_sec2.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_entsize_sec2.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_entsize_sec2.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_entsize_sec2.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_entsize_sec2.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec2.sh_entsize_sec2.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_type_sec3.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_type_sec3.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_type_sec3.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_type_sec3.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_type_sec3.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_offset_sec3.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_offset_sec3.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_offset_sec3.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_offset_sec3.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_offset_sec3.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_size_sec3.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_size_sec3.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_size_sec3.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_size_sec3.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_size_sec3.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_link_sec3.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_link_sec3.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_link_sec3.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_link_sec3.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_link_sec3.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_info_sec3.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_info_sec3.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_info_sec3.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_info_sec3.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_info_sec3.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_entsize_sec3.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_entsize_sec3.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_entsize_sec3.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_entsize_sec3.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec3.sh_entsize_sec3.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_type_sec4.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_type_sec4.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_type_sec4.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_type_sec4.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_type_sec4.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_offset_sec4.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_offset_sec4.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_offset_sec4.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_offset_sec4.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_offset_sec4.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_size_sec4.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_size_sec4.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_size_sec4.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_size_sec4.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_size_sec4.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_link_sec4.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_link_sec4.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_link_sec4.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_link_sec4.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_link_sec4.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_info_sec4.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_info_sec4.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_info_sec4.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_info_sec4.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_info_sec4.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_entsize_sec4.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_entsize_sec4.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_entsize_sec4.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_entsize_sec4.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec4.sh_entsize_sec4.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_type_sec5.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_type_sec5.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_type_sec5.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_type_sec5.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_type_sec5.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_offset_sec5.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_offset_sec5.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_offset_sec5.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_offset_sec5.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_offset_sec5.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_size_sec5.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_size_sec5.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_size_sec5.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_size_sec5.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_size_sec5.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_link_sec5.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_link_sec5.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_link_sec5.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_link_sec5.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_link_sec5.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_info_sec5.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_info_sec5.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_info_sec5.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_info_sec5.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_info_sec5.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_entsize_sec5.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_entsize_sec5.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_entsize_sec5.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_entsize_sec5.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec5.sh_entsize_sec5.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_type_sec6.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_type_sec6.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_type_sec6.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_type_sec6.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_type_sec6.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_offset_sec6.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_offset_sec6.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_offset_sec6.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_offset_sec6.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_offset_sec6.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_size_sec6.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_size_sec6.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_size_sec6.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_size_sec6.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_size_sec6.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_link_sec6.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_link_sec6.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_link_sec6.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_link_sec6.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_link_sec6.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_info_sec6.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_info_sec6.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_info_sec6.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_info_sec6.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_info_sec6.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_entsize_sec6.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_entsize_sec6.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_entsize_sec6.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_entsize_sec6.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec6.sh_entsize_sec6.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_type_sec7.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_type_sec7.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_type_sec7.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_type_sec7.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_type_sec7.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_offset_sec7.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_offset_sec7.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_offset_sec7.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_offset_sec7.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_offset_sec7.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_size_sec7.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_size_sec7.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_size_sec7.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_size_sec7.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_size_sec7.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_link_sec7.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_link_sec7.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_link_sec7.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_link_sec7.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_link_sec7.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_info_sec7.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_info_sec7.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_info_sec7.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_info_sec7.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_info_sec7.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_entsize_sec7.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_entsize_sec7.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_entsize_sec7.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_entsize_sec7.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec7.sh_entsize_sec7.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_type_sec8.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_type_sec8.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_type_sec8.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_type_sec8.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_type_sec8.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_offset_sec8.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_offset_sec8.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_offset_sec8.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_offset_sec8.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_offset_sec8.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_size_sec8.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_size_sec8.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_size_sec8.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_size_sec8.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_size_sec8.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_link_sec8.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_link_sec8.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_link_sec8.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_link_sec8.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_link_sec8.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_info_sec8.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_info_sec8.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_info_sec8.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_info_sec8.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_info_sec8.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_entsize_sec8.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_entsize_sec8.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_entsize_sec8.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_entsize_sec8.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec8.sh_entsize_sec8.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_type_sec9.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_type_sec9.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_type_sec9.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_type_sec9.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_type_sec9.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_offset_sec9.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_offset_sec9.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_offset_sec9.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_offset_sec9.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_offset_sec9.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_size_sec9.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_size_sec9.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_size_sec9.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_size_sec9.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_size_sec9.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_link_sec9.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_link_sec9.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_link_sec9.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_link_sec9.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_link_sec9.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_info_sec9.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_info_sec9.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_info_sec9.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_info_sec9.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_info_sec9.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_entsize_sec9.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_entsize_sec9.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_entsize_sec9.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_entsize_sec9.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec9.sh_entsize_sec9.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_type_sec10.sh_type_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_type_sec10.sh_type_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_type_sec10.sh_type_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_type_sec10.sh_type_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_type_sec10.sh_type_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_offset_sec10.sh_offset_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_offset_sec10.sh_offset_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_offset_sec10.sh_offset_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_offset_sec10.sh_offset_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_offset_sec10.sh_offset_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_size_sec10.sh_size_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_size_sec10.sh_size_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_size_sec10.sh_size_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_size_sec10.sh_size_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_size_sec10.sh_size_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_link_sec10.sh_link_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_link_sec10.sh_link_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_link_sec10.sh_link_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_link_sec10.sh_link_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_link_sec10.sh_link_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_info_sec10.sh_info_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_info_sec10.sh_info_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_info_sec10.sh_info_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_info_sec10.sh_info_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_info_sec10.sh_info_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_entsize_sec10.sh_entsize_0.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_entsize_sec10.sh_entsize_1.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_entsize_sec10.sh_entsize_4294967295.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_entsize_sec10.sh_entsize_2536.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
f='sec10.sh_entsize_sec10.sh_entsize_2537.cubin'
rm -f ".cc.$f"
CRASHCAP_OUT=".cc.$f" LD_PRELOAD="$crashcap" timeout 10 nvdisasm "$f" >/dev/null 2>&1
rc=$?
echo "[CPG_RUN] $f::nvdisasm exit=$rc"
if [ -f ".cc.$f" ]; then sed "s/^/[CPG_CRASH] $f /" ".cc.$f"; rm -f ".cc.$f"; fi
true
