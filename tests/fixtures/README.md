# Controlled ELF fixture

`elf64_le_rel.hex` is hexadecimal source for a deterministic 656-byte
ELF64 little-endian relocatable object with machine type EM_X86_64. It is
constructed independently in `tests/test_elf_tools.py`; it is not a captured
CUDA candidate or private experimental artifact.

Decoded-byte SHA-256:
`fd9119b01caf56fe810d6f1bd79fcbfa20ca8188844d02a3325d092ba6086750`.

It has a null section, section-name table, three-byte text section, NOBITS
section, symbol-name table, two symbols, and one RELA entry. NOBITS deliberately
has a conceptual offset beyond the file. The layout follows the [System V gABI
section specification](https://www.sco.com/developers/gabi/latest/ch4.sheader.html).

During P1-C validation, WSL `readelf -h -S -s -r` parsed the decoded fixture
with exit code 0 and empty stderr. The file was never loaded or executed.
Negative tests modify fresh copies in memory and never execute malformed files.

For Mock CUDA-tool tests, changing `e_machine` to EM_CUDA creates a synthetic
structural fixture; that change does not make the payload a genuine cubin.
