
from tools.elf_value_sweep import summarise  # noqa: E402
from src.mutation_campaign import Variant  # noqa: E402


def test_crashes_are_grouped_by_site():
    """Forty-four variants at one site is one fact, not forty-four findings."""
    crashes = [
        Variant("a", "e_shoff", 0, 0, 8, fingerprint="libc.so.6+0x183000"),
        Variant("b", "e_shnum", 1, 0, 2, fingerprint="libc.so.6+0x183000"),
        Variant("c", "e_shoff", 1, 0, 8, fingerprint="cuobjdump+0x12000"),
    ]
    groups = summarise(crashes)
    assert len(groups) == 2
    site, items = groups[0]
    assert site == "libc.so.6+0x183000" and len(items) == 2
    assert {item.field for item in items} == {"e_shoff", "e_shnum"}
