pub(super) const X86_ID_WINDOW_SIZE: i32 = 65535;
pub(super) const X86_MAX_TRANSLATION_OFFSET: i32 = 1023;

pub(super) fn x86_filter(data: &mut [u8]) {
    x86_filter_impl(data, true);
}

pub(super) fn x86_filter_impl(data: &mut [u8], undo: bool) {
    let size = data.len() as i32;
    if size <= 17 {
        return;
    }

    let mut last_x86_pos: i32 = -X86_MAX_TRANSLATION_OFFSET - 1;
    let mut last_target_usages = vec![-X86_ID_WINDOW_SIZE - 1i32; 65536];

    let mut i: i32 = 1;
    let limit = size - 16;

    while i < limit {
        let opcode = data[i as usize];
        let (nbytes, max_off) = match opcode {
            0xE8 => (1, X86_MAX_TRANSLATION_OFFSET >> 1),
            0x48 | 0x4C => {
                let modrm = data[(i + 2) as usize];
                let op = data[(i + 1) as usize];
                if (modrm & 0x07) == 0x05
                    && (op == 0x8D || (op == 0x8B && (opcode & 0x04) == 0 && (modrm & 0xF0) == 0))
                {
                    (3, X86_MAX_TRANSLATION_OFFSET)
                } else {
                    i += 1;
                    continue;
                }
            }
            0xFF if data[(i + 1) as usize] == 0x15 => (2, X86_MAX_TRANSLATION_OFFSET),
            // Lock-prefixed `add dword [rip+disp32], imm8` only. The ModR/M
            // byte must be exactly 0x05 (mod=00, reg=000/add, rm=101/RIP-rel);
            // Microsoft's filter tests the whole byte here, NOT just the low 3
            // rm bits. Matching `& 0x07 == 0x05` wrongly translated other 0x83
            // group ops (e.g. modrm 0x3d/0x7d/0x0d/0x65), corrupting their
            // 4-byte operand by the opcode position.
            0xF0 if data[(i + 1) as usize] == 0x83 && data[(i + 2) as usize] == 0x05 => {
                (3, X86_MAX_TRANSLATION_OFFSET)
            }
            0xE9 => {
                i += 5;
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        };

        let p = (i + nbytes) as usize;
        let active = i - last_x86_pos <= max_off;
        if undo && active {
            let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
            data[p..p + 4].copy_from_slice(&n.wrapping_sub(i as u32).to_le_bytes());
        }
        let target16 =
            (i as u16).wrapping_add(u16::from_le_bytes(data[p..p + 2].try_into().unwrap()));
        if !undo && active {
            let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
            data[p..p + 4].copy_from_slice(&n.wrapping_add(i as u32).to_le_bytes());
        }
        let end_pos = i + nbytes + 3;
        if end_pos - last_target_usages[target16 as usize] <= X86_ID_WINDOW_SIZE {
            last_x86_pos = end_pos;
        }
        last_target_usages[target16 as usize] = end_pos;
        i = end_pos + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `0xF0 0x83` (lock arithmetic on `[rip+disp32]`) translation must
    /// fire only for ModR/M byte `0x05` exactly, not for any byte whose low 3
    /// bits are `0b101`. Microsoft's filter tests the whole ModR/M byte, so
    /// `0x83` group ops like `cmp`/`or` with a non-RIP ModR/M (0x3d, 0x7d,
    /// 0x0d, 0x65, ...) must be left untranslated; treating them as opcodes
    /// corrupted their 4-byte operand by the opcode position.
    #[test]
    fn f0_83_translates_only_modrm_05() {
        // Lay out three `F0 83` ops in an active translation region (a repeated
        // target16 pulls `last_x86_pos` up to just behind the third op):
        //   A,B @ modrm 0x05 with the same target16 -> arms last_x86_pos
        //   C   @ modrm 0x7d (NOT 0x05) -> must NOT translate (the bug)
        //   D   @ modrm 0x05            -> must translate (the legit case)
        let mut data = vec![0u8; 300];
        let put = |d: &mut [u8], at: usize, modrm: u8, operand: [u8; 4]| {
            d[at] = 0xF0;
            d[at + 1] = 0x83;
            d[at + 2] = modrm;
            d[at + 3..at + 7].copy_from_slice(&operand);
        };
        put(&mut data, 20, 0x05, [0x00, 0x00, 0x00, 0x00]); // target16 = 20
        put(&mut data, 30, 0x05, [0xF6, 0xFF, 0x00, 0x00]); // target16 = 30 + 0xFFF6 = 20
        put(&mut data, 40, 0x7D, [0x10, 0x00, 0x00, 0x00]); // active, but not an opcode
        put(&mut data, 50, 0x05, [0x64, 0x00, 0x00, 0x00]); // active, legit -> 100 - 50

        x86_filter(&mut data); // undo == true (decompress direction)

        // C: ModR/M 0x7d -> untranslated (regression: was 0x10 - 40).
        assert_eq!(&data[43..47], &[0x10, 0x00, 0x00, 0x00], "F0 83 7d must not translate");
        // D: ModR/M 0x05 -> translated by its opcode position (100 - 50 = 50).
        assert_eq!(&data[53..57], &[50, 0x00, 0x00, 0x00], "F0 83 05 must translate");
    }
}
