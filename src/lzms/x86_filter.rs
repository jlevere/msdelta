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
            0xFF if data[(i + 1) as usize] == 0x15 => {
                (2, X86_MAX_TRANSLATION_OFFSET)
            }
            0xF0
                if data[(i + 1) as usize] == 0x83
                    && (data[(i + 2) as usize] & 0x07) == 0x05 =>
            {
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
        let target16 = (i as u16).wrapping_add(u16::from_le_bytes(
            data[p..p + 2].try_into().unwrap(),
        ));
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
