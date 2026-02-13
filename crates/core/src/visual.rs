use crate::Hash256;

pub type HashBitmap16 = [[u8; 16]; 16];

pub fn hash_to_bitmap_16x16(hash: Hash256) -> HashBitmap16 {
    let mut bitmap = [[0u8; 16]; 16];
    for (bit_index, bit) in hash
        .0
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .enumerate()
    {
        let row = bit_index / 16;
        let col = bit_index % 16;
        bitmap[row][col] = bit;
    }
    bitmap
}

pub fn render_hash_bitmap_16x16(hash: Hash256) -> String {
    let bitmap = hash_to_bitmap_16x16(hash);
    let mut out = String::new();
    for row in bitmap {
        for bit in row {
            if bit == 1 {
                // 1 means white pixel: render as blank cell.
                out.push_str("  ");
            } else {
                // 0 means black pixel: render as filled cell.
                out.push_str("##");
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::{
        Hash256,
        visual::{hash_to_bitmap_16x16, render_hash_bitmap_16x16},
    };

    #[test]
    fn bitmap_is_16_by_16() {
        let bitmap = hash_to_bitmap_16x16(Hash256([0xff; 32]));
        assert_eq!(bitmap.len(), 16);
        assert_eq!(bitmap[0].len(), 16);
    }

    #[test]
    fn first_bit_maps_to_row0_col0() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b1000_0000;
        let bitmap = hash_to_bitmap_16x16(Hash256(bytes));
        assert_eq!(bitmap[0][0], 1);
        assert_eq!(bitmap[0][1], 0);
    }

    #[test]
    fn rendered_bitmap_has_expected_dimensions() {
        let rendered = render_hash_bitmap_16x16(Hash256([0u8; 32]));
        let rows: Vec<&str> = rendered.lines().collect();
        assert_eq!(rows.len(), 16);
        assert!(rows.iter().all(|line| line.len() == 32));
    }

    #[test]
    fn rendered_bitmap_maps_first_two_bits_to_expected_cells() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b1000_0000;
        let rendered = render_hash_bitmap_16x16(Hash256(bytes));
        let first_row = rendered.lines().next().expect("first row should exist");
        assert!(first_row.starts_with("  ##"));
    }
}
