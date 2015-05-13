/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const KEY_SIZE: usize = 12;
const BLOCK_SIZE: usize = 144;

pub trait OMADigest {
  fn oma_digest(&self, key: &[u8]) -> [u8; 8];
}

impl OMADigest for [u8] {
  fn oma_digest(&self, key: &[u8]) -> [u8; 8] {
    // Key must be 96 bits.
    assert_eq!(key.len(), KEY_SIZE);

    // The internal state.
    let mut state = [0u8; 8];

    fn process_block(state: &mut [u8], key: &[u8], block: &[u8]) {
      // For each byte in the block...
      for l in 0..144 {
        // Current position in the state, starts from the back.
        let j = (7u8.wrapping_sub(l as u8) % 8) as usize;

        // The current key bit to work with.
        let key_bit = key[(l / 8) % KEY_SIZE] >> (7 - j);

        // The block byte at the given index or 0 if the block is too
        // short. This basically implements zero-padding short blocks.
        let block_byte = if l < block.len() { block[l] } else { 0 };

        // Temp values shared between branches.
        let yz = state[(j + 1) % 8].wrapping_add(block_byte);
        let xc = !state[j].wrapping_add(j as u8);

        // Switch based on key bit.
        state[j] = if key_bit & 1 == 1 {
          yz.wrapping_add(xc.rotate_left(1))
        } else {
          yz.wrapping_sub(xc.rotate_right(1))
        };
      }
    }

    // Process each block, carrying over state.
    for block in self.chunks(BLOCK_SIZE) {
      process_block(&mut state, key, block);
    }

    state // The final state.
  }
}

#[cfg(test)]
mod test {
  use OMADigest;

  #[test]
  fn test() {
    let key = [0xdf; 12];
    let data = [0x02, 0x02, 0x00, 0x30, 0x00, 0x03, 0x7f, 0x30, 0xea, 0x6d,
                0x00, 0x00, 0x00, 0x0d, 0x00, 0x20, 0x98, 0x00, 0x31, 0xc3,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11];
    let tag = [0xdb, 0xe5, 0xcd, 0xe5, 0x07, 0xb1, 0xcb, 0x3d];
    assert_eq!(&data.oma_digest(&key), &tag);
  }
}

