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
      // 18 rounds.
      for i in 0..18 {
        let key_byte = key[i % KEY_SIZE];

        // Transform each state byte.
        for j in (0..8).rev() {
          let key_bit = key_byte >> (7 - j);

          let index = 8 * i + 7 - j;
          // The block byte at the given index or 0 if the block is too
          // short. This basically implements zero-padding short blocks.
          let block_byte = if index < block.len() { block[index] } else { 0 };

          // Temp values shared between branches.
          let yz = state[(j + 1) % 8].wrapping_add(block_byte);
          let xc = !state[j].wrapping_add(j as u8);

          // Switch based on key bit.
          state[j] = if key_bit % 2 == 1 {
            yz.wrapping_add(xc).rotate_left(1)
          } else {
            yz.wrapping_sub(xc).rotate_right(1)
          };
        }
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
    // TODO find some test vectors or a reference implementation

    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2];
    let data = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby";
    let hex = data.oma_digest(&key).iter().fold(String::new(), |s, b| format!("{}{:02x}", s, b));
    assert_eq!(hex, "8ce33dbc13805261");
  }
}

