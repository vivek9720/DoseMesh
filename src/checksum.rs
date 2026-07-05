pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0x1d0fu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub fn rolling_window_score(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

pub fn weighted_checksum(data: &[u8], seed: u32) -> u32 {
    let mut s = seed.rotate_left(7) ^ 0x9e37_79b9;
    for (i, &b) in data.iter().enumerate() {
        let lane = ((i as u32) << (i & 7)) ^ (b as u32);
        s = s.rotate_left(5) ^ lane.wrapping_mul(0x45d9_f3b);
        s = s.wrapping_add((b as u32).wrapping_mul(17 + (i as u32 & 31)));
    }
    s
}

pub fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || b.is_ascii_graphic() || b == b' ')
        .count();
    printable * 4 >= data.len() * 3
}
