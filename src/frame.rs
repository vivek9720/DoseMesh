use crate::checksum;
use crate::cursor::{parse_u32, trim_ascii, Cursor};
use crate::error::{DecodeError, ErrorKind, Result};
use crate::model::{Frame, FrameKind};

const TEXT_MAGIC: &[u8] = b"DMF|";
const BIN_MAGIC: &[u8] = b"DMB1";

pub fn parse_frame(data: &[u8]) -> Result<Frame> {
    let data = trim_ascii(data);
    if data.is_empty() {
        return Err(DecodeError::new(ErrorKind::Empty, 0, "empty frame"));
    }
    if data.starts_with(BIN_MAGIC) {
        parse_binary_frame(data)
    } else if data.starts_with(TEXT_MAGIC) {
        parse_text_frame(data)
    } else if data.starts_with(b"DM1|") {
        parse_text_frame(data)
    } else {
        parse_legacy_frame(data)
    }
}

pub fn parse_frames(data: &[u8]) -> Result<Vec<Frame>> {
    if data.starts_with(BIN_MAGIC) {
        let mut c = Cursor::new(data);
        let mut out = Vec::new();
        while !c.is_empty() {
            let start = c.pos();
            if c.remaining() < 15 {
                break;
            }
            let len = binary_frame_len(&data[start..])?;
            let slice = c.read_slice(len)?;
            match parse_binary_frame(slice) {
                Ok(frame) => out.push(frame),
                Err(_) => break,
            }
            if out.len() > 2048 {
                return Err(DecodeError::new(ErrorKind::Limit, start, "too many frames"));
            }
        }
        return Ok(out);
    }

    let mut cur = Cursor::new(data);
    let mut frames = Vec::new();
    while let Some(line) = cur.read_line() {
        let line = trim_ascii(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        match parse_frame(line) {
            Ok(frame) => frames.push(frame),
            Err(_) => {
                if frames.is_empty() {
                    return parse_legacy_blob(data).map(|f| vec![f]);
                }
            }
        }
        if frames.len() > 4096 {
            return Err(DecodeError::new(
                ErrorKind::Limit,
                cur.pos(),
                "too many text frames",
            ));
        }
    }

    if frames.is_empty() {
        parse_legacy_blob(data).map(|f| vec![f])
    } else {
        Ok(frames)
    }
}

fn parse_text_frame(data: &[u8]) -> Result<Frame> {
    let mut parts = data.splitn(5, |&b| b == b'|');
    let _magic = parts.next().unwrap_or_default();
    let kind_raw = parts
        .next()
        .ok_or_else(|| DecodeError::new(ErrorKind::BadField, 0, "missing kind"))?;
    let seq_raw = parts
        .next()
        .ok_or_else(|| DecodeError::new(ErrorKind::BadField, 0, "missing sequence"))?;
    let flags_raw = parts
        .next()
        .ok_or_else(|| DecodeError::new(ErrorKind::BadField, 0, "missing flags"))?;
    let payload = parts.next().unwrap_or_default().to_vec();

    let kind = FrameKind::from_name(trim_ascii(kind_raw))
        .ok_or_else(|| DecodeError::new(ErrorKind::UnknownKind, 4, "unknown frame kind"))?;
    let sequence = parse_u32(seq_raw).unwrap_or(0);
    let flags = parse_u32(flags_raw).unwrap_or(0) as u16;
    Ok(Frame::new(kind, sequence, flags, payload))
}

fn parse_legacy_frame(data: &[u8]) -> Result<Frame> {
    let mut parts = data.splitn(2, |&b| b == b':');
    let kind_raw = parts.next().unwrap_or_default();
    let payload = parts.next().unwrap_or_default().to_vec();
    let kind = FrameKind::from_name(kind_raw).unwrap_or(FrameKind::Telemetry);
    Ok(Frame::new(
        kind,
        checksum::rolling_window_score(kind_raw),
        0,
        payload,
    ))
}

fn parse_legacy_blob(data: &[u8]) -> Result<Frame> {
    if data.is_empty() {
        return Err(DecodeError::new(ErrorKind::Empty, 0, "empty legacy blob"));
    }
    let kind = if data.windows(4).any(|w| w.eq_ignore_ascii_case(b"drug")) {
        FrameKind::Dictionary
    } else if data.windows(5).any(|w| w.eq_ignore_ascii_case(b"order")) {
        FrameKind::Order
    } else if data.windows(6).any(|w| w.eq_ignore_ascii_case(b"script")) {
        FrameKind::Script
    } else {
        FrameKind::Telemetry
    };
    Ok(Frame::new(
        kind,
        checksum::rolling_window_score(data),
        0,
        data.to_vec(),
    ))
}

fn parse_binary_frame(data: &[u8]) -> Result<Frame> {
    let mut c = Cursor::new(data);
    let magic = c.read_slice(4)?;
    if magic != BIN_MAGIC {
        return Err(DecodeError::new(
            ErrorKind::BadMagic,
            0,
            "bad binary frame magic",
        ));
    }
    let kind = FrameKind::from_code(c.read_u8()?);
    let flags = c.read_u16_le()?;
    let sequence = c.read_u32_le()?;
    let len = c.read_u32_le()? as usize;
    if len > 1 << 20 {
        return Err(DecodeError::new(
            ErrorKind::Limit,
            c.pos(),
            "payload too large",
        ));
    }
    let payload = c.read_slice(len)?.to_vec();
    let expected = c.read_u16_le().unwrap_or(0);
    let actual = checksum::crc16_ccitt(&payload);
    if expected != 0 && expected != actual && flags & 0x8000 != 0 {
        return Err(DecodeError::new(
            ErrorKind::BadChecksum,
            c.pos(),
            "checksum mismatch",
        ));
    }
    Ok(Frame::new(kind, sequence, flags, payload))
}

fn binary_frame_len(data: &[u8]) -> Result<usize> {
    if data.len() < 15 {
        return Err(DecodeError::new(
            ErrorKind::Truncated,
            data.len(),
            "short binary header",
        ));
    }
    let len = u32::from_le_bytes([data[11], data[12], data[13], data[14]]) as usize;
    15usize
        .checked_add(len)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| DecodeError::new(ErrorKind::BadLength, 11, "frame length overflow"))
}
