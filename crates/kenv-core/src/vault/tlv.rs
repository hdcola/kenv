/// TLV (Tag-Length-Value) encoding with varint length support
///
/// Allows forward-compatible format where unknown tags can be safely skipped.

use crate::KenvError;

/// Varint length encoding (1-4 bytes)
/// - 0-127: 1 byte (bit 7 = 0)
/// - 128-16383: 2 bytes (bits 15-14 = 10)
/// - 16384-2097151: 3 bytes (bits 23-21 = 110)
/// - 2097152+: 4 bytes (bits 31-29 = 111)

fn encode_varint(value: u32, buf: &mut [u8]) -> Result<usize, KenvError> {
    if value < 128 {
        buf[0] = value as u8;
        Ok(1)
    } else if value < 16384 {
        buf[0] = 0x80 | ((value >> 8) as u8);
        buf[1] = (value & 0xFF) as u8;
        Ok(2)
    } else if value < 2097152 {
        buf[0] = 0xC0 | ((value >> 16) as u8);
        buf[1] = ((value >> 8) & 0xFF) as u8;
        buf[2] = (value & 0xFF) as u8;
        Ok(3)
    } else {
        buf[0] = 0xE0 | ((value >> 24) as u8);
        buf[1] = ((value >> 16) & 0xFF) as u8;
        buf[2] = ((value >> 8) & 0xFF) as u8;
        buf[3] = (value & 0xFF) as u8;
        Ok(4)
    }
}

fn decode_varint(buf: &[u8]) -> Result<(u32, usize), KenvError> {
    if buf.is_empty() {
        return Err(KenvError::InvalidVaultFormat);
    }

    let first = buf[0];
    if first & 0x80 == 0 {
        // 1 byte
        Ok((first as u32, 1))
    } else if first & 0xC0 == 0x80 {
        // 2 bytes
        if buf.len() < 2 {
            return Err(KenvError::InvalidVaultFormat);
        }
        let val = (((first & 0x3F) as u32) << 8) | (buf[1] as u32);
        Ok((val, 2))
    } else if first & 0xE0 == 0xC0 {
        // 3 bytes
        if buf.len() < 3 {
            return Err(KenvError::InvalidVaultFormat);
        }
        let val = (((first & 0x1F) as u32) << 16)
            | ((buf[1] as u32) << 8)
            | (buf[2] as u32);
        Ok((val, 3))
    } else if first & 0xE0 == 0xE0 {
        // 4 bytes
        if buf.len() < 4 {
            return Err(KenvError::InvalidVaultFormat);
        }
        let val = (((first & 0x1F) as u32) << 24)
            | ((buf[1] as u32) << 16)
            | ((buf[2] as u32) << 8)
            | (buf[3] as u32);
        Ok((val, 4))
    } else {
        Err(KenvError::InvalidVaultFormat)
    }
}

/// Write a TLV field
pub fn write_field(
    writer: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
) -> Result<(), KenvError> {
    // Write tag
    writer.push(tag);

    // Write varint length
    let mut len_buf = [0u8; 4];
    let len_bytes = encode_varint(value.len() as u32, &mut len_buf)?;
    writer.extend_from_slice(&len_buf[..len_bytes]);

    // Write value
    writer.extend_from_slice(value);

    Ok(())
}

/// Read a TLV field, skipping unknown tags
pub fn read_field(
    data: &[u8],
    offset: &mut usize,
) -> Result<Option<(u8, Vec<u8>)>, KenvError> {
    if *offset >= data.len() {
        return Ok(None);
    }

    let tag = data[*offset];
    *offset += 1;

    if *offset >= data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }

    let (len, len_size) = decode_varint(&data[*offset..])?;
    *offset += len_size;

    let len = len as usize;
    if *offset + len > data.len() {
        return Err(KenvError::InvalidVaultFormat);
    }

    let value = data[*offset..*offset + len].to_vec();
    *offset += len;

    Ok(Some((tag, value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_encode_1byte() {
        let mut buf = [0u8; 4];
        assert_eq!(encode_varint(0, &mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0);

        let mut buf = [0u8; 4];
        assert_eq!(encode_varint(127, &mut buf).unwrap(), 1);
        assert_eq!(buf[0], 127);
    }

    #[test]
    fn varint_decode_1byte() {
        assert_eq!(decode_varint(&[0]).unwrap(), (0, 1));
        assert_eq!(decode_varint(&[127]).unwrap(), (127, 1));
    }

    #[test]
    fn varint_encode_2bytes() {
        let mut buf = [0u8; 4];
        assert_eq!(encode_varint(128, &mut buf).unwrap(), 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 128);
    }

    #[test]
    fn write_and_read_field() {
        let mut writer = Vec::new();
        write_field(&mut writer, 0x01, b"hello").unwrap();

        let mut offset = 0;
        let (tag, value) = read_field(&writer, &mut offset).unwrap().unwrap();
        assert_eq!(tag, 0x01);
        assert_eq!(value, b"hello");
    }

    #[test]
    fn skip_unknown_tags() {
        let mut writer = Vec::new();
        write_field(&mut writer, 0x01, b"first").unwrap();
        write_field(&mut writer, 0xFF, b"unknown").unwrap(); // Unknown tag
        write_field(&mut writer, 0x02, b"second").unwrap();

        let mut offset = 0;

        // Read first field
        let (tag, value) = read_field(&writer, &mut offset).unwrap().unwrap();
        assert_eq!(tag, 0x01);
        assert_eq!(value, b"first");

        // Skip unknown field
        let (tag, _) = read_field(&writer, &mut offset).unwrap().unwrap();
        assert_eq!(tag, 0xFF); // Unknown tag is still readable, caller decides to skip

        // Read second field
        let (tag, value) = read_field(&writer, &mut offset).unwrap().unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(value, b"second");
    }
}
