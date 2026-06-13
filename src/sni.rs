// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! TLS ClientHello SNI extraction.
//!
//! Parses just enough of a TLS record to pull out the Server Name Indication
//! (SNI) hostname from the ClientHello extensions.  Pure byte parsing — no I/O,
//! no allocations on the error path.

/// Extract the SNI hostname from a TLS ClientHello message.
///
/// `buf` should contain at least the first ~512 bytes peeked from a TCP
/// connection.  Returns `None` if the buffer is too short, not a valid
/// ClientHello, or lacks an SNI extension.
pub fn parse_client_hello_sni(buf: &[u8]) -> Option<&str> {
    // ── TLS record header (5 bytes) ─────────────────────────────────────
    // ContentType: 0x16 = Handshake
    if buf.first()? != &0x16 {
        return None;
    }
    // Skip ProtocolVersion (2 bytes) — always 0x0301 in the record layer,
    // even for TLS 1.3.
    let record_len = u16::from_be_bytes([*buf.get(3)?, *buf.get(4)?]) as usize;
    let record_payload = buf.get(5..5 + record_len.min(buf.len() - 5))?;

    // ── Handshake header (4 bytes) ──────────────────────────────────────
    // HandshakeType: 0x01 = ClientHello
    if record_payload.first()? != &0x01 {
        return None;
    }
    // 3-byte handshake length — we don't need it since we walk field by field.
    let hs = record_payload.get(4..)?;

    // ── ClientHello fields ──────────────────────────────────────────────
    // ProtocolVersion (2) + Random (32) = 34 bytes
    let hs = hs.get(34..)?;

    // Session ID: 1-byte length prefix
    let session_id_len = *hs.first()? as usize;
    let hs = hs.get(1 + session_id_len..)?;

    // Cipher Suites: 2-byte length prefix
    let cs_len = u16::from_be_bytes([*hs.first()?, *hs.get(1)?]) as usize;
    let hs = hs.get(2 + cs_len..)?;

    // Compression Methods: 1-byte length prefix
    let comp_len = *hs.first()? as usize;
    let hs = hs.get(1 + comp_len..)?;

    // ── Extensions ──────────────────────────────────────────────────────
    if hs.len() < 2 {
        return None; // No extensions present
    }
    let ext_len = u16::from_be_bytes([*hs.first()?, *hs.get(1)?]) as usize;
    let mut ext = hs.get(2..2 + ext_len.min(hs.len() - 2))?;

    while ext.len() >= 4 {
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_data_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let ext_data = ext.get(4..4 + ext_data_len)?;

        if ext_type == 0x0000 {
            // SNI extension: ServerNameList
            return parse_sni_extension(ext_data);
        }

        ext = ext.get(4 + ext_data_len..)?;
    }

    None
}

/// Parse the SNI extension payload to extract the hostname.
///
/// Format: 2-byte list length, then entries of (1-byte type, 2-byte name
/// length, name bytes).  Type 0x00 = DNS hostname.
fn parse_sni_extension(data: &[u8]) -> Option<&str> {
    if data.len() < 2 {
        return None;
    }
    // Skip the server_name_list_length — walk entries directly.
    let mut pos = 2;

    while pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > data.len() {
            return None;
        }

        if name_type == 0x00 {
            // DNS hostname — must be valid UTF-8 (ASCII subset in practice).
            return std::str::from_utf8(&data[pos..pos + name_len]).ok();
        }

        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(sni: Option<&str>) -> Vec<u8> {
        // ClientHello body (after handshake header):
        //   ProtocolVersion + Random + SessionID + CipherSuites + Compression + Extensions
        let mut ch = Vec::new();

        // ProtocolVersion: TLS 1.2
        ch.extend_from_slice(&[0x03, 0x03]);
        // Random: 32 zero bytes
        ch.extend_from_slice(&[0u8; 32]);
        // Session ID: empty
        ch.push(0x00);
        // Cipher Suites: 2 bytes length + one suite (TLS_AES_128_GCM_SHA256)
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // Compression Methods: 1 entry (null)
        ch.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let mut exts = Vec::new();

        if let Some(hostname) = sni {
            // SNI extension (type 0x0000)
            let name_bytes = hostname.as_bytes();
            let name_len = name_bytes.len() as u16;
            let entry_len = 1 + 2 + name_len; // type(1) + name_len(2) + name
            let sni_data_len = 2 + entry_len; // list_len field + entry

            exts.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
            exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes()); // ext data length
            exts.extend_from_slice(&((entry_len) as u16).to_be_bytes()); // server_name_list_length
            exts.push(0x00); // name type = hostname
            exts.extend_from_slice(&name_len.to_be_bytes()); // name length
            exts.extend_from_slice(name_bytes); // name
        }

        // Add a dummy extension after SNI to test we stop at the right one
        exts.extend_from_slice(&[0x00, 0x17]); // extended_master_secret
        exts.extend_from_slice(&[0x00, 0x00]); // 0 bytes of data

        // Extensions length prefix
        let ext_len = exts.len() as u16;
        ch.extend_from_slice(&ext_len.to_be_bytes());
        ch.extend_from_slice(&exts);

        // Handshake header: type(1) + length(3)
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let ch_len = ch.len() as u32;
        hs.push((ch_len >> 16) as u8);
        hs.push((ch_len >> 8) as u8);
        hs.push(ch_len as u8);
        hs.extend_from_slice(&ch);

        // TLS record header: type(1) + version(2) + length(2)
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        let hs_len = hs.len() as u16;
        record.extend_from_slice(&hs_len.to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[test]
    fn extracts_sni_from_valid_client_hello() {
        let buf = build_client_hello(Some("build.sunbeam.pt"));
        assert_eq!(parse_client_hello_sni(&buf), Some("build.sunbeam.pt"));
    }

    #[test]
    fn extracts_sni_with_long_hostname() {
        let long = "a".repeat(253); // max DNS name length
        let buf = build_client_hello(Some(&long));
        assert_eq!(parse_client_hello_sni(&buf), Some(long.as_str()));
    }

    #[test]
    fn returns_none_for_no_sni_extension() {
        let buf = build_client_hello(None);
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn returns_none_for_empty_buffer() {
        assert_eq!(parse_client_hello_sni(&[]), None);
    }

    #[test]
    fn returns_none_for_non_tls_data() {
        // HTTP request, not TLS
        assert_eq!(parse_client_hello_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn returns_none_for_truncated_record_header() {
        assert_eq!(parse_client_hello_sni(&[0x16, 0x03]), None);
    }

    #[test]
    fn returns_none_for_truncated_handshake() {
        // Valid record header but payload is too short for a ClientHello.
        let buf = &[
            0x16, 0x03, 0x01, 0x00, 0x05, // record: 5 bytes payload
            0x01, 0x00, 0x00, 0x01, 0x00, // handshake header + 1 byte
        ];
        assert_eq!(parse_client_hello_sni(buf), None);
    }

    #[test]
    fn returns_none_for_non_client_hello_handshake() {
        // Handshake type 0x02 = ServerHello
        let mut buf = build_client_hello(Some("test.example.com"));
        buf[5] = 0x02; // change handshake type
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn handles_nonempty_session_id() {
        let mut ch = Vec::new();
        // ProtocolVersion + Random
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0u8; 32]);
        // Session ID: 32 bytes
        ch.push(0x20);
        ch.extend_from_slice(&[0xAA; 32]);
        // Cipher Suites
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // Compression
        ch.extend_from_slice(&[0x01, 0x00]);

        // SNI extension
        let hostname = b"build.sunbeam.pt";
        let name_len = hostname.len() as u16;
        let entry_len = 1 + 2 + name_len;
        let sni_data_len = 2 + entry_len;

        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(hostname);

        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        // Wrap in handshake + record
        let mut hs = vec![0x01];
        let ch_len = ch.len() as u32;
        hs.push((ch_len >> 16) as u8);
        hs.push((ch_len >> 8) as u8);
        hs.push(ch_len as u8);
        hs.extend_from_slice(&ch);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        assert_eq!(parse_client_hello_sni(&record), Some("build.sunbeam.pt"));
    }

    #[test]
    fn sni_not_first_extension() {
        // Put a supported_versions extension before SNI.
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0u8; 32]);
        ch.push(0x00); // no session id
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression

        let mut exts = Vec::new();

        // supported_versions extension (type 0x002b), 3 bytes of data
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // SNI extension
        let hostname = b"src.sunbeam.pt";
        let name_len = hostname.len() as u16;
        let entry_len = 1 + 2 + name_len;
        let sni_data_len = 2 + entry_len;
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(hostname);

        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let ch_len = ch.len() as u32;
        hs.push((ch_len >> 16) as u8);
        hs.push((ch_len >> 8) as u8);
        hs.push(ch_len as u8);
        hs.extend_from_slice(&ch);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        assert_eq!(parse_client_hello_sni(&record), Some("src.sunbeam.pt"));
    }

    #[test]
    fn returns_none_for_truncated_sni_extension() {
        let mut buf = build_client_hello(Some("build.sunbeam.pt"));
        // Truncate the buffer mid-SNI extension data
        buf.truncate(buf.len() - 8);
        // Fix the record length to match
        let new_len = (buf.len() - 5) as u16;
        buf[3] = (new_len >> 8) as u8;
        buf[4] = new_len as u8;
        assert_eq!(parse_client_hello_sni(&buf), None);
    }

    #[test]
    fn returns_none_for_single_byte_garbage() {
        assert_eq!(parse_client_hello_sni(&[0x16]), None);
        assert_eq!(parse_client_hello_sni(&[0xFF]), None);
        assert_eq!(parse_client_hello_sni(&[0x00]), None);
    }

    #[test]
    fn handles_buffer_larger_than_record() {
        // Extra trailing bytes after the TLS record should be ignored.
        let mut buf = build_client_hello(Some("test.local"));
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parse_client_hello_sni(&buf), Some("test.local"));
    }
}
