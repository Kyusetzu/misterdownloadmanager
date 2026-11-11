//! What Click'n'Load 2 posts is opened with: AES-128-CBC, Base64, a link a line.

/// AES-128 in CBC mode, the padding left to the caller (Click'n'Load pads with zeros): `data`'s
/// length a multiple of 16, else None.
pub(crate) fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let cipher = aes::Aes128::new(key.into());
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0 {
        let mut block = aes::Block::from(*chunk);
        cipher.decrypt_block(&mut block);
        out.extend(block.iter().zip(prev).map(|(b, p)| b ^ p));
        prev = *chunk;
    }
    Some(out)
}

/// The other way, for the tests' own posts.
#[cfg(test)]
pub(crate) fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes128::new(key.into());
    let mut padded = data.to_vec();
    padded.resize(data.len().div_ceil(16) * 16, 0);
    let mut prev = *iv;
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.as_chunks::<16>().0 {
        let mut block = aes::Block::default();
        for (b, (c, p)) in block.iter_mut().zip(chunk.iter().zip(prev)) {
            *b = c ^ p;
        }
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        out.extend_from_slice(&block);
    }
    out
}

/// Base64 as the sites write it: standard alphabet, padding optional, line breaks and spaces
/// ignored.
pub(crate) fn base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(clean.trim_end_matches('='))
        .ok()
}

/// The links in a decrypted text: one a line, http(s) and ftp only, each once, NUL padding
/// and blanks dropped.
pub(crate) fn lines(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    text.split(['\r', '\n'])
        .map(|l| l.trim_matches(|c: char| c == '\0' || c.is_whitespace()))
        .filter(|l| {
            url::Url::parse(l).is_ok_and(|u| matches!(u.scheme(), "http" | "https" | "ftp"))
        })
        .filter(|l| seen.insert(l.to_string()))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_goes_both_ways_and_refuses_partial_blocks() {
        let (key, iv) = (*b"0123456789abcdef", *b"fedcba9876543210");
        let text = b"a text longer than one block, zero padded";
        let sealed = aes_cbc_encrypt(&key, &iv, text);
        assert_eq!(sealed.len() % 16, 0);
        let open = aes_cbc_decrypt(&key, &iv, &sealed).unwrap();
        assert_eq!(&open[..text.len()], text);
        assert!(open[text.len()..].iter().all(|b| *b == 0));
        assert_eq!(aes_cbc_decrypt(&key, &iv, &sealed[1..]), None);
    }

    #[test]
    fn links_one_a_line_each_once() {
        let t = "http://a.example/1\r\n\nhttps://b.example/2\nnot a link\nhttp://a.example/1\0\0";
        assert_eq!(lines(t), vec!["http://a.example/1", "https://b.example/2"]);
        assert_eq!(base64("aGVs\nbG8"), Some(b"hello".to_vec()));
    }
}
