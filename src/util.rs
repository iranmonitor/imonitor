use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn random_hex(byte_len: usize) -> Result<String, String> {
    let bytes = random_bytes(byte_len)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_u16() -> Result<u16, String> {
    let bytes = random_bytes(2)?;
    let mut array = [0_u8; 2];
    array.copy_from_slice(&bytes);
    Ok(u16::from_be_bytes(array))
}

pub fn random_bytes(byte_len: usize) -> Result<Vec<u8>, String> {
    use ring::rand::SecureRandom;
    let mut bytes = vec![0_u8; byte_len];
    ring::rand::SystemRandom::new().fill(&mut bytes)
        .map_err(|_| "failed to generate secure random bytes".to_string())?;
    Ok(bytes)
}

pub fn pick_free_tcp_port(bind_host: &str, start: u16, end: u16) -> Result<u16, String> {
    if start == 0 || end == 0 || start > end {
        return Err(format!("invalid tcp port range {start}-{end}"));
    }

    let span = u32::from(end - start) + 1;
    for _ in 0..128 {
        let candidate = start + (u32::from(random_u16()?) % span) as u16;
        if let Ok(listener) = TcpListener::bind((bind_host, candidate)) {
            drop(listener);
            return Ok(candidate);
        }
    }

    for candidate in start..=end {
        if let Ok(listener) = TcpListener::bind((bind_host, candidate)) {
            drop(listener);
            return Ok(candidate);
        }
    }

    Err(format!(
        "could not find a free tcp port on {bind_host} in range {start}-{end}"
    ))
}

pub fn create_password_hash(password: &str) -> Result<String, String> {
    let salt_bytes = random_bytes(16)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| format!("failed to encode password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("failed to hash password: {error}"))
}

pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, String> {
    if stored_hash.starts_with("$argon2") {
        let parsed = PasswordHash::new(stored_hash)
            .map_err(|error| format!("invalid password hash: {error}"))?;
        return Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok());
    }

    // Keep existing accounts usable. New and changed passwords are always Argon2id.
    let Some((salt, digest)) = stored_hash.split_once('$') else {
        return Ok(false);
    };
    let computed = sha256_hex(&format!("{salt}:{password}"))?;
    Ok(computed == digest)
}

pub fn sha256_hex(input: &str) -> Result<String, String> {
    let mut child = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-hex")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to execute openssl: {error}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| format!("failed to write to openssl stdin: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for openssl: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let digest = stdout
        .split('=')
        .nth(1)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if digest.is_empty() {
        Err("openssl did not return a sha256 digest".to_string())
    } else {
        Ok(digest)
    }
}

pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn bytes_to_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut index = 0;
    while value >= 1024.0 && index < UNITS.len() - 1 {
        value /= 1024.0;
        index += 1;
    }
    format!("{value:.1} {}", UNITS[index])
}

pub fn bits_to_human(bits_per_sec: u64) -> String {
    const UNITS: [&str; 4] = ["bps", "Kbps", "Mbps", "Gbps"];
    let mut value = bits_per_sec as f64;
    let mut index = 0;
    while value >= 1000.0 && index < UNITS.len() - 1 {
        value /= 1000.0;
        index += 1;
    }
    format!("{value:.1} {}", UNITS[index])
}

pub fn decode_base64_lenient(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity((cleaned.len() * 3) / 4 + 3);
    let mut accumulator: u32 = 0;
    let mut bit_count: u8 = 0;

    for byte in cleaned {
        if byte == b'=' {
            break;
        }
        let value = decode_base64_char(byte)
            .ok_or_else(|| format!("invalid base64 character: {}", byte as char))?
            as u32;
        accumulator = (accumulator << 6) | value;
        bit_count += 6;
        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((accumulator >> bit_count) & 0xff) as u8);
        }
    }

    Ok(output)
}

fn decode_base64_char(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

pub fn normalize_branding_image(
    input_bytes: &[u8],
    output_path: &Path,
    kind: &str,
) -> Result<(), String> {
    if input_bytes.is_empty() {
        return Err("uploaded image is empty".to_string());
    }

    let Some(parent) = output_path.parent() else {
        return Err(format!(
            "cannot determine parent directory for {}",
            output_path.display()
        ));
    };
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create branding asset directory {}: {error}",
            parent.display()
        )
    })?;

    let temp_input = std::env::temp_dir().join(format!("iranmonitor-upload-{}.bin", random_hex(8)?));
    fs::write(&temp_input, input_bytes).map_err(|error| {
        format!(
            "failed to write temporary uploaded image {}: {error}",
            temp_input.display()
        )
    })?;

    let script = r#"
import sys
from PIL import Image, ImageOps

src, dest, mode = sys.argv[1], sys.argv[2], sys.argv[3]
resampling = getattr(Image, "Resampling", Image)

with Image.open(src) as img:
    image = img.convert("RGBA")
    if mode == "favicon":
        canvas = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        fitted = ImageOps.contain(image, (64, 64), resampling.LANCZOS)
        offset = ((64 - fitted.width) // 2, (64 - fitted.height) // 2)
        canvas.alpha_composite(fitted, offset)
        canvas.save(dest, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
    else:
        canvas = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
        fitted = ImageOps.contain(image, (512, 512), resampling.LANCZOS)
        offset = ((512 - fitted.width) // 2, (512 - fitted.height) // 2)
        canvas.alpha_composite(fitted, offset)
        canvas.save(dest, format="PNG")
"#;

    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&temp_input)
        .arg(output_path)
        .arg(kind)
        .output()
        .map_err(|error| format!("failed to execute python3 for image conversion: {error}"))?;
    let _ = fs::remove_file(&temp_input);

    if !output.status.success() {
        return Err(
            String::from_utf8_lossy(&output.stderr)
                .trim()
                .trim_matches('"')
                .to_string(),
        );
    }

    let metadata = fs::metadata(output_path).map_err(|error| {
        format!(
            "converted branding asset was not written to {}: {error}",
            output_path.display()
        )
    })?;
    if metadata.len() == 0 {
        return Err(format!(
            "converted branding asset {} is empty",
            output_path.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        create_password_hash,
        verify_password,
    };

    #[test]
    fn new_password_hashes_use_argon2id_and_verify() {
        let hash = create_password_hash("correct horse battery staple").expect("hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash).expect("verify"));
        assert!(!verify_password("wrong password", &hash).expect("reject"));
    }

}
