//! Appearance stream of visible signatures: text (AutoFirma's `layer2Text`)
//! over an optional rubric image, drawn with a standard 14 font.

use std::io::Write;

use flate2::{Compression, write::ZlibEncoder};
use lopdf::{Dictionary, Object, Stream};
use serde::{Deserialize, Serialize};

use super::{font_metrics, pdf::format_number};
use crate::error::{Error, Result};

/// Font family of the signature text (AutoFirma's `layer2FontFamily`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FontFamily {
    /// Courier, AutoFirma's default (`0`).
    #[default]
    Courier,
    /// Helvetica (`1`).
    Helvetica,
    /// Times Roman (`2`).
    Times,
}

/// Text color (AutoFirma's `layer2FontColor` names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FontColor {
    /// Black (default).
    #[default]
    Black,
    /// White.
    White,
    /// Light gray.
    LightGray,
    /// Gray.
    Gray,
    /// Dark gray.
    DarkGray,
    /// Red.
    Red,
    /// Pink.
    Pink,
}

impl FontColor {
    fn rgb(self) -> [u8; 3] {
        match self {
            FontColor::Black => [0, 0, 0],
            FontColor::White => [255, 255, 255],
            FontColor::LightGray => [192, 192, 192],
            FontColor::Gray => [128, 128, 128],
            FontColor::DarkGray => [64, 64, 64],
            FontColor::Red => [255, 0, 0],
            FontColor::Pink => [255, 175, 175],
        }
    }
}

/// Font of the signature text.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Font {
    /// Family.
    pub family: FontFamily,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Size in points (AutoFirma's default is 12).
    pub size: f32,
    /// Color.
    pub color: FontColor,
}

impl Default for Font {
    fn default() -> Self {
        Font {
            family: FontFamily::Courier,
            bold: false,
            italic: false,
            size: 12.0,
            color: FontColor::Black,
        }
    }
}

impl Font {
    fn base_font(&self) -> &'static str {
        match (self.family, self.bold, self.italic) {
            (FontFamily::Courier, false, false) => "Courier",
            (FontFamily::Courier, true, false) => "Courier-Bold",
            (FontFamily::Courier, false, true) => "Courier-Oblique",
            (FontFamily::Courier, true, true) => "Courier-BoldOblique",
            (FontFamily::Helvetica, false, false) => "Helvetica",
            (FontFamily::Helvetica, true, false) => "Helvetica-Bold",
            (FontFamily::Helvetica, false, true) => "Helvetica-Oblique",
            (FontFamily::Helvetica, true, true) => "Helvetica-BoldOblique",
            (FontFamily::Times, false, false) => "Times-Roman",
            (FontFamily::Times, true, false) => "Times-Bold",
            (FontFamily::Times, false, true) => "Times-Italic",
            (FontFamily::Times, true, true) => "Times-BoldItalic",
        }
    }

    fn widths(&self) -> Option<&'static [u16; 224]> {
        use font_metrics::*;
        match (self.family, self.bold, self.italic) {
            (FontFamily::Courier, ..) => None,
            (FontFamily::Helvetica, false, false) => Some(&HELVETICA),
            (FontFamily::Helvetica, true, false) => Some(&HELVETICA_BOLD),
            (FontFamily::Helvetica, false, true) => Some(&HELVETICA_OBLIQUE),
            (FontFamily::Helvetica, true, true) => Some(&HELVETICA_BOLDOBLIQUE),
            (FontFamily::Times, false, false) => Some(&TIMES_ROMAN),
            (FontFamily::Times, true, false) => Some(&TIMES_BOLD),
            (FontFamily::Times, false, true) => Some(&TIMES_ITALIC),
            (FontFamily::Times, true, true) => Some(&TIMES_BOLDITALIC),
        }
    }

    /// Width of WinAnsi encoded `text` at `size`.
    fn text_width(&self, text: &[u8], size: f32) -> f32 {
        let units: u32 = text
            .iter()
            .map(|&b| match self.widths() {
                None => 600,
                Some(widths) => u32::from(b.checked_sub(32).map_or(0, |i| widths[usize::from(i)])),
            })
            .sum();
        units as f32 * size / 1000.0
    }

    /// Font dictionary for the page resources.
    pub(crate) fn dictionary(&self) -> Dictionary {
        let mut dict = Dictionary::new();
        dict.set("Type", Object::Name(b"Font".to_vec()));
        dict.set("Subtype", Object::Name(b"Type1".to_vec()));
        dict.set(
            "BaseFont",
            Object::Name(self.base_font().as_bytes().to_vec()),
        );
        dict.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
        dict
    }
}

/// Encodes `text` in WinAnsiEncoding (Windows-1252); other characters become `?`.
pub(crate) fn win_ansi(text: &str) -> Vec<u8> {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
        '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}',
        'ž', 'Ÿ',
    ];
    text.chars()
        .map(|c| match c as u32 {
            0x20..=0x7e | 0xa0..=0xff => c as u8,
            _ => HIGH
                .iter()
                .position(|&h| h == c && !matches!(c as u32, 0x80..=0x9f))
                .map_or(b'?', |i| 0x80 + i as u8),
        })
        .collect()
}

/// A rubric image ready to be embedded.
#[derive(Debug)]
pub(crate) struct Image {
    pub width: u32,
    pub height: u32,
    pub stream: Stream,
    /// Alpha channel (`SMask`), for PNG images with transparency.
    pub alpha: Option<Stream>,
}

impl Image {
    /// Decodes a JPEG (embedded as is) or PNG rubric image.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.starts_with(&[0xff, 0xd8]) {
            jpeg(data)
        } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            png(data)
        } else {
            Err(Error::Unsupported(
                "la imagen de la rúbrica debe ser JPEG o PNG".to_string(),
            ))
        }
    }
}

fn image_dict(width: u32, height: u32, color_space: &str, bits: u8) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Image".to_vec()));
    dict.set("Width", i64::from(width));
    dict.set("Height", i64::from(height));
    dict.set("ColorSpace", Object::Name(color_space.as_bytes().to_vec()));
    dict.set("BitsPerComponent", i64::from(bits));
    dict
}

fn jpeg(data: &[u8]) -> Result<Image> {
    let invalid = || Error::Unsupported("imagen JPEG no válida".to_string());
    let mut pos = 2;
    let mut adobe = false;
    loop {
        // Skip fill bytes before the marker.
        while data.get(pos) == Some(&0xff) && data.get(pos + 1) == Some(&0xff) {
            pos += 1;
        }
        let (Some(0xff), Some(&marker)) = (data.get(pos), data.get(pos + 1)) else {
            return Err(invalid());
        };
        let len = usize::from(u16::from_be_bytes([
            *data.get(pos + 2).ok_or_else(invalid)?,
            *data.get(pos + 3).ok_or_else(invalid)?,
        ]));
        let segment = data.get(pos + 4..pos + 2 + len).ok_or_else(invalid)?;
        match marker {
            0xee if segment.starts_with(b"Adobe") => adobe = true,
            // SOFn, except DHT (C4), JPG (C8) and DAC (CC).
            0xc0..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                let [bits, h1, h0, w1, w0, components, ..] = *segment else {
                    return Err(invalid());
                };
                let color_space = match components {
                    1 => "DeviceGray",
                    3 => "DeviceRGB",
                    4 => "DeviceCMYK",
                    _ => return Err(invalid()),
                };
                let (width, height) = (
                    u32::from(u16::from_be_bytes([w1, w0])),
                    u32::from(u16::from_be_bytes([h1, h0])),
                );
                let mut dict = image_dict(width, height, color_space, bits);
                dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
                if components == 4 && adobe {
                    // Adobe CMYK JPEGs are stored inverted.
                    dict.set(
                        "Decode",
                        [1, 0, 1, 0, 1, 0, 1, 0].map(Object::Integer).to_vec(),
                    );
                }
                return Ok(Image {
                    width,
                    height,
                    stream: Stream::new(dict, data.to_vec()).with_compression(false),
                    alpha: None,
                });
            }
            0xd9 | 0xda => return Err(invalid()),
            _ => {}
        }
        pos += 2 + len;
    }
}

fn png(data: &[u8]) -> Result<Image> {
    let invalid =
        |e: &dyn std::fmt::Display| Error::Unsupported(format!("imagen PNG no válida: {e}"));
    let mut decoder = png::Decoder::new(std::io::Cursor::new(data));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|e| invalid(&e))?;
    let mut pixels = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or_else(|| invalid(&"demasiado grande"))?
    ];
    let info = reader.next_frame(&mut pixels).map_err(|e| invalid(&e))?;
    pixels.truncate(info.buffer_size());

    let (channels, color_space) = match info.color_type {
        png::ColorType::Grayscale => (1, "DeviceGray"),
        png::ColorType::GrayscaleAlpha => (2, "DeviceGray"),
        png::ColorType::Rgb => (3, "DeviceRGB"),
        png::ColorType::Rgba => (4, "DeviceRGB"),
        png::ColorType::Indexed => return Err(invalid(&"paleta no expandida")),
    };
    let color_channels = if channels % 2 == 0 {
        channels - 1
    } else {
        channels
    };
    let (mut color, mut alpha) = (Vec::with_capacity(pixels.len()), Vec::new());
    for pixel in pixels.chunks_exact(channels) {
        color.extend_from_slice(&pixel[..color_channels]);
        if color_channels != channels {
            alpha.push(pixel[channels - 1]);
        }
    }

    let flate = |bytes: &[u8], dict: Dictionary| -> Result<Stream> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).map_err(|e| invalid(&e))?;
        let mut dict = dict;
        dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        Ok(Stream::new(dict, encoder.finish().map_err(|e| invalid(&e))?).with_compression(false))
    };
    let alpha = (!alpha.is_empty() && alpha.iter().any(|&a| a != 255))
        .then(|| flate(&alpha, image_dict(info.width, info.height, "DeviceGray", 8)))
        .transpose()?;
    Ok(Image {
        width: info.width,
        height: info.height,
        stream: flate(&color, image_dict(info.width, info.height, color_space, 8))?,
        alpha,
    })
}

/// Margin between the field border and the text, as in iText.
const MARGIN: f32 = 2.0;
/// Smallest font size used when shrinking the text to fit.
const MIN_FONT_SIZE: f32 = 4.0;

/// Content stream drawing the image (scaled to fit, centered) and the `text`
/// lines inside a `width` x `height` box. The font is `/F1`, the image `/Img`.
pub(crate) fn content(
    text: &str,
    font: &Font,
    width: f32,
    height: f32,
    image: Option<(u32, u32)>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let n = format_number;

    if let Some((image_width, image_height)) = image {
        let scale = (width / image_width as f32).min(height / image_height as f32);
        let (w, h) = (image_width as f32 * scale, image_height as f32 * scale);
        let x = n((width - w) / 2.0);
        let y = n((height - h) / 2.0);
        out.extend_from_slice(format!("q {} 0 0 {} {x} {y} cm /Img Do Q\n", n(w), n(h)).as_bytes());
    }

    let text = text.trim_end();
    if text.is_empty() {
        return out;
    }
    let available_width = (width - 2.0 * MARGIN).max(1.0);
    let available_height = height - 2.0 * MARGIN;

    // Shrink the font until the wrapped text fits in the box.
    let mut size = font.size.max(MIN_FONT_SIZE);
    let mut lines = wrap(text, font, size, available_width);
    while lines.len() as f32 * size > available_height && size > MIN_FONT_SIZE {
        size = (size - 0.5).max(MIN_FONT_SIZE);
        lines = wrap(text, font, size, available_width);
    }

    let [r, g, b] = font.color.rgb().map(|c| n(f32::from(c) / 255.0));
    out.extend_from_slice(format!("BT\n/F1 {} Tf\n{r} {g} {b} rg\n", n(size)).as_bytes());
    let mut y = height - MARGIN - size;
    for line in lines {
        if y < MARGIN - size {
            break;
        }
        out.extend_from_slice(format!("1 0 0 1 {} {} Tm\n", n(MARGIN), n(y)).as_bytes());
        super::pdf::write_object(
            &mut out,
            &Object::String(line, lopdf::StringFormat::Literal),
        );
        out.extend_from_slice(b" Tj\n");
        y -= size;
    }
    out.extend_from_slice(b"ET\n");
    out
}

/// Splits `text` into lines (at `\n` and between words) no wider than `max_width`.
fn wrap(text: &str, font: &Font, size: f32, max_width: f32) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let paragraph = win_ansi(paragraph.trim_end_matches('\r'));
        let mut line: Vec<u8> = Vec::new();
        for word in paragraph.split(|&b| b == b' ') {
            let candidate = if line.is_empty() {
                word.to_vec()
            } else {
                [line.as_slice(), b" ", word].concat()
            };
            if font.text_width(&candidate, size) <= max_width || line.is_empty() && word.is_empty()
            {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            // Break words longer than the line.
            let mut word = word;
            while font.text_width(word, size) > max_width && word.len() > 1 {
                let fit = (1..word.len())
                    .rev()
                    .find(|&i| font.text_width(&word[..i], size) <= max_width)
                    .unwrap_or(1);
                lines.push(word[..fit].to_vec());
                word = &word[fit..];
            }
            line = word.to_vec();
        }
        lines.push(line);
    }
    lines
}

/// Appearance `Matrix` that keeps the content upright on a page with `/Rotate rotation`.
pub(crate) fn rotation_matrix(rotation: i64) -> Option<[f32; 6]> {
    match rotation.rem_euclid(360) {
        90 => Some([0.0, 1.0, -1.0, 0.0, 0.0, 0.0]),
        180 => Some([-1.0, 0.0, 0.0, -1.0, 0.0, 0.0]),
        270 => Some([0.0, -1.0, 1.0, 0.0, 0.0, 0.0]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_win_ansi() {
        assert_eq!(win_ansi("día €"), b"d\xeda \x80");
        assert_eq!(win_ansi("\u{81}ĉ"), b"??");
    }

    #[test]
    fn wraps_text() {
        let font = Font::default(); // Courier 12: 7.2 points per character
        let lines = wrap("Firmado por JUAN ESPAÑOL\nFecha", &font, 12.0, 75.0);
        assert_eq!(
            lines,
            [
                b"Firmado".to_vec(),
                b"por JUAN".to_vec(),
                b"ESPA\xd1OL".to_vec(),
                b"Fecha".to_vec()
            ]
        );
        // A word longer than the line is split.
        assert_eq!(wrap("123456789012", &font, 12.0, 40.0).len(), 3);
    }

    #[test]
    fn helvetica_metrics() {
        let font = Font {
            family: FontFamily::Helvetica,
            ..Font::default()
        };
        // "Hi": H = 722, i = 222.
        assert!((font.text_width(b"Hi", 10.0) - 9.44).abs() < 1e-4);
    }

    #[test]
    fn content_stream() {
        let content = content(
            "Firmado por\nJosé",
            &Font::default(),
            200.0,
            70.0,
            Some((100, 50)),
        );
        let text = String::from_utf8_lossy(&content);
        assert!(
            text.starts_with("q 140 0 0 70 30 0 cm /Img Do Q\n"),
            "{text}"
        );
        assert!(text.contains("/F1 12 Tf"));
        assert!(text.contains("1 0 0 1 2 56 Tm\n(Firmado por) Tj\n1 0 0 1 2 44 Tm\n"));
        assert!(content.windows(6).any(|w| w == b"(Jos\xe9)"));
    }

    #[test]
    fn shrinks_text_to_fit() {
        // 8 lines in 36 points (40 minus the margins): 4.5 points per line.
        let content = content(
            "a\nb\nc\nd\ne\nf\ng\nh",
            &Font::default(),
            100.0,
            40.0,
            None,
        );
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("/F1 4.5 Tf"), "{text}");
        assert_eq!(text.matches(" Tj").count(), 8);
    }

    #[test]
    fn decodes_images() {
        // 1x1 red PNG with alpha.
        let mut png_data = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png_data, 1, 1);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[255, 0, 0, 128]).unwrap();
        }
        let image = Image::decode(&png_data).unwrap();
        assert_eq!((image.width, image.height), (1, 1));
        assert!(image.alpha.is_some());

        // Minimal JPEG header: SOI, SOF0 (8 bits, 2x3, 3 components).
        let jpeg_data = [
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x03, 0x00, 0x02, 0x03, 1, 0x11, 0, 2,
            0x11, 0, 3, 0x11, 0,
        ];
        let image = Image::decode(&jpeg_data).unwrap();
        assert_eq!((image.width, image.height), (2, 3));
        assert_eq!(image.stream.content, jpeg_data);

        assert!(Image::decode(b"GIF89a").is_err());
    }
}
