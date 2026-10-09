fn render_layout(
    branding: &PublicBranding,
    lang: UiLanguage,
    title: &str,
    body: String,
    admin: bool,
) -> String {
    let direction = if lang.is_rtl() { "rtl" } else { "ltr" };
    let theme_class = if branding.dark_mode_default { "dark" } else { "light" };
    let page_class = if admin { "admin-page" } else { "public-page" };
    let viewport_content = "width=device-width, initial-scale=1";
    let favicon = asset_href(&branding.favicon_url, "favicon").or_else(|| Some("/assets/imonitor-mark.svg".to_string()));
    let public_theme = derive_public_theme_palette(branding);
    let base_glow_primary = rgba_from_hex(&branding.primary_color, 0.15);
    let base_glow_secondary = rgba_from_hex(&branding.secondary_color, 0.10);
    format!(
        r#"<!DOCTYPE html>
<html lang="{lang}" dir="{direction}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="{viewport_content}">
  <title>{title}</title>
  {favicon}
  <link rel="preload" href="{font_preload}" as="font" type="font/ttf" crossorigin>
  <style>{base_css}
{glass_css}</style>
</head>
<body class="{theme_class} {page_class}">
  <main class="frame">{body}</main>
</body>
</html>"#,
        base_css = render_template(include_str!("base.css"), &[
            ("primary", (html_escape(&branding.primary_color)).to_string()),
            ("secondary", (html_escape(&branding.secondary_color)).to_string()),
            ("background", (html_escape(&branding.background_color)).to_string()),
            ("public_dark_bg", (public_theme.dark_bg).to_string()),
            ("public_dark_elevated", (public_theme.dark_elevated).to_string()),
            ("public_dark_panel", (public_theme.dark_panel).to_string()),
            ("public_dark_panel_soft", (public_theme.dark_panel_soft).to_string()),
            ("public_dark_input", (public_theme.dark_input).to_string()),
            ("public_dark_border", (public_theme.dark_border).to_string()),
            ("public_dark_border_strong", (public_theme.dark_border_strong).to_string()),
            ("public_dark_text", (public_theme.dark_text).to_string()),
            ("public_dark_text_soft", (public_theme.dark_text_soft).to_string()),
            ("public_dark_shadow", (public_theme.dark_shadow).to_string()),
            ("public_light_bg", (public_theme.light_bg).to_string()),
            ("public_light_elevated", (public_theme.light_elevated).to_string()),
            ("public_light_panel", (public_theme.light_panel).to_string()),
            ("public_light_panel_soft", (public_theme.light_panel_soft).to_string()),
            ("public_light_input", (public_theme.light_input).to_string()),
            ("public_light_border", (public_theme.light_border).to_string()),
            ("public_light_border_strong", (public_theme.light_border_strong).to_string()),
            ("public_light_text", (public_theme.light_text).to_string()),
            ("public_light_text_soft", (public_theme.light_text_soft).to_string()),
            ("public_light_shadow", (public_theme.light_shadow).to_string()),
            ("base_glow_primary", (base_glow_primary).to_string()),
            ("base_glow_secondary", (base_glow_secondary).to_string()),
            ("width", (if admin { "1540px" } else { "1220px" }).to_string()),
            ("public_dark_glow_primary", (public_theme.dark_glow_primary).to_string()),
            ("public_dark_glow_secondary", (public_theme.dark_glow_secondary).to_string()),
            ("public_light_glow_primary", (public_theme.light_glow_primary).to_string()),
            ("public_light_glow_secondary", (public_theme.light_glow_secondary).to_string()),
        ]),
        glass_css = include_str!("glass.css"),
        font_preload = if lang.is_rtl() { "/assets/fonts/vazirmatn.ttf" } else { "/assets/fonts/ibm-plex-sans.ttf" },
        lang = lang.as_str(),
        direction = direction,
        viewport_content = viewport_content,
        title = html_escape(title),
        favicon = favicon
            .map(|url| format!(r#"<link rel="icon" href="{}">"#, html_escape(&url)))
            .unwrap_or_default(),
        theme_class = theme_class,
        page_class = page_class,
        body = body,
    )
}

#[derive(Clone, Copy)]
struct RgbColor {
    r: u8,
    g: u8,
    b: u8,
}

struct PublicThemePalette {
    dark_bg: String,
    dark_elevated: String,
    dark_panel: String,
    dark_panel_soft: String,
    dark_input: String,
    dark_border: String,
    dark_border_strong: String,
    dark_text: String,
    dark_text_soft: String,
    dark_shadow: String,
    dark_glow_primary: String,
    dark_glow_secondary: String,
    light_bg: String,
    light_elevated: String,
    light_panel: String,
    light_panel_soft: String,
    light_input: String,
    light_border: String,
    light_border_strong: String,
    light_text: String,
    light_text_soft: String,
    light_shadow: String,
    light_glow_primary: String,
    light_glow_secondary: String,
}

fn derive_public_theme_palette(branding: &PublicBranding) -> PublicThemePalette {
    let primary = parse_hex_color(&branding.primary_color).unwrap_or(RgbColor {
        r: 34,
        g: 197,
        b: 94,
    });
    let secondary = parse_hex_color(&branding.secondary_color).unwrap_or(RgbColor {
        r: 22,
        g: 163,
        b: 74,
    });
    let background = parse_hex_color(&branding.background_color).unwrap_or(RgbColor {
        r: 6,
        g: 17,
        b: 10,
    });
    let white = RgbColor {
        r: 255,
        g: 255,
        b: 255,
    };
    let black = RgbColor { r: 0, g: 0, b: 0 };

    let dark_bg = mix_colors(background, black, 0.08);
    let dark_panel = mix_colors(background, white, 0.08);
    let dark_panel_soft = mix_colors(background, white, 0.12);
    let dark_input = mix_colors(background, white, 0.10);
    let dark_text = mix_colors(white, primary, 0.08);
    let dark_text_soft = mix_colors(white, primary, 0.42);

    let light_bg = mix_colors(white, primary, 0.07);
    let light_panel = mix_colors(white, primary, 0.02);
    let light_panel_soft = mix_colors(white, primary, 0.04);
    let light_input = mix_colors(white, primary, 0.01);
    let light_text = mix_colors(background, black, 0.18);
    let light_text_soft = mix_colors(light_text, white, 0.34);

    PublicThemePalette {
        dark_bg: rgb_to_hex(dark_bg),
        dark_elevated: rgba_string(dark_panel, 0.94),
        dark_panel: rgba_string(dark_panel, 0.96),
        dark_panel_soft: rgba_string(dark_panel_soft, 0.98),
        dark_input: rgba_string(dark_input, 0.98),
        dark_border: rgba_string(primary, 0.18),
        dark_border_strong: rgba_string(primary, 0.28),
        dark_text: rgb_to_hex(dark_text),
        dark_text_soft: rgb_to_hex(dark_text_soft),
        dark_shadow: format!("0 24px 56px {}", rgba_string(black, 0.30)),
        dark_glow_primary: rgba_string(primary, 0.20),
        dark_glow_secondary: rgba_string(secondary, 0.14),
        light_bg: rgb_to_hex(light_bg),
        light_elevated: rgba_string(white, 0.96),
        light_panel: rgba_string(light_panel, 0.98),
        light_panel_soft: rgba_string(light_panel_soft, 0.99),
        light_input: rgba_string(light_input, 0.99),
        light_border: rgba_string(primary, 0.16),
        light_border_strong: rgba_string(primary, 0.24),
        light_text: rgb_to_hex(light_text),
        light_text_soft: rgb_to_hex(light_text_soft),
        light_shadow: format!("0 18px 42px {}", rgba_string(black, 0.08)),
        light_glow_primary: rgba_string(primary, 0.11),
        light_glow_secondary: rgba_string(secondary, 0.08),
    }
}

fn parse_hex_color(value: &str) -> Option<RgbColor> {
    let trimmed = value.trim().trim_start_matches('#');
    if trimmed.len() != 6 {
        return None;
    }

    let r = u8::from_str_radix(&trimmed[0..2], 16).ok()?;
    let g = u8::from_str_radix(&trimmed[2..4], 16).ok()?;
    let b = u8::from_str_radix(&trimmed[4..6], 16).ok()?;
    Some(RgbColor { r, g, b })
}

fn mix_colors(base: RgbColor, other: RgbColor, other_weight: f64) -> RgbColor {
    let weight = other_weight.clamp(0.0, 1.0);
    let base_weight = 1.0 - weight;
    RgbColor {
        r: ((base.r as f64 * base_weight) + (other.r as f64 * weight)).round() as u8,
        g: ((base.g as f64 * base_weight) + (other.g as f64 * weight)).round() as u8,
        b: ((base.b as f64 * base_weight) + (other.b as f64 * weight)).round() as u8,
    }
}

fn rgb_to_hex(color: RgbColor) -> String {
    format!("#{:02x}{:02x}{:02x}", color.r, color.g, color.b)
}

fn rgba_string(color: RgbColor, alpha: f64) -> String {
    format!(
        "rgba({}, {}, {}, {:.3})",
        color.r,
        color.g,
        color.b,
        alpha.clamp(0.0, 1.0)
    )
}

fn rgba_from_hex(value: &str, alpha: f64) -> String {
    parse_hex_color(value)
        .map(|color| rgba_string(color, alpha))
        .unwrap_or_else(|| format!("rgba(34, 197, 94, {:.3})", alpha.clamp(0.0, 1.0)))
}

