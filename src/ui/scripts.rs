fn render_admin_dashboard_script(lang: UiLanguage) -> String {
    let fetch_failed = copy(lang, "به‌روزرسانی زنده متریک‌ها با خطا روبه‌رو شد.", "Live metric refresh failed.");
    let builder_create = copy(lang, "ساخت مانیتور جدید", "Create a New Monitor");
    let builder_edit_prefix = copy(lang, "در حال ویرایش", "Editing");
    let analytics_loading = copy(lang, "در حال بارگذاری تحلیل مانیتور...", "Loading monitor analytics...");
    let analytics_error = copy(lang, "بارگذاری تحلیل مانیتور با خطا روبه‌رو شد.", "Failed to load monitor analytics.");
    let analytics_no_rows = copy(lang, "برای این بازه داده‌ای ثبت نشده است.", "No data was recorded for this range.");
    let tunnel_diag_error = copy(lang, "اجرای تست زنده‌ی تونل با خطا روبه‌رو شد.", "Failed to run live tunnel diagnostics.");
    let tunnel_saved_outer = copy(lang, "ثبت‌شده / سفارشی", "Saved / Custom");
    let tunnel_saved_source = copy(lang, "سفارشی", "Custom");
    let branding_upload_failed = copy(lang, "آپلود تصویر برندینگ با خطا روبه‌رو شد.", "Branding image upload failed.");
    let branding_upload_image_only = copy(lang, "فقط فایل تصویری انتخاب کنید.", "Please choose an image file.");
    let branding_upload_too_large = copy(lang, "فایل تصویر باید حداکثر 8 مگابایت باشد.", "Please choose an image up to 8 MB.");
    let branding_upload_decode_error = copy(lang, "مرورگر نتوانست فایل انتخاب‌شده را بخواند.", "The selected file could not be read by the browser.");
    let branding_upload_canvas_error = copy(lang, "مرورگر این فایل را برای تبدیل آماده نکرد.", "The browser could not prepare this image for upload.");
    format!("<script>{}</script><script>{}</script>",
        render_template(include_str!("admin.js"), &[
        ("builder_create", html_escape(builder_create)),
        ("branding_upload_decode_error", html_escape(branding_upload_decode_error)),
        ("branding_upload_canvas_error", html_escape(branding_upload_canvas_error)),
        ("branding_upload_image_only", html_escape(branding_upload_image_only)),
        ("branding_upload_too_large", html_escape(branding_upload_too_large)),
        ("builder_edit_prefix", html_escape(builder_edit_prefix)),
        ("tunnel_saved_outer", html_escape(tunnel_saved_outer)),
        ("tunnel_saved_source", html_escape(tunnel_saved_source)),
        ("tunnel_diag_error", html_escape(tunnel_diag_error)),
        ("analytics_no_rows", html_escape(analytics_no_rows)),
        ("analytics_loading", html_escape(analytics_loading)),
        ("analytics_error", html_escape(analytics_error)),
        ("branding_upload_failed", html_escape(branding_upload_failed)),
        ("fetch_failed", html_escape(fetch_failed)),
        ]), include_str!("workspace.js"))
}


