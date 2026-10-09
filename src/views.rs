use crate::app_types::{
    AdminDashboardData, AdminSection, AppSettings, HistoryPoint, HostIpInventoryEntry,
    MonitorCheckRow, MonitorFolder, PublicBranding, PublicCheckHistoryPoint,
    PublicCheckView, PublicStatusPayload, SnapshotSummary, SystemSample, UiLanguage,
};
use crate::http::url_encode;
use crate::util::{bits_to_human, bytes_to_human, html_escape};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct PublicMonitorFolder {
    name: String,
    logo_url: String,
    logo_shape: String,
    monitors: Vec<PublicCheckView>,
}

fn render_monitor_kind_options(lang: UiLanguage) -> String {
    [ ("icmp", "پینگ · ICMP", "Ping · ICMP"), ("tcp", "پورت TCP", "TCP port"), ("udp", "پاسخ UDP", "UDP response"),
      ("ssh", "بنر SSH", "SSH banner"), ("sftp", "SFTP / SSH", "SFTP / SSH"), ("http", "وب‌سایت · HTTP", "Website · HTTP"),
      ("https", "وب‌سایت · HTTPS", "Website · HTTPS"), ("dns", "رکورد DNS", "DNS record"), ("rdp", "دسکتاپ از راه دور", "Remote Desktop"),
      ("ftp", "FTP", "FTP"), ("v2ray", "پروکسی / V2Ray / Xray", "Proxy / V2Ray / Xray") ]
    .into_iter().map(|(value, fa_label, en_label)| format!(r#"<option value="{value}"{selected}>{label}</option>"#,
        label=copy(lang,fa_label,en_label), selected = if value == "https" { " selected" } else { "" }))
    .collect::<Vec<_>>().join("")
}

fn render_tunnel_protocol_options(_lang: UiLanguage) -> String {
    [ ("gre", "GRE · kernel tunnel"), ("ipv4_ip_in_ip", "IPv4 IP-in-IP · protocol 4"),
      ("ipip", "IPIP · Linux protocol 4"), ("ipv6_encapsulation", "IPv6 encapsulation · protocol 41"),
      ("etherip", "EtherIP · external interface required"), ("encap", "IP-in-IP over GUE / UDP"),
      ("gretap", "GRETAP · kernel Ethernet tunnel"), ("vxlan", "VXLAN · kernel UDP overlay"), ("geneve", "GENEVE · kernel UDP overlay"),
      ("l2tp", "L2TPv3"), ("esp", "ESP / XFRM · encrypted IPsec"),
      ("tun", "TUN · TCP / UDP / ICMP"), ("ssh", "SSH TUN"),
      ("reverse_ssh", "Reverse SSH TUN"), ("wireguard", "WireGuard · encrypted UDP") ]
    .into_iter().map(|(value, label)| format!(r#"<option value="{value}">{label}</option>"#))
    .collect::<Vec<_>>().join("")
}

pub fn render_admin_login(
    branding: &PublicBranding,
    lang: UiLanguage,
    error: Option<&str>,
) -> String {
    let body = format!(
        r#"
<section class="auth-shell fade-up">
  <div class="auth-card">
    <div class="brand-line brand-line--large">
      {logo}
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
    </div>
    <div class="section-divider"></div>
    <h2>{login_title}</h2>
    <p class="muted">{hint}</p>
    {error_html}
    <form method="post" action="/admin/login" class="stack-form">
      <div>
        <label>{username_label}</label>
        <input type="text" name="username" autocomplete="username" required>
      </div>
      <div>
        <label>{password_label}</label>
        <input type="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit">{login_button}</button>
    </form>
    <div class="lang-links">
      <a href="/admin/login?lang=fa">فارسی</a>
      <a href="/admin/login?lang=en">English</a>
    </div>
  </div>
</section>
"#,
        logo = render_logo(&branding.logo_url, &branding.title),
        title = html_escape(&branding.title),
        subtitle = html_escape(&branding.subtitle),
        login_title = t(lang, "admin_login"),
        username_label = t(lang, "username"),
        password_label = t(lang, "password"),
        login_button = t(lang, "sign_in"),
        hint = t(lang, "login_hint"),
        error_html = error
            .map(|message| format!(r#"<div class="alert alert--danger">{}</div>"#, html_escape(message)))
            .unwrap_or_default(),
    );
    render_layout(branding, lang, t(lang, "admin_panel"), body, true)
}

pub fn render_admin_dashboard(
    data: &AdminDashboardData,
    lang: UiLanguage,
    flash: Option<&str>,
    reverse_proxy_snippet: &str,
    section: AdminSection,
) -> String {
    let system = data.latest_system.as_ref();
    let warning_html = if data.warnings.is_empty() {
        String::new()
    } else {
        let items = data
            .warnings
            .iter()
            .map(|warning| format!(r#"<li>{}</li>"#, html_escape(warning)))
            .collect::<Vec<_>>()
            .join("");
        format!(
            r#"<div class="alert alert--warn"><ul class="compact-list">{items}</ul></div>"#
        )
    };

    let flash_html = flash
        .map(|message| format!(r#"<div class="alert alert--success">{}</div>"#, html_escape(message)))
        .unwrap_or_default();

    let metrics_html = render_admin_system_metrics_fragment(system, lang);
    let logo = render_logo(&data.public_payload.settings.logo_url, &data.public_payload.settings.title);
    let monitor_builder = render_monitor_builder_form(
        lang,
        &admin_section_href(AdminSection::Monitors, lang),
        &data.monitor_folders,
        &data.checks,
        &data.host_ip_inventory,
    );
    let theme_preset_selector = render_theme_preset_selector(&data.settings, lang);
    let dashboard_script = render_admin_dashboard_script(lang);
    let page_content = match section {
        AdminSection::Overview => render_admin_overview_section(data, lang, &metrics_html),
        AdminSection::ServerHealth => render_admin_server_health_section(data, lang),
        AdminSection::Monitors => render_admin_checks_section(data, lang, &monitor_builder, section),
        AdminSection::Tunnels => render_admin_checks_section(data, lang, &render_tunnel_builder(data, lang), section),
        AdminSection::Guide => render_admin_guide_section(lang),
        AdminSection::Folders => render_admin_folders_section(data, lang),
        AdminSection::Notifications => render_admin_notifications_section(data, lang),
        AdminSection::Backups => render_admin_backups_section(data, lang),
        AdminSection::SourceIp => render_admin_source_ip_section(data, lang),
        AdminSection::Settings =>
            render_admin_settings_section(data, lang, &theme_preset_selector, reverse_proxy_snippet),
        AdminSection::NetworkControls => render_admin_enterprise_section(data, lang),
        AdminSection::Forwarding => render_admin_forwarding_section(data, lang),
        AdminSection::Sockets => render_admin_sockets_section(data, lang),
        AdminSection::Reports => render_admin_reports_section(data, lang),
    };

    let body = format!(
        r##"
<section class="admin-shell fade-up" dir="ltr" data-workspace-section="{section_key}" data-account="{account}">
  <aside class="card admin-sidebar" dir="{content_dir}">
    <div class="admin-sidebar__brand">
      <div class="brand-line brand-line--large">
        {logo}
        <div>
          <h1>{app_name}</h1>
          <div class="admin-release-bar">
            <span class="pill {release_class}">v{current_release}</span>
            <span class="table-secondary">{release_text}</span>
          </div>
          <form method="post" action="/admin/self-update" class="admin-release-update">
            <input type="hidden" name="return_to" value="{return_to}">
            <button type="submit" class="ghost {release_button_class}">{update_label}</button>
          </form>
        </div>
      </div>
    </div>
    <div class="admin-sidebar__meta">
      <span class="pill pill--soft">{free_label}</span>
      <a class="ghost ghost--subtle" href="/?lang={lang_code}" target="_blank" rel="noopener">{public_status}</a>
    </div>
    <nav class="admin-sidebar__nav">
      {section_nav}
    </nav>
    <div class="admin-sidebar__footer">
      <a class="ghost ghost--subtle" href="{public_fa_href}">فارسی</a>
      <a class="ghost ghost--subtle" href="{public_en_href}">English</a>
    </div>
  </aside>
  <div class="admin-main" dir="{content_dir}">
    {flash_html}
    {warning_html}
    <header class="workspace-topbar"><div><span class="eyebrow">{workspace_label}</span><h2>{section_title}</h2></div><div class="workspace-topbar__actions"><a class="ghost ghost--subtle" href="{language_href}">{language_label}</a><button class="ghost ghost--subtle" type="button" data-start-tour>{guide_button}</button><a class="ghost ghost--subtle" href="/admin/logout">{logout_label}</a></div></header>
    {page_content}
    {admin_ad}
  </div>
</section>
{dashboard_script}
"##,
        section_key = admin_section_key(section),
        account = html_escape(&data.admin_username),
        logo = logo,
        app_name = html_escape(&data.settings.app_name),
        current_release = html_escape(&data.current_release_version),
        release_class = admin_release_status_class(
            &data.current_release_version,
            &data.latest_release_version,
        ),
        release_text = html_escape(&admin_release_status_text(
            &data.current_release_version,
            &data.latest_release_version,
            lang,
        )),
        release_button_class = admin_release_button_class(
            &data.current_release_version,
            &data.latest_release_version,
        ),
        update_label = html_escape(copy(lang, "به‌روزرسانی", "Update")),
        return_to = html_escape(&admin_section_href(section, lang)),
        free_label = copy(lang,"رایگان برای همه","Free for everyone"),
        lang_code = lang.as_str(),
        content_dir = if lang.is_rtl() { "rtl" } else { "ltr" },
        public_status = t(lang, "public_status"),
        public_fa_href = html_escape(&admin_section_href(section, UiLanguage::Fa)),
        public_en_href = html_escape(&admin_section_href(section, UiLanguage::En)),
        flash_html = flash_html,
        warning_html = warning_html,
        section_nav = render_admin_sidebar_nav(section, lang),
        workspace_label = copy(lang,"فضای مدیریت","YOUR WORKSPACE"),
        section_title = admin_section_label(section,lang),
        guide_button = copy(lang,"راهنما","Help & tour"),
        language_href = admin_section_href(section,if lang.is_rtl() { UiLanguage::En } else { UiLanguage::Fa }),
        language_label = if lang.is_rtl() { "English" } else { "فارسی" },
        logout_label = copy(lang,"خروج","Sign out"),
        admin_ad = crate::ads::render_slot("admin", lang),
        page_content = page_content,
        dashboard_script = dashboard_script,
    );

    render_layout(
        &data.public_payload.settings,
        lang,
        t(lang, "admin_panel"),
        body,
        true,
    )
}

fn render_admin_server_health_section(data: &AdminDashboardData, lang: UiLanguage) -> String {


    let Some(report) = data.server_health.as_ref() else {
        return format!(
            r#"<section class="card"><div class="section-header"><h2>{title}</h2><p>{body}</p></div></section>"#,
            title = html_escape(admin_section_label(AdminSection::ServerHealth, lang)),
            body = html_escape(copy(
                lang,
                "گزارش سلامت سرور هنوز آماده نشده است.",
                "The server health report is not ready yet.",
            )),
        );
    };

    let metrics = [
        (
            copy(lang, "سیستم‌عامل", "Operating System"),
            report.distro.clone(),
        ),
        (copy(lang, "کرنل", "Kernel"), report.kernel.clone()),
        (
            copy(lang, "پردازنده", "Processor"),
            format!("{} • {} {}", report.cpu_model, report.cpu_count, copy(lang, "هسته", "cores")),
        ),
        (
            copy(lang, "RAM", "RAM"),
            format_bytes(report.total_ram_bytes),
        ),
        (
            copy(lang, "دیسک", "Disk"),
            format_bytes(report.total_disk_bytes),
        ),
        (
            copy(lang, "به‌روزرسانی‌ها", "Updates"),
            if report.updates_summary.trim().is_empty() {
                copy(lang, "نامشخص", "Unknown").to_string()
            } else {
                report.updates_summary.clone()
            },
        ),
    ]
    .into_iter()
    .map(|(label, value)| {
        format!(
            r#"<article class="analytics-stat-card"><span>{}</span><strong>{}</strong></article>"#,
            html_escape(label),
            html_escape(&value),
        )
    })
    .collect::<Vec<_>>()
    .join("");

    let accessible = if report.accessible_regions.is_empty() {
        format!(
            r#"<div class="empty-state">{}</div>"#,
            html_escape(copy(
                lang,
                "هنوز مقصدی با پاسخ موفق ثبت نشده است.",
                "No successful regional path was recorded yet.",
            ))
        )
    } else {
        report
            .accessible_regions
            .iter()
            .map(|probe| {
                let latency = probe
                    .avg_rtt_ms
                    .map(|value| format!("{value:.1} ms"))
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    r#"<article class="status-card"><div class="status-top"><strong>{label}</strong><span class="pill pill--success">{ok}</span></div><p>{ip}</p><div class="table-secondary">{latency}</div></article>"#,
                    label = html_escape(&probe.label),
                    ok = html_escape(copy(lang, "در دسترس", "Reachable")),
                    ip = html_escape(&probe.ip),
                    latency = html_escape(&latency),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let blocked = if report.blocked_regions.is_empty() {
        String::new()
    } else {
        report
            .blocked_regions
            .iter()
            .map(|probe| {
                let error_text = if probe.error.trim().is_empty() {
                    copy(lang, "پینگ پاسخ نگرفت.", "Ping did not return.").to_string()
                } else {
                    probe.error.clone()
                };
                format!(
                    r#"<article class="status-card"><div class="status-top"><strong>{label}</strong><span class="pill pill--danger">{down}</span></div><p>{ip}</p><div class="table-secondary">{error}</div></article>"#,
                    label = html_escape(&probe.label),
                    down = html_escape(copy(lang, "بدون پاسخ", "No reply")),
                    ip = html_escape(&probe.ip),
                    error = html_escape(&error_text),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="card">
  <div class="section-header">
    <h2>{title}</h2>
    <p>{subtitle}</p>
  </div>
  <div class="analytics-stat-grid">{metrics}</div>
  <div class="server-health-grid">
    <article class="card server-health-card">
      <div class="section-header">
        <h2>{map_title}</h2>
        <p>{map_subtitle}</p>
      </div>
      {map_svg}
    </article>
    <article class="card server-health-card">
      <div class="section-header">
        <h2>{ok_title}</h2>
        <p>{ok_subtitle}</p>
      </div>
      <div class="insight-grid">{accessible}</div>
    </article>
  </div>
  {blocked_section}
</section>"#,
        title = html_escape(admin_section_label(AdminSection::ServerHealth, lang)),
        subtitle = html_escape(copy(
            lang,
            "این بخش سخت‌افزار، نرم‌افزار، آپدیت‌ها و دسترسی کشورها به همین سرور را با نودهای بین‌المللی جمع‌بندی می‌کند.",
            "This section summarizes hardware, software, updates, and country reachability to this server from international nodes.",
        )),
        metrics = metrics,
        map_title = html_escape(copy(lang, "نقشه دسترسی", "Reachability Map")),
        map_subtitle = html_escape(copy(
            lang,
            "نقاط سبز کشورهایی هستند که نود منتخب آن‌ها توانسته این سرور را از بیرون پاسخ بگیرد.",
            "Green markers show countries whose selected remote node could reach this server.",
        )),
        map_svg = render_server_health_map(report),
        ok_title = html_escape(copy(lang, "مقصدهای در دسترس", "Reachable Regions")),
        ok_subtitle = html_escape(copy(
            lang,
            "هر کارت بر پایهٔ تست زندهٔ نود منتخب همان کشور در همین لحظه ساخته شده است.",
            "Each card is built from a live result on the selected node for that country.",
        )),
        accessible = accessible,
        blocked_section = if blocked.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="card server-health-card"><div class="section-header"><h2>{}</h2><p>{}</p></div><div class="insight-grid">{}</div></div>"#,
                html_escape(copy(lang, "مقصدهای بدون پاسخ", "Blocked or No Response")),
                html_escape(copy(
                    lang,
                    "این کشورها یا در مسیر تا این سرور مسدود هستند یا در این لحظه پاسخی نگرفته‌اند.",
                    "These countries are either blocked on the path to this server or did not receive a reply right now.",
                )),
                blocked,
            )
        },
    )
}

fn render_admin_overview_section(data: &AdminDashboardData, lang: UiLanguage, metrics_html: &str) -> String {
    let monitor_count = data.checks.iter().filter(|row| !row.kind.eq_ignore_ascii_case("tunnel")).count();
    let tunnel_count = data.checks.len() - monitor_count;
    format!(r#"<section class="page-grid page-grid--admin">
      <div class="card welcome-card"><span class="eyebrow">iMONITOR</span><h2>{title}</h2><p>{subtitle}</p>
      <div class="welcome-actions"><a class="ghost" href="{monitor_href}">{monitor_action}</a><a class="ghost" href="{tunnel_href}">{tunnel_action}</a><button type="button" class="ghost ghost--subtle" data-start-tour>{tour}</button></div></div>
      <div class="workspace-summary"><a class="card workspace-summary__item" href="{monitor_href}"><span>{monitors}</span><strong>{monitor_count}</strong><small>{monitor_note}</small></a>
      <a class="card workspace-summary__item" href="{tunnel_href}"><span>{tunnels}</span><strong>{tunnel_count}</strong><small>{tunnel_note}</small></a>
      <a class="card workspace-summary__item" href="{guide_href}"><span>{guide}</span><strong>01 →</strong><small>{guide_note}</small></a></div>
      <div class="card section-card">{health_header}<div id="systemMetricsPanel" class="live-panel" data-live-panel="system">{metrics_html}</div></div>
    </section>"#,
      title=copy(lang,"همه‌چیز، در یک نگاه.","Your network, at a glance."),
      subtitle=copy(lang,"سرویس‌ها را پایش کنید، سرورها را به هم متصل کنید و مشکل را پیدا کنید. همه امکانات برای همه رایگان است.","Monitor services, connect your servers, and understand what needs attention. Every feature is free for everyone."),
      monitor_href=admin_section_href(AdminSection::Monitors,lang),tunnel_href=admin_section_href(AdminSection::Tunnels,lang),guide_href=admin_section_href(AdminSection::Guide,lang),
      monitor_action=copy(lang,"＋ افزودن مانیتور","＋ Add a monitor"),tunnel_action=copy(lang,"＋ ساخت تونل","＋ Create a tunnel"),tour=copy(lang,"راهنمای پنل","Show me around"),
      monitors=copy(lang,"مانیتورینگ","Monitoring"),tunnels=copy(lang,"تونل‌ها","Tunnels"),guide=copy(lang,"شروع آسان","Getting started"),
      monitor_note=copy(lang,"دسترسی و عملکرد سرویس‌ها","Service availability and response times"),tunnel_note=copy(lang,"اتصال خصوصی بین دو سرور","Private connections between two servers"),guide_note=copy(lang,"راهنمای مرحله به مرحله","A step-by-step guide"),
      health_header=render_section_header("",copy(lang,"وضعیت این سرور","This server"),copy(lang,"این اعداد هر ۵ ثانیه به‌روز می‌شوند.","These readings refresh every 5 seconds."),String::new()))
}

fn render_admin_checks_section(
    data: &AdminDashboardData,
    lang: UiLanguage,
    monitor_builder: &str,
    section: AdminSection,
) -> String {
    let latest_result_map = data
        .latest_results
        .iter()
        .map(|result| (result.id.as_str(), result))
        .collect::<BTreeMap<_, _>>();
    let return_to = admin_section_href(section, lang);
    let tunnels = matches!(section, AdminSection::Tunnels);
    let rows = data.checks.iter().filter(|row| row.kind.eq_ignore_ascii_case("tunnel") == tunnels).collect::<Vec<_>>();

    let monitor_rows = if rows.is_empty() {
        format!(
            r#"<tr><td colspan="5" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                if tunnels { "هنوز تونلی ساخته نشده است." } else { "هنوز مانیتوری ثبت نشده است." },
                if tunnels { "No tunnels yet. Create your first connection above." } else { "No monitors yet. Add your first service above." },
            )
        )
    } else {
        rows
            .iter()
            .map(|row| {
                let latest = latest_result_map.get(row.check_id.as_str()).copied();
                let status_html = latest
                    .map(|result| render_result_status_chip(result.status, lang))
                    .unwrap_or_else(|| render_named_status_chip("pending", copy(lang, "در انتظار", "Pending")));
                let latency = latest
                    .and_then(|result| result.latency_ms)
                    .map(|value| format!("{value} ms"))
                    .unwrap_or_else(|| "-".to_string());
                let interval_secs = monitor_interval_secs_from_json(&row.check_json);
                let endpoint = latest
                    .and_then(|result| result.endpoint.as_ref())
                    .map(|value| html_escape(value))
                    .unwrap_or_else(|| "-".to_string());
                let message = latest
                    .map(|result| html_escape(&result.message))
                    .unwrap_or_else(|| {
                        html_escape(copy(
                            lang,
                            "در انتظار اولین نمونه‌برداری",
                            "Waiting for the first sample",
                        ))
                    });
                let observed_at = latest
                    .map(|result| result.observed_at_unix.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let group_badge = if row.display_group.trim().is_empty() {
                    String::new()
                } else {
                    format!(
                        r#"<div class="table-secondary">{group_label}: {group_name}</div>"#,
                        group_label = html_escape(copy(lang, "پوشه", "Folder")),
                        group_name = html_escape(&row.display_group),
                    )
                };
                let speed_test_button = if row.kind.eq_ignore_ascii_case("tunnel") {
                    format!(
                        r#"<button
      type="button"
      class="ghost ghost--diagnostics"
      data-open-tunnel-diagnostics="1"
      data-check-id="{check_id_raw}"
      data-check-label="{label_raw}"
      title="{speed_title}"
      aria-label="{speed_title}"
    >{speed_icon}<span>{speed_label}</span></button>"#,
                        check_id_raw = html_escape(&row.check_id),
                        label_raw = html_escape(&row.label),
                        speed_title = html_escape(copy(lang, "تست زنده‌ی پینگ و سرعت تونل", "Live tunnel ping and speed test")),
                        speed_icon = render_speedometer_icon(),
                        speed_label = copy(lang,"عیب‌یابی","Diagnostics"),
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<tr>
  <td>
    <div class="table-primary">{label}</div>
    <div class="table-secondary">{kind} · {interval}</div>
    {group_badge}
  </td>
  <td>{status}<div class="table-secondary">{latency}</div></td>
  <td class="check-details"><p>{message}</p><details><summary>{details_label}</summary><div class="table-secondary"><code>{endpoint}</code><br><code>{check_id}</code></div></details></td>
  <td><time class="check-time" data-unix="{observed_at}">{observed_at}</time></td>
  <td class="actions-cell actions-cell--wide">
    <div class="actions-wrap actions-wrap--monitor">
      <button
        type="button"
        class="ghost"
        data-edit-check="{check_json}"
        data-edit-label="{label_raw}"
        data-edit-enabled="{enabled_raw}"
        data-edit-public="{public_raw}"
      >{edit_label}</button>
      <button
        type="button"
        class="ghost"
        data-open-analytics="1"
        data-check-id="{check_id_raw}"
        data-check-label="{label_raw}"
      >{analytics_label}</button>
      {speed_test_button}
      <form method="post" action="/admin/checks/delete" onsubmit="return confirm('{confirm}')">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="check_id" value="{check_id_raw}">
        <button type="submit" class="ghost ghost--danger">{delete_label}</button>
      </form>
    </div>
  </td>
</tr>"#,
                    label = html_escape(&row.label),
                    details_label = copy(lang,"جزئیات اتصال","Connection details"),
                    check_id = html_escape(&row.check_id),
                    group_badge = group_badge,
                    kind = html_escape(display_kind_label(&row.kind)),
                    interval = html_escape(&format!("{}s", interval_secs)),
                    status = status_html,
                    latency = html_escape(&latency),
                    message = message,
                    endpoint = endpoint,
                    observed_at = html_escape(&observed_at),
                    check_json = html_escape(&row.check_json),
                    label_raw = html_escape(&row.label),
                    enabled_raw = if row.enabled { "1" } else { "0" },
                    public_raw = if row.public_visible { "1" } else { "0" },
                    edit_label = copy(lang, "ویرایش", "Edit"),
                    analytics_label = copy(lang, "تحلیل", "Analytics"),
                    speed_test_button = speed_test_button,
                    confirm = t(lang, "delete_confirm"),
                    return_to = html_escape(&return_to),
                    check_id_raw = html_escape(&row.check_id),
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="monitor-guide" aria-label="{guide_label}"{guide_hidden}>
      <div class="monitor-guide__step"><span>1</span><div><strong>{guide_type_title}</strong><small>{guide_type_copy}</small></div></div>
      <div class="monitor-guide__step"><span>2</span><div><strong>{guide_target_title}</strong><small>{guide_target_copy}</small></div></div>
      <div class="monitor-guide__step"><span>3</span><div><strong>{guide_result_title}</strong><small>{guide_result_copy}</small></div></div>
    </div>
    {monitor_builder}
  </div>
  <div class="card section-card fade-up">
    {list_header}
    <div class="table-shell">
      <table>
        <thead>
          <tr>
            <th>{monitor_label}</th>
            <th>{status_label}</th>
            <th>{message_label}</th>
            <th>{time_label}</th>
            <th>{actions_label}</th>
          </tr>
        </thead>
        <tbody>{monitor_rows}</tbody>
      </table>
    </div>
  </div>
  {analytics_modal}
  {tunnel_diagnostics_modal}
</section>"#,
        section_header = render_section_header(
            "",
            if tunnels { copy(lang,"راه‌اندازی تونل","Tunnel setup") } else { copy(lang,"افزودن مانیتور","Add a monitor") },
            copy(
                lang,
                "نوع بررسی را انتخاب کنید؛ فرم فقط گزینه‌های مرتبط را نمایش می‌دهد.",
                "Start with the basics. Advanced options are available when you need them.",
            ),
            String::new(),
        ),
        guide_hidden = if tunnels { " hidden" } else { "" },
        guide_label = copy(lang, "مراحل ساخت مانیتور", "Monitor creation steps"),
        guide_type_title = copy(lang, "نوع مانیتور", "Monitor type"),
        guide_type_copy = if tunnels { copy(lang,"پروتکل یکسان در دو سرور","Choose the same protocol on both servers") } else { copy(lang,"نوع سرویس را انتخاب کنید","Choose the service you want to check") },
        guide_target_title = copy(lang, "مقصد و بازه", "Target and interval"),
        guide_target_copy = copy(lang, "آدرس و زمان بررسی را وارد کنید", "Enter the address and check interval"),
        guide_result_title = copy(lang, "ذخیره و مشاهده", "Save and observe"),
        guide_result_copy = copy(lang, "نتیجه در جدول پایین نمایش داده می‌شود", "Results appear in the table below"),
        monitor_builder = monitor_builder,
        list_header = render_section_header(
            "",
            if tunnels { copy(lang,"تونل‌های شما و عیب‌یابی","Your tunnels & diagnostics") } else { copy(lang,"مانیتورهای شما","Your monitors") },
            "",
            String::new(),
        ),
        monitor_label = if tunnels { copy(lang,"اتصال","Connection") } else { copy(lang,"مانیتور","Monitor") },
        status_label = t(lang, "status"),
        message_label = copy(lang,"نتیجه بررسی","What happened"),
        time_label = copy(lang,"آخرین بررسی","Last checked"),
        actions_label = t(lang, "actions"),
        monitor_rows = monitor_rows,
        analytics_modal = render_admin_monitor_analytics_modal(lang),
        tunnel_diagnostics_modal = render_admin_tunnel_diagnostics_modal(lang),
    )
}

fn render_admin_folders_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::Folders, lang);
    let folder_rows = if data.monitor_folders.is_empty() {
        format!(
            r#"<tr><td colspan="5" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز پوشه‌ای ساخته نشده است.",
                "No monitor folders have been created yet.",
            )
        )
    } else {
        data.monitor_folders
            .iter()
            .map(|folder| {
                let assigned_count = data
                    .checks
                    .iter()
                    .filter(|row| row.display_group.trim() == folder.name.trim())
                    .count();
                format!(
                    r#"<tr>
  <td><div class="table-primary">{name}</div></td>
  <td>{assigned_count}</td>
  <td><code>{logo_url}</code></td>
  <td>{shape}</td>
  <td class="actions-cell actions-cell--wide">
    <div class="actions-wrap actions-wrap--admin">
      <form method="post" action="/admin/folders/save" class="inline-form inline-form--stretch">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="original_folder_name" value="{original_name}">
        <input type="text" name="folder_name" value="{folder_name}" placeholder="{folder_name_placeholder}" required>
        <input type="text" name="folder_logo_url" value="{folder_logo_url}" placeholder="https://cdn.example.com/folder.png">
        <select name="folder_logo_shape">{shape_options}</select>
        <button type="submit">{save_label}</button>
      </form>
      <form method="post" action="/admin/folders/delete" onsubmit="return confirm('{delete_confirm}')">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="folder_name" value="{original_name}">
        <button type="submit" class="ghost ghost--danger">{delete_label}</button>
      </form>
    </div>
  </td>
</tr>"#,
                    name = html_escape(&folder.name),
                    assigned_count = assigned_count,
                    logo_url = html_escape(if folder.logo_url.trim().is_empty() {
                        "-"
                    } else {
                        &folder.logo_url
                    }),
                    shape = html_escape(match normalize_group_logo_shape(&folder.logo_shape) {
                        "circle" => copy(lang, "دایره‌ای", "Circle"),
                        "rect" => copy(lang, "مستطیلی", "Rectangle"),
                        _ => copy(lang, "گرد", "Rounded"),
                    }),
                    return_to = html_escape(&return_to),
                    original_name = html_escape(&folder.name),
                    folder_name = html_escape(&folder.name),
                    folder_name_placeholder = html_escape(copy(lang, "اروپا", "Europe")),
                    folder_logo_url = html_escape(&folder.logo_url),
                    shape_options = render_folder_logo_shape_options(
                        normalize_group_logo_shape(&folder.logo_shape),
                        lang,
                    ),
                    save_label = t(lang, "save"),
                    delete_confirm = t(lang, "delete_confirm"),
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let assignment_rows = if data.checks.is_empty() {
        format!(
            r#"<tr><td colspan="3" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز مانیتوری برای انتساب وجود ندارد.",
                "There are no monitors available to assign yet.",
            )
        )
    } else {
        data.checks
            .iter()
            .map(|row| {
                format!(
                    r#"<tr>
  <td>
    <div class="table-primary">{label}</div>
    <div class="table-secondary"><code>{check_id}</code></div>
  </td>
  <td>{kind}</td>
  <td>
    <select name="folder_for_{check_id_attr}">
      {folder_options}
    </select>
  </td>
</tr>"#,
                    label = html_escape(&row.label),
                    check_id = html_escape(&row.check_id),
                    kind = html_escape(display_kind_label(&row.kind)),
                    check_id_attr = html_escape(&row.check_id),
                    folder_options =
                        render_folder_assignment_options(&data.monitor_folders, &row.display_group, lang),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {folder_header}
    <form method="post" action="/admin/folders/save" class="stack-form">
      <input type="hidden" name="return_to" value="{return_to}">
      <div class="form-grid">
        <div>
          <label>{folder_name_label}</label>
          <input type="text" name="folder_name" placeholder="{folder_name_placeholder}" required>
          <div class="field-hint">{folder_name_hint}</div>
        </div>
        <div>
          <label>{folder_logo_label}</label>
          <input type="text" name="folder_logo_url" placeholder="https://cdn.example.com/folder.png">
          <div class="field-hint">{folder_logo_hint}</div>
        </div>
        <div>
          <label>{folder_shape_label}</label>
          <select name="folder_logo_shape">{new_shape_options}</select>
          <div class="field-hint">{folder_shape_hint}</div>
        </div>
      </div>
      <button type="submit">{create_folder}</button>
    </form>
    <div class="section-divider"></div>
    <div class="table-shell">
      <table>
        <thead>
          <tr>
            <th>{folder_column}</th>
            <th>{assigned_column}</th>
            <th>{logo_column}</th>
            <th>{shape_column}</th>
            <th>{actions_column}</th>
          </tr>
        </thead>
        <tbody>{folder_rows}</tbody>
      </table>
    </div>
  </div>
  <div class="card section-card fade-up">
    {assign_header}
    <form method="post" action="/admin/folders/assign" class="stack-form">
      <input type="hidden" name="return_to" value="{return_to}">
      <div class="table-shell">
        <table>
          <thead>
            <tr>
              <th>{monitor_label}</th>
              <th>{kind_label}</th>
              <th>{folder_label}</th>
            </tr>
          </thead>
          <tbody>{assignment_rows}</tbody>
        </table>
      </div>
      <button type="submit">{save_assignments}</button>
    </form>
  </div>
</section>"#,
        folder_header = render_section_header(
            copy(lang, "پوشه‌ها", "Folders"),
            copy(lang, "پوشه مانیتور ها", "Monitor Folders"),
            copy(
                lang,
                "از این صفحه پوشه بسازید، لوگو و شکل آن را عوض کنید، و پوشه‌های قدیمی را پاک یا ویرایش کنید.",
                "Create folders, change their logo and shape, and edit or remove old folders from this page.",
            ),
            String::new(),
        ),
        return_to = html_escape(&return_to),
        folder_name_label = copy(lang, "نام پوشه", "Folder Name"),
        folder_name_placeholder = html_escape(copy(lang, "اروپا", "Europe")),
        folder_name_hint = copy(
            lang,
            "این نام در سربرگ پوشه عمومی نمایش داده می‌شود.",
            "This name is shown in the public folder header.",
        ),
        folder_logo_label = copy(lang, "لوگوی پوشه", "Folder Logo"),
        folder_logo_hint = copy(
            lang,
            "می‌توانید از URL مستقیم یا مسیر فایل محلی داخل /var/www استفاده کنید.",
            "You can use a direct URL or a local file path under /var/www.",
        ),
        folder_shape_label = copy(lang, "شکل لوگو", "Logo Shape"),
        folder_shape_hint = copy(
            lang,
            "لوگوی پوشه در پنل عمومی با همین شکل نمایش داده می‌شود.",
            "The public folder will use this logo shape.",
        ),
        new_shape_options = render_folder_logo_shape_options("rounded", lang),
        create_folder = copy(lang, "ساخت پوشه", "Create Folder"),
        folder_column = copy(lang, "پوشه", "Folder"),
        assigned_column = copy(lang, "مانیتورهای منتسب", "Assigned Monitors"),
        logo_column = copy(lang, "لوگو", "Logo"),
        shape_column = copy(lang, "شکل", "Shape"),
        actions_column = t(lang, "actions"),
        folder_rows = folder_rows,
        assign_header = render_section_header(
            copy(lang, "انتساب", "Assignments"),
            copy(lang, "انتساب مانیتورها به پوشه", "Assign Monitors to Folders"),
            copy(
                lang,
                "هر مانیتور را به یک پوشه وصل کنید تا در پنل عمومی به‌صورت تاشو و مرتب کنار هم دیده شوند.",
                "Attach each monitor to a folder so the public page shows them in clean collapsible groups.",
            ),
            String::new(),
        ),
        monitor_label = copy(lang, "مانیتور", "Monitor"),
        kind_label = t(lang, "kind"),
        folder_label = copy(lang, "پوشه", "Folder"),
        assignment_rows = assignment_rows,
        save_assignments = copy(lang, "ذخیره انتساب‌ها", "Save Assignments"),
    )
}

fn render_admin_notifications_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::Notifications, lang);
    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <form method="post" action="/admin/settings" class="stack-form">
      <input type="hidden" name="return_to" value="{return_to}">
      <div class="form-grid">
        <div class="span-2">
          <label>{bot_token}</label>
          <input type="text" name="telegram_bot_token" value="{bot_token_value}" placeholder="123456789:AA...">
          <div class="field-hint">{bot_token_hint}</div>
        </div>
        <div>
          <label>{admin_chat_id}</label>
          <textarea name="telegram_admin_chat_id" rows="5" placeholder="-1001234567890&#10;123456789">{admin_chat_id_value}</textarea>
          <div class="field-hint">{admin_chat_id_hint}</div>
        </div>
        <div>
          <label>{failure_threshold}</label>
          <input type="number" min="1" name="telegram_failure_threshold" value="{failure_threshold_value}">
          <div class="field-hint">{failure_threshold_hint}</div>
        </div>
        <div>
          <label>{socks5_host}</label>
          <input type="text" name="telegram_socks5_host" value="{socks5_host_value}" placeholder="127.0.0.1">
          <div class="field-hint">{socks5_host_hint}</div>
        </div>
        <div>
          <label>{socks5_port}</label>
          <input type="number" min="1" max="65535" name="telegram_socks5_port" value="{socks5_port_value}">
        </div>
        <div>
          <label>{socks5_username}</label>
          <input type="text" name="telegram_socks5_username" value="{socks5_username_value}" placeholder="{optional_placeholder}">
        </div>
        <div>
          <label>{socks5_password}</label>
          <input type="password" name="telegram_socks5_password" value="{socks5_password_value}" placeholder="{optional_placeholder}">
        </div>
      </div>
      <button type="submit">{save_button}</button>
    </form>
    <div class="button-row mt-3">
      <form method="post" action="/admin/notifications/test-bot">
        <button type="submit" class="ghost">{test_bot}</button>
      </form>
      <form method="post" action="/admin/notifications/test-socks">
        <button type="submit" class="ghost">{test_socks}</button>
      </form>
      <form method="post" action="/admin/notifications/test">
        <button type="submit" class="ghost">{test_message}</button>
      </form>
    </div>
  </div>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "تلگرام", "Telegram"),
            "",
            String::new(),
        ),
        return_to = html_escape(&return_to),
        bot_token = copy(lang, "توکن ربات تلگرام", "Telegram Bot Token"),
        bot_token_value = html_escape(&data.settings.telegram_bot_token),
        bot_token_hint = copy(
            lang,
            "توکن کامل ربات را وارد کنید.",
            "Enter the full bot token.",
        ),
        admin_chat_id = copy(lang, "آیدی عددی ادمین‌های تلگرام", "Telegram Admin Numeric IDs"),
        admin_chat_id_value = html_escape(&data.settings.telegram_admin_chat_id),
        admin_chat_id_hint = copy(
            lang,
            "هر خط یک آیدی عددی. همه‌ی این آیدی‌ها هشدار می‌گیرند و اجازه‌ی دستورهای ربات را دارند.",
            "One numeric ID per line. All of them receive alerts and can use bot commands.",
        ),
        failure_threshold = copy(lang, "تعداد خطای پیاپی", "Consecutive Failure Threshold"),
        failure_threshold_value = data.settings.telegram_failure_threshold,
        failure_threshold_hint = copy(
            lang,
            "پیش‌فرض ۳ است.",
            "Default is 3.",
        ),
        socks5_host = copy(lang, "هاست SOCKS5", "SOCKS5 Host"),
        socks5_host_value = html_escape(&data.settings.telegram_socks5_host),
        socks5_host_hint = copy(
            lang,
            "اگر سرور به Bot API دسترسی مستقیم ندارد، پراکسی SOCKS5 را اینجا بگذارید.",
            "Use this when the server cannot reach the Bot API directly.",
        ),
        socks5_port = copy(lang, "پورت SOCKS5", "SOCKS5 Port"),
        socks5_port_value = data.settings.telegram_socks5_port,
        socks5_username = copy(lang, "نام کاربری SOCKS5", "SOCKS5 Username"),
        socks5_username_value = html_escape(&data.settings.telegram_socks5_username),
        socks5_password = copy(lang, "رمز عبور SOCKS5", "SOCKS5 Password"),
        socks5_password_value = html_escape(&data.settings.telegram_socks5_password),
        optional_placeholder = copy(lang, "اختیاری", "optional"),
        save_button = t(lang, "save"),
        test_bot = copy(lang, "تست ربات", "Test Bot"),
        test_socks = copy(lang, "تست SOCKS5", "Test SOCKS5"),
        test_message = copy(lang, "ارسال پیام تست", "Send Test Message"),
    )
}

fn render_admin_backups_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::Backups, lang);
    let target_rows = if data.backup_targets.is_empty() {
        format!(
            r#"<tr><td colspan="7" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز مقصد بکاپی ثبت نشده است.",
                "No backup target has been created yet.",
            )
        )
    } else {
        data.backup_targets
            .iter()
            .map(|target| {
                let endpoint = if target.protocol == "s3" {
                    format!(
                        "s3://{}{}{}",
                        target.s3_bucket,
                        if target.remote_path.trim().is_empty() { "" } else { "/" },
                        target.remote_path.trim().trim_start_matches('/')
                    )
                } else if target.port > 0 {
                    format!("{}:{}{}", target.endpoint, target.port, target.remote_path)
                } else {
                    format!("{}{}", target.endpoint, target.remote_path)
                };
                format!(
                    r#"<tr>
  <td>{label}</td>
  <td>{protocol}</td>
  <td>{endpoint}</td>
  <td>{enabled}</td>
  <td>{status}</td>
  <td>{updated}</td>
  <td class="actions-cell">
    <form method="post" action="/admin/backups/target/delete" class="inline-form" onsubmit="return confirm('{delete_confirm}')">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="target_id" value="{target_id}">
      <button type="submit" class="ghost ghost--danger">{delete_label}</button>
    </form>
  </td>
</tr>"#,
                    label = html_escape(&target.label),
                    protocol = html_escape(&target.protocol.to_ascii_uppercase()),
                    endpoint = html_escape(&endpoint),
                    enabled = html_escape(yes_no(lang, target.enabled)),
                    status = html_escape(&target.last_status),
                    updated = html_escape(&format_unix_time(target.updated_at_unix)),
                    delete_confirm = t(lang, "delete_confirm"),
                    return_to = html_escape(&return_to),
                    target_id = target.id,
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let job_target_map = data
        .backup_targets
        .iter()
        .map(|target| (target.id, target.label.clone()))
        .collect::<BTreeMap<_, _>>();
    let selected_by_job = data.backup_job_links.iter().fold(
        BTreeMap::<i64, Vec<i64>>::new(),
        |mut acc, link| {
            acc.entry(link.job_id).or_default().push(link.target_id);
            acc
        },
    );
    let job_rows = if data.backup_jobs.is_empty() {
        format!(
            r#"<tr><td colspan="8" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز هیچ وظیفه‌ی بکاپی ساخته نشده است.",
                "No backup job has been created yet.",
            )
        )
    } else {
        data.backup_jobs
            .iter()
            .map(|job| {
                let targets = selected_by_job
                    .get(&job.id)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|id| job_target_map.get(&id).cloned())
                    .collect::<Vec<_>>()
                    .join(", ");
                let sources = if job.source_paths.is_empty() {
                    "-".to_string()
                } else {
                    job.source_paths
                        .iter()
                        .map(|path| html_escape(path))
                        .collect::<Vec<_>>()
                        .join("<br>")
                };
                format!(
                    r#"<tr>
  <td>{label}</td>
  <td>{sources}</td>
  <td>{compression}</td>
  <td>{schedule}</td>
  <td>{retention}</td>
  <td>{targets}</td>
  <td>{status}</td>
  <td class="actions-cell">
    <form method="post" action="/admin/backups/job/run" class="inline-form">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="job_id" value="{job_id}">
      <button type="submit" class="ghost">{run_label}</button>
    </form>
    <form method="post" action="/admin/backups/job/delete" class="inline-form" onsubmit="return confirm('{delete_confirm}')">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="job_id" value="{job_id}">
      <button type="submit" class="ghost ghost--danger">{delete_label}</button>
    </form>
  </td>
</tr>"#,
                    label = html_escape(&job.label),
                    sources = sources,
                    compression = html_escape(&job.compression_format),
                    schedule = html_escape(&format!(
                        "{} / {}",
                        job.schedule_kind,
                        job.schedule_value
                    )),
                    retention = job.retention_count,
                    targets = html_escape(if targets.is_empty() { "-" } else { &targets }),
                    status = html_escape(&job.last_status),
                    return_to = html_escape(&return_to),
                    job_id = job.id,
                    run_label = copy(lang, "اجرای فوری", "Run Now"),
                    delete_confirm = t(lang, "delete_confirm"),
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let record_rows = if data.backup_records.is_empty() {
        format!(
            r#"<tr><td colspan="6" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز هیچ بکاپی اجرا نشده است.",
                "No backup execution has been recorded yet.",
            )
        )
    } else {
        data.backup_records
            .iter()
            .map(|record| {
                let target_name = data
                    .backup_targets
                    .iter()
                    .find(|target| target.id == record.target_id)
                    .map(|target| target.label.as_str())
                    .unwrap_or("-");
                let job_name = data
                    .backup_jobs
                    .iter()
                    .find(|job| job.id == record.job_id)
                    .map(|job| job.label.as_str())
                    .unwrap_or("-");
                format!(
                    r#"<tr>
  <td>{job}</td>
  <td>{target}</td>
  <td>{archive}</td>
  <td>{size}</td>
  <td>{status}</td>
  <td>{time}</td>
</tr>"#,
                    job = html_escape(job_name),
                    target = html_escape(target_name),
                    archive = html_escape(&record.archive_name),
                    size = html_escape(&bytes_to_human(record.archive_size_bytes)),
                    status = html_escape(&record.status),
                    time = html_escape(&format_unix_time(record.created_at_unix)),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let target_options = data
        .backup_targets
        .iter()
        .map(|target| {
            format!(
                r#"<label class="choice-chip"><input type="checkbox" name="target_ids" value="{id}"><span>{label}</span></label>"#,
                id = target.id,
                label = html_escape(&target.label),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="split-columns">
      <div class="subpanel stack-form">
        <div>
          <h3>{browser_title}</h3>
          <p class="muted">{browser_note}</p>
        </div>
        <div class="inline-form inline-form--stretch">
          <input type="text" id="backupBrowserPath" value="/" dir="ltr">
          <button type="button" class="ghost" onclick="window.iMonitorBackupBrowserLoad(document.getElementById('backupBrowserPath').value)">{browse_label}</button>
          <button type="button" class="ghost" onclick="window.iMonitorBackupBrowserUp()">{parent_label}</button>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{name_label}</th><th>{kind_label}</th><th>{size_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody id="backupBrowserRows">
              <tr><td colspan="4" class="empty-cell">{loading_label}</td></tr>
            </tbody>
          </table>
        </div>
        <div>
          <label>{selected_paths_label}</label>
          <textarea id="backupSelectedPaths" rows="7" placeholder="/etc/nginx&#10;/var/www"></textarea>
          <div class="field-hint">{selected_paths_hint}</div>
        </div>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{target_form_title}</h3>
          <p class="muted">{target_form_note}</p>
        </div>
        <form method="post" action="/admin/backups/target/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{label_label}</label><input type="text" name="label" required></div>
            <div><label>{protocol_label}</label><select name="protocol"><option value="ftp">FTP</option><option value="sftp">SFTP</option><option value="s3">S3</option></select></div>
            <div><label>{endpoint_label}</label><input type="text" name="endpoint" placeholder="backup.example.com"></div>
            <div><label>{port_label}</label><input type="number" min="0" max="65535" name="port" placeholder="21"></div>
            <div><label>{username_label}</label><input type="text" name="username"></div>
            <div><label>{password_label}</label><input type="password" name="password"></div>
            <div><label>{remote_path_label}</label><input type="text" name="remote_path" placeholder="/imonitor"></div>
            <div><label>{enabled_label}</label><select name="enabled"><option value="1">{yes}</option><option value="0">{no}</option></select></div>
            <div><label>{bucket_label}</label><input type="text" name="s3_bucket" placeholder="bucket-name"></div>
            <div><label>{region_label}</label><input type="text" name="s3_region" placeholder="eu-central-1"></div>
            <div><label>{s3_endpoint_label}</label><input type="text" name="s3_endpoint" placeholder="https://s3.example.com"></div>
            <div><label>{access_key_label}</label><input type="text" name="s3_access_key"></div>
            <div><label>{secret_key_label}</label><input type="password" name="s3_secret_key"></div>
          </div>
          <button type="submit">{save_target_label}</button>
        </form>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{label_label}</th><th>{protocol_label}</th><th>{endpoint_label}</th><th>{enabled_label}</th><th>{status_label}</th><th>{updated_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{target_rows}</tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="split-columns">
      <div class="subpanel stack-form">
        <div>
          <h3>{job_form_title}</h3>
          <p class="muted">{job_form_note}</p>
        </div>
        <form method="post" action="/admin/backups/job/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{label_label}</label><input type="text" name="label" required></div>
            <div><label>{compression_label}</label><select name="compression_format"><option value="tar.gz">tar.gz</option><option value="tar.xz">tar.xz</option><option value="zip">zip</option></select></div>
            <div><label>{schedule_kind_label}</label><select name="schedule_kind"><option value="minute">{minute_label}</option><option value="hour">{hour_label}</option><option value="day">{day_label}</option></select></div>
            <div><label>{schedule_value_label}</label><input type="number" min="1" name="schedule_value" value="1"></div>
            <div><label>{retention_label}</label><input type="number" min="1" name="retention_count" value="8"></div>
            <div><label>{enabled_label}</label><select name="enabled"><option value="1">{yes}</option><option value="0">{no}</option></select></div>
            <div><label>{include_hidden_label}</label><select name="include_hidden"><option value="0">{no}</option><option value="1">{yes}</option></select></div>
          </div>
          <div>
            <label>{selected_paths_label}</label>
            <textarea id="backupJobSourcePaths" name="source_paths" rows="7" placeholder="/etc/nginx&#10;/var/www"></textarea>
            <div class="field-hint">{job_source_hint}</div>
          </div>
          <div>
            <label>{target_select_label}</label>
            <div class="chip-cloud">{target_options}</div>
            <div class="field-hint">{target_select_hint}</div>
          </div>
          <button type="submit">{save_job_label}</button>
        </form>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{job_table_title}</h3>
          <p class="muted">{job_table_note}</p>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{label_label}</th><th>{source_label}</th><th>{compression_label}</th><th>{schedule_label}</th><th>{retention_label}</th><th>{targets_label}</th><th>{status_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{job_rows}</tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="subpanel stack-form">
      <div>
        <h3>{records_title}</h3>
        <p class="muted">{records_note}</p>
      </div>
      <div class="table-shell">
        <table>
          <thead>
            <tr><th>{label_label}</th><th>{target_single_label}</th><th>{archive_label}</th><th>{size_label}</th><th>{status_label}</th><th>{time_label}</th></tr>
          </thead>
          <tbody>{record_rows}</tbody>
        </table>
      </div>
    </div>
  </div>
  <script>
  (() => {{
    const rows = document.getElementById('backupBrowserRows');
    const pathInput = document.getElementById('backupBrowserPath');
    const targetTextarea = document.getElementById('backupSelectedPaths');
    const jobTextarea = document.getElementById('backupJobSourcePaths');
    if (!rows || !pathInput || !targetTextarea) return;
    function escapeHtml(value) {{
      return String(value ?? '').replace(/[&<>\"']/g, (character) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}}[character]));
    }}
    function appendPath(path) {{
      const current = targetTextarea.value.split('\\n').map((line) => line.trim()).filter(Boolean);
      if (!current.includes(path)) current.push(path);
      targetTextarea.value = current.join('\\n');
      if (jobTextarea) jobTextarea.value = targetTextarea.value;
    }}
    function renderEntries(payload) {{
      pathInput.value = payload.current_path || '/';
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      if (!entries.length) {{
        rows.innerHTML = '<tr><td colspan="4" class="empty-cell">{empty_browser_label}</td></tr>';
        return;
      }}
      rows.innerHTML = entries.map((entry) => {{
        const type = entry.is_dir ? '{dir_label}' : '{file_label}';
        const browse = entry.is_dir
          ? `<button type="button" class="ghost" data-browse="${{escapeHtml(entry.path)}}">{browse_label}</button>`
          : '';
        return `<tr>
          <td>${{escapeHtml(entry.name)}}</td>
          <td>${{type}}</td>
          <td>${{escapeHtml(entry.size_human || '-')}}</td>
          <td class="actions-cell">
            <button type="button" class="ghost" data-pick="${{escapeHtml(entry.path)}}">{pick_label}</button>
            ${{browse}}
          </td>
        </tr>`;
      }}).join('');
      rows.querySelectorAll('[data-pick]').forEach((button) => {{
        button.addEventListener('click', () => appendPath(button.getAttribute('data-pick') || ''));
      }});
      rows.querySelectorAll('[data-browse]').forEach((button) => {{
        button.addEventListener('click', () => window.iMonitorBackupBrowserLoad(button.getAttribute('data-browse') || '/'));
      }});
    }}
    window.iMonitorBackupBrowserLoad = async (path) => {{
      rows.innerHTML = '<tr><td colspan="4" class="empty-cell">{loading_label}</td></tr>';
      try {{
        const response = await fetch(`/admin/backups/browse.json?lang={lang_code}&path=${{encodeURIComponent(path || "/")}}`, {{ credentials: 'same-origin' }});
        const payload = await response.json();
        if (!response.ok || payload.error) {{
          rows.innerHTML = `<tr><td colspan="4" class="empty-cell">${{escapeHtml(payload.error || 'Request failed')}}</td></tr>`;
          return;
        }}
        renderEntries(payload);
      }} catch (error) {{
        rows.innerHTML = `<tr><td colspan="4" class="empty-cell">${{escapeHtml(error.message || 'Request failed')}}</td></tr>`;
      }}
    }};
    window.iMonitorBackupBrowserUp = () => {{
      const current = pathInput.value || '/';
      if (current === '/') {{
        window.iMonitorBackupBrowserLoad('/');
        return;
      }}
      const parts = current.replace(/\/+$/,'').split('/').filter(Boolean);
      parts.pop();
      window.iMonitorBackupBrowserLoad('/' + parts.join('/'));
    }};
    window.iMonitorBackupBrowserLoad(pathInput.value);
  }})();
  </script>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "بکاپ", "Backup"),
            copy(
                lang,
                "از فایل‌ها و پوشه‌های مهم سرور نسخه‌ی فشرده بگیرید، زمان‌بندی کنید و روی چند مقصد جداگانه بفرستید.",
                "Create compressed backups from important server files and folders, schedule them, and push them to multiple destinations.",
            ),
            String::new(),
        ),
        browser_title = copy(lang, "انتخاب فایل و پوشه", "File & Folder Picker"),
        browser_note = copy(
            lang,
            "از این مرورگر برای پیدا کردن مسیرها استفاده کنید و با یک کلیک آن‌ها را به لیست منابع بکاپ اضافه کنید.",
            "Use this browser to locate paths and add them to the backup source list with one click.",
        ),
        browse_label = copy(lang, "باز کردن", "Browse"),
        parent_label = copy(lang, "پوشه بالاتر", "Up"),
        name_label = copy(lang, "نام", "Name"),
        kind_label = copy(lang, "نوع", "Type"),
        size_label = copy(lang, "حجم", "Size"),
        actions_label = t(lang, "actions"),
        loading_label = copy(lang, "در حال بارگذاری...", "Loading..."),
        selected_paths_label = copy(lang, "مسیرهای انتخاب‌شده", "Selected Paths"),
        selected_paths_hint = copy(
            lang,
            "هر مسیر را در یک خط جدا بنویسید. می‌توانید فایل و پوشه را با هم بکاپ بگیرید.",
            "Put each path on a separate line. You can back up files and folders together.",
        ),
        target_form_title = copy(lang, "مقصدهای بکاپ", "Backup Targets"),
        target_form_note = copy(
            lang,
            "برای یک وظیفه می‌توانید چند مقصد تعریف کنید؛ مثلا هم‌زمان روی SFTP و S3.",
            "Each job can send to multiple targets, for example SFTP and S3 at the same time.",
        ),
        return_to = html_escape(&return_to),
        label_label = t(lang, "label"),
        protocol_label = t(lang, "protocol"),
        endpoint_label = t(lang, "endpoint"),
        port_label = t(lang, "port"),
        username_label = t(lang, "username"),
        password_label = t(lang, "password"),
        remote_path_label = copy(lang, "مسیر مقصد", "Remote Path"),
        enabled_label = t(lang, "enabled"),
        yes = t(lang, "yes"),
        no = t(lang, "no"),
        bucket_label = copy(lang, "باکت", "Bucket"),
        region_label = copy(lang, "ریجن", "Region"),
        s3_endpoint_label = copy(lang, "S3 Endpoint", "S3 Endpoint"),
        access_key_label = copy(lang, "Access Key", "Access Key"),
        secret_key_label = copy(lang, "Secret Key", "Secret Key"),
        save_target_label = copy(lang, "ذخیره مقصد بکاپ", "Save Backup Target"),
        target_rows = target_rows,
        status_label = t(lang, "status"),
        updated_label = copy(lang, "آخرین تغییر", "Updated"),
        job_form_title = copy(lang, "وظیفه‌ی بکاپ", "Backup Job"),
        job_form_note = copy(
            lang,
            "هر وظیفه می‌تواند چند مسیر و چند مقصد داشته باشد. قبل از پر شدن مقصد، قدیمی‌ترین نسخه‌ها پاک می‌شوند.",
            "Each job can include multiple paths and multiple targets. Old backups are removed before the destination fills up.",
        ),
        compression_label = copy(lang, "فرمت فشرده‌سازی", "Compression Format"),
        schedule_kind_label = copy(lang, "نوع زمان‌بندی", "Schedule Type"),
        minute_label = copy(lang, "دقیقه", "Minute"),
        hour_label = copy(lang, "ساعت", "Hour"),
        day_label = copy(lang, "روز", "Day"),
        schedule_value_label = copy(lang, "هر چند واحد", "Every N Units"),
        retention_label = copy(lang, "تعداد نگهداری", "Retention Count"),
        include_hidden_label = copy(lang, "فایل مخفی", "Include Hidden"),
        job_source_hint = copy(
            lang,
            "اگر از مرورگر بالا استفاده می‌کنید، مسیرها را از آن‌جا کپی یا اضافه کنید.",
            "If you use the browser above, copy or append the source paths from there.",
        ),
        target_select_label = copy(lang, "مقصدهای این وظیفه", "Targets For This Job"),
        target_select_hint = copy(
            lang,
            "برای یک منبع می‌توانید چند مقصد را هم‌زمان انتخاب کنید.",
            "You can select multiple destinations for the same source set.",
        ),
        target_options = if target_options.is_empty() {
            format!(
                r#"<div class="field-hint">{}</div>"#,
                copy(
                    lang,
                    "اول باید حداقل یک مقصد بکاپ بسازید.",
                    "Create at least one backup target first.",
                )
            )
        } else {
            target_options
        },
        save_job_label = copy(lang, "ذخیره وظیفه بکاپ", "Save Backup Job"),
        job_table_title = copy(lang, "وظیفه‌های ثبت‌شده", "Saved Jobs"),
        job_table_note = copy(
            lang,
            "وظیفه‌ها هر دقیقه توسط سرویس بررسی می‌شوند و در زمان مقرر اجرا خواهند شد.",
            "Jobs are checked every minute by the service and run automatically when their schedule is due.",
        ),
        source_label = copy(lang, "منابع", "Sources"),
        schedule_label = copy(lang, "زمان‌بندی", "Schedule"),
        targets_label = copy(lang, "مقصدها", "Targets"),
        job_rows = job_rows,
        records_title = copy(lang, "تاریخچه بکاپ", "Backup History"),
        records_note = copy(
            lang,
            "این جدول آخرین آرشیوهای تولیدشده و وضعیت ارسال آن‌ها را نشان می‌دهد.",
            "This table shows the latest produced archives and their upload status.",
        ),
        target_single_label = copy(lang, "مقصد", "Target"),
        archive_label = copy(lang, "آرشیو", "Archive"),
        time_label = t(lang, "time"),
        record_rows = record_rows,
        empty_browser_label = copy(lang, "چیزی در این مسیر پیدا نشد.", "Nothing was found in this path."),
        dir_label = copy(lang, "پوشه", "Directory"),
        file_label = copy(lang, "فایل", "File"),
        pick_label = copy(lang, "افزودن", "Add"),
        lang_code = lang.as_str(),
    )
}

fn render_admin_settings_section(
    data: &AdminDashboardData,
    lang: UiLanguage,
    theme_preset_selector: &str,
    reverse_proxy_snippet: &str,
) -> String {
    let return_to = admin_section_href(AdminSection::Settings, lang);
    let listen_port = listen_port_from_bind_addr(&data.settings.bind_addr);
    let logo_preview = render_branding_asset_preview(&data.settings.logo_url, "logo", lang);
    let favicon_preview =
        render_branding_asset_preview(&data.settings.favicon_url, "favicon", lang);
    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="split-columns split-columns--tight">
      <div class="subpanel stack-form">
        <div>
          <h3>{access_title}</h3>
          <p class="muted">{access_note}</p>
        </div>
        <form method="post" action="/admin/access" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div>
              <label>{username_label}</label>
              <input type="text" name="admin_username" value="{admin_username_value}" autocomplete="username" required>
            </div>
            <div>
              <label>{listen_port_label}</label>
              <input type="number" min="1" max="65535" name="listen_port" value="{listen_port_value}" required>
            </div>
            <div>
              <label>{new_password_label}</label>
              <input type="password" name="new_password" autocomplete="new-password" placeholder="{password_placeholder}">
            </div>
            <div>
              <label>{confirm_password_label}</label>
              <input type="password" name="confirm_password" autocomplete="new-password" placeholder="{password_placeholder}">
            </div>
          </div>
          <button type="submit">{save_access_button}</button>
        </form>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{network_title}</h3>
          <p class="muted">{network_note}</p>
        </div>
        <div class="stat-stack">
          <div class="metric-inline"><span>{bind_addr}</span><code>{bind_addr_value}</code></div>
          <div class="metric-inline"><span>{public_base_url}</span><code>{public_base_url_value}</code></div>
          <div class="metric-inline"><span>{admin_base_url}</span><code>{admin_base_url_value}</code></div>
          <div class="metric-inline"><span>{ssl_mode}</span><code>{ssl_mode_value}</code></div>
        </div>
        <details class="soft-details soft-details--spaced">
          <summary>{nginx_snippet}</summary>
          <pre class="code-block">{proxy_snippet}</pre>
        </details>
      </div>
    </div>
  </div>

  <div class="card section-card fade-up">
    {appearance_header}
    <form method="post" action="/admin/settings" class="stack-form" id="brandingSettingsForm">
      <input type="hidden" name="return_to" value="{return_to}">
      {theme_preset_selector}
      <div class="form-grid">
        <div class="span-2">
          <div class="subpanel subpanel--soft">
            <h3>{custom_palette_title}</h3>
            <p class="muted">{custom_palette_note}</p>
            <div class="color-picker-grid">
              <div>
                <label>{primary_color}</label>
                <div class="color-picker-field">
                  <input type="color" value="{primary_value}" data-sync-color="primary_color">
                  <input type="text" name="primary_color" value="{primary_value}">
                </div>
              </div>
              <div>
                <label>{secondary_color}</label>
                <div class="color-picker-field">
                  <input type="color" value="{secondary_value}" data-sync-color="secondary_color">
                  <input type="text" name="secondary_color" value="{secondary_value}">
                </div>
              </div>
              <div>
                <label>{background_color}</label>
                <div class="color-picker-field">
                  <input type="color" value="{background_value}" data-sync-color="background_color">
                  <input type="text" name="background_color" value="{background_value}">
                </div>
              </div>
            </div>
          </div>
        </div>
        <div>
          <label>{public_title}</label>
          <input type="text" name="public_title" value="{public_title_value}">
        </div>
        <div>
          <label>{public_subtitle}</label>
          <input type="text" name="public_subtitle" value="{public_subtitle_value}">
        </div>
        <div>
          <label>{default_language}</label>
          <select name="default_language">
            <option value="fa" {fa_selected}>فارسی</option>
            <option value="en" {en_selected}>English</option>
          </select>
        </div>
        <div>
          <label>{dark_mode}</label>
          <select name="dark_mode_default">
            <option value="1" {dark_selected}>{dark_label}</option>
            <option value="0" {light_selected}>{light_label}</option>
          </select>
        </div>
        <div>
          <label>{contact_email}</label>
          <input type="text" name="contact_email" value="{contact_email_value}">
        </div>
        <div>
          <label>{contact_telegram}</label>
          <input type="text" name="contact_telegram" value="{contact_telegram_value}">
        </div>
        <div>
          <label>{contact_phone}</label>
          <input type="text" name="contact_phone" value="{contact_phone_value}">
        </div>
        <div class="span-2">
          <div class="branding-upload-grid">
            <div class="subpanel subpanel--soft">
              <label>{logo_url}</label>
              <input type="text" name="logo_url" value="{logo_url_value}" placeholder="https://cdn.example.com/logo.png">
              <div class="field-hint">{logo_url_hint}</div>
              <label>{logo_upload_label}</label>
              <input type="file" id="brandingLogoUpload" accept="image/*,.ico,.svg">
              <input type="hidden" name="logo_upload_data" id="brandingLogoUploadData">
              <input type="hidden" name="logo_upload_name" id="brandingLogoUploadName">
              <div class="field-hint">{logo_upload_hint}</div>
              {logo_preview}
            </div>
            <div class="subpanel subpanel--soft">
              <label>{favicon_url}</label>
              <input type="text" name="favicon_url" value="{favicon_url_value}" placeholder="https://cdn.example.com/favicon.ico">
              <div class="field-hint">{favicon_url_hint}</div>
              <label>{favicon_upload_label}</label>
              <input type="file" id="brandingFaviconUpload" accept="image/*,.ico,.svg">
              <input type="hidden" name="favicon_upload_data" id="brandingFaviconUploadData">
              <input type="hidden" name="favicon_upload_name" id="brandingFaviconUploadName">
              <div class="field-hint">{favicon_upload_hint}</div>
              {favicon_preview}
            </div>
          </div>
        </div>
      </div>
      <div>
        <label>{notes_label}</label>
        <textarea name="notes" rows="4">{notes_value}</textarea>
      </div>
      <button type="submit">{save_button}</button>
    </form>
  </div>

</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "تنظیمات پنل", "Panel Settings"),
            copy(
                lang,
                "دسترسی پنل، ظاهر، آدرس‌ها و SSL را از همین صفحه مدیریت کنید.",
                "Manage panel access, appearance, URLs, and SSL from this page.",
            ),
            String::new(),
        ),
        appearance_header = render_section_header(
            copy(lang, "ظاهر", "Appearance"),
            copy(lang, "ظاهر", "Appearance"),
            copy(
                lang,
                "تم روشن و تاریک، پالت‌های آماده، و رنگ‌های سفارشی پنل عمومی را از این صفحه تنظیم کنید.",
                "Control light/dark defaults, preset palettes, and custom colors for the public panel here.",
            ),
            String::new(),
        ),
        return_to = html_escape(&return_to),
        access_title = copy(lang, "دسترسی پنل", "Panel Access"),
        access_note = copy(
            lang,
            "از اینجا می‌توانید نام کاربری، رمز عبور و پورت پنل را تغییر دهید. اگر پورت عوض شود، سرویس به‌صورت خودکار روی پورت جدید ری‌استارت می‌شود.",
            "Change the admin username, password, and panel port here. If the port changes, the service restarts automatically on the new port.",
        ),
        username_label = t(lang, "username"),
        admin_username_value = html_escape(&data.admin_username),
        listen_port_label = copy(lang, "پورت پنل", "Panel Port"),
        listen_port_value = listen_port,
        new_password_label = copy(lang, "رمز عبور جدید", "New Password"),
        confirm_password_label = copy(lang, "تکرار رمز عبور", "Confirm Password"),
        password_placeholder = copy(lang, "اگر تغییر نمی‌دهید خالی بماند", "Leave blank to keep the current password"),
        save_access_button = copy(lang, "ذخیره دسترسی", "Save Access"),
        network_title = copy(lang, "دامنه و SSL", "Domain & SSL"),
        network_note = copy(
            lang,
            "کاربر نهایی می‌تواند پنل را پشت دامنه و رورس‌پراکسی قرار دهد تا IP مستقیم دیده نشود.",
            "Let server owners place the panel behind a domain and reverse proxy instead of exposing a raw IP.",
        ),
        bind_addr = t(lang, "bind_addr"),
        bind_addr_value = html_escape(&data.settings.bind_addr),
        public_base_url = t(lang, "public_base_url"),
        public_base_url_value = html_escape(&data.settings.public_base_url),
        admin_base_url = t(lang, "admin_base_url"),
        admin_base_url_value = html_escape(&data.settings.admin_base_url),
        ssl_mode = t(lang, "ssl_mode"),
        ssl_mode_value = html_escape(&data.settings.ssl_mode),
        nginx_snippet = t(lang, "nginx_snippet"),
        proxy_snippet = html_escape(reverse_proxy_snippet),
        theme_preset_selector = theme_preset_selector,
        custom_palette_title = copy(lang, "رنگ سفارشی", "Custom Colors"),
        custom_palette_note = copy(
            lang,
            "اگر پالت آماده کافی نیست، این سه رنگ را مستقیم تنظیم کنید. پنل عمومی هر دو حالت روشن و تاریک را با همین پالت رعایت می‌کند.",
            "If a preset is not enough, set these three colors directly. The public UI will respect them in both light and dark mode.",
        ),
        primary_color = copy(lang, "رنگ اصلی", "Primary Color"),
        secondary_color = copy(lang, "رنگ ثانویه", "Secondary Color"),
        background_color = copy(lang, "رنگ پس‌زمینه", "Background Color"),
        primary_value = html_escape(&data.settings.primary_color),
        secondary_value = html_escape(&data.settings.secondary_color),
        background_value = html_escape(&data.settings.background_color),
        public_title = t(lang, "public_title"),
        public_subtitle = t(lang, "public_subtitle"),
        default_language = t(lang, "default_language"),
        dark_mode = t(lang, "dark_mode"),
        dark_label = t(lang, "dark"),
        light_label = t(lang, "light"),
        contact_email = t(lang, "contact_email"),
        contact_telegram = t(lang, "contact_telegram"),
        contact_phone = t(lang, "contact_phone"),
        public_title_value = html_escape(&data.settings.public_title),
        public_subtitle_value = html_escape(&data.settings.public_subtitle),
        fa_selected = if matches!(data.settings.default_language, UiLanguage::Fa) {
            "selected"
        } else {
            ""
        },
        en_selected = if matches!(data.settings.default_language, UiLanguage::En) {
            "selected"
        } else {
            ""
        },
        dark_selected = if data.settings.dark_mode_default { "selected" } else { "" },
        light_selected = if data.settings.dark_mode_default { "" } else { "selected" },
        contact_email_value = html_escape(&data.settings.contact_email),
        contact_telegram_value = html_escape(&data.settings.contact_telegram),
        contact_phone_value = html_escape(&data.settings.contact_phone),
        logo_url = t(lang, "logo_url"),
        favicon_url = t(lang, "favicon_url"),
        logo_url_value = html_escape(&data.settings.logo_url),
        favicon_url_value = html_escape(&data.settings.favicon_url),
        logo_url_hint = copy(
            lang,
            "اگر لوگو روی CDN یا دامنه دیگری میزبانی می‌شود، آدرس مستقیم آن را اینجا وارد کنید. آپلود فایل، این مقدار را با فایل محلی مدیریت‌شده جایگزین می‌کند.",
            "Paste a direct URL if the logo is hosted elsewhere. Uploading a file will replace this with a managed local asset.",
        ),
        favicon_url_hint = copy(
            lang,
            "اگر آیکون را از بیرون میزبانی می‌کنید، آدرس مستقیم آن را وارد کنید. آپلود فایل، این مقدار را با آیکون محلی مدیریت‌شده جایگزین می‌کند.",
            "Paste a direct URL if the favicon is hosted elsewhere. Uploading a file will replace this with a managed local icon.",
        ),
        logo_upload_label = copy(lang, "آپلود لوگو", "Upload Logo"),
        favicon_upload_label = copy(lang, "آپلود آیکون", "Upload Favicon"),
        logo_upload_hint = copy(
            lang,
            "هر تصویر قابل‌نمایش در مرورگر را می‌توانید انتخاب کنید. ایران‌مانیتور آن را به یک PNG شفاف 512×512 برای پنل عمومی تبدیل و ذخیره می‌کند.",
            "Choose any browser-readable image. IranMonitor will normalize it into a transparent 512x512 PNG for the public panel.",
        ),
        favicon_upload_hint = copy(
            lang,
            "برای آیکون تب مرورگر هر تصویر قابل‌نمایش در مرورگر را انتخاب کنید. اگر ICO نباشد، سیستم خودش آن را به فایل چندسایزی 64×64 .ico تبدیل می‌کند.",
            "Choose any browser-readable image for the browser tab icon. If it is not already ICO, IranMonitor will convert it into a multi-size 64x64 .ico file.",
        ),
        logo_preview = logo_preview,
        favicon_preview = favicon_preview,
        notes_label = t(lang, "notes"),
        notes_value = html_escape(&data.settings.notes),
        save_button = t(lang, "save"),
    )
}

fn render_admin_enterprise_section(data: &AdminDashboardData, lang: UiLanguage) -> String {


    let return_to = admin_section_href(AdminSection::NetworkControls, lang);
    let traffic_watchers_table = if data.traffic_watchers.is_empty() {
        format!(
            r#"<tr><td colspan="9" class="empty-cell">{}</td></tr>"#,
            copy(lang, "هنوز ردیاب ترافیکی اضافه نشده است.", "No traffic watcher has been added yet.")
        )
    } else {
        data
            .traffic_watchers
            .iter()
            .map(|watcher| {
                format!(
                    r#"<tr>
  <td>{label}</td>
  <td>{family}</td>
  <td>{direction}</td>
  <td>{protocol}</td>
  <td>{source_ip}</td>
  <td>{port}</td>
  <td>{total}</td>
  <td>{speed}</td>
  <td class="actions-cell">
    <div class="actions-wrap">
      <form method="post" action="/admin/traffic-watchers/delete">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="watcher_id" value="{watcher_id}">
        <button type="submit" class="ghost ghost--danger">{delete_label}</button>
      </form>
    </div>
  </td>
</tr>"#,
                    label = html_escape(&watcher.label),
                    family = html_escape(&watcher.family),
                    direction = html_escape(&watcher.direction),
                    protocol = html_escape(&watcher.protocol),
                    source_ip = html_escape(if watcher.source_ip.is_empty() {
                        "*"
                    } else {
                        &watcher.source_ip
                    }),
                    port = watcher.target_port,
                    total = bytes_to_human(watcher.total_bytes),
                    speed = bits_to_human(watcher.current_bps.saturating_mul(8)),
                    return_to = html_escape(&return_to),
                    watcher_id = watcher.id,
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let speed_limits_table = if data.speed_limits.is_empty() {
        format!(
            r#"<tr><td colspan="7" class="empty-cell">{}</td></tr>"#,
            copy(lang, "هنوز محدودیت سرعتی تعریف نشده است.", "No speed limit rule has been created yet.")
        )
    } else {
        data
            .speed_limits
            .iter()
            .map(|rule| {
                format!(
                    r#"<tr>
  <td>{iface}</td>
  <td>{protocol}</td>
  <td>{port}</td>
  <td>{rate}</td>
  <td>{applied}</td>
  <td>{status}</td>
  <td class="actions-cell">
    <div class="actions-wrap">
      <form method="post" action="/admin/speed-limits/delete">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="rule_id" value="{rule_id}">
        <button type="submit" class="ghost ghost--danger">{delete_label}</button>
      </form>
    </div>
  </td>
</tr>"#,
                    iface = html_escape(&rule.interface_name),
                    protocol = html_escape(&rule.protocol),
                    port = rule.port,
                    rate = format!("{} {}", rule.rate_value, html_escape(&rule.rate_unit)),
                    applied = yes_no(lang, rule.applied),
                    status = html_escape(&rule.last_status),
                    return_to = html_escape(&return_to),
                    rule_id = rule.id,
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="split-columns">
      <div class="subpanel stack-form">
        <div>
          <h3>{watcher_title}</h3>
          <p class="muted">{watcher_note}</p>
        </div>
        <form method="post" action="/admin/traffic-watchers/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{label_label}</label><input type="text" name="label" required></div>
            <div><label>{family_label}</label><select name="family"><option value="ipv4">ipv4</option><option value="ipv6">ipv6</option><option value="any">any</option></select></div>
            <div><label>{direction_label}</label><select name="direction"><option value="input">input</option><option value="output">output</option></select></div>
            <div><label>{protocol_label}</label><select name="protocol"><option value="tcp">tcp</option><option value="udp">udp</option><option value="any">any</option></select></div>
            <div><label>{source_ip_label}</label><input type="text" name="source_ip" placeholder="198.51.100.10 or *"></div>
            <div><label>{port_label}</label><input type="number" min="1" max="65535" name="target_port" required></div>
          </div>
          <button type="submit">{add_watcher}</button>
        </form>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{label_label}</th><th>{family_label}</th><th>{direction_label}</th><th>{protocol_label}</th><th>{source_ip_label}</th><th>{port_label}</th><th>{traffic_label}</th><th>{speed_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{traffic_watchers_table}</tbody>
          </table>
        </div>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{speed_limit_title}</h3>
          <p class="muted">{speed_limit_note}</p>
        </div>
        <form method="post" action="/admin/speed-limits/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{interface_label}</label><input type="text" name="interface_name" placeholder="eth0" required></div>
            <div><label>{protocol_label}</label><select name="protocol"><option value="tcp">tcp</option><option value="udp">udp</option></select></div>
            <div><label>{port_label}</label><input type="number" min="1" max="65535" name="port" required></div>
            <div><label>{rate_label}</label><input type="number" min="1" name="rate_value" required></div>
            <div><label>{rate_unit_label}</label><select name="rate_unit"><option value="mbps">Mbps</option><option value="kbps">Kbps</option><option value="gbps">Gbps</option></select></div>
          </div>
          <button type="submit">{add_speed_limit}</button>
        </form>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{interface_label}</th><th>{protocol_label}</th><th>{port_label}</th><th>{rate_label}</th><th>{applied_label}</th><th>{status_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{speed_limits_table}</tbody>
          </table>
        </div>
        <form method="post" action="/admin/controls/apply-speed-limits" class="inline-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <button type="submit">{apply_speed_limits}</button>
        </form>

        <div class="section-divider"></div>
        <div>
          <h3>{tcp_limit_title}</h3>
          <p class="muted">{tcp_limit_note}</p>
        </div>
        <form method="post" action="/admin/controls/tcp-limit" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{enabled_label}</label><select name="enabled"><option value="1" {tcp_enabled_yes}>{yes}</option><option value="0" {tcp_enabled_no}>{no}</option></select></div>
            <div><label>{port_label}</label><input type="number" min="1" max="65535" name="target_port" value="{tcp_target_port_value}"></div>
            <div><label>{limit_per_ip}</label><input type="number" min="1" name="limit_per_ip" value="{tcp_limit_value}"></div>
          </div>
          <button type="submit">{apply_tcp_limit}</button>
        </form>
        <p class="muted">{tcp_limit_status}: {tcp_limit_status_value}</p>
      </div>
    </div>
  </div>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "کنترل شبکه", "Network Controls"),
            copy(
                lang,
                "در این بخش می‌توانید مصرف ترافیک هر پورت را ببینید، برای یک پورت محدودیت سرعت بگذارید و تعداد اتصال‌های TCP هر IP را برای همان پورت کنترل کنید.",
                "Use this page to watch per-port traffic, apply per-port speed limits, and control TCP connection counts per IP on a chosen port.",
            ),
            String::new(),
        ),
        watcher_title = t(lang, "traffic_watchers"),
        watcher_note = copy(
            lang,
            "برای هر پورت یا IP مهم، ترافیک و سرعت زنده را نگه‌داری کنید.",
            "Track total traffic and current speed for the ports and source IPs you care about.",
        ),
        return_to = html_escape(&return_to),
        label_label = t(lang, "label"),
        family_label = t(lang, "family"),
        direction_label = t(lang, "direction"),
        protocol_label = t(lang, "protocol"),
        source_ip_label = t(lang, "source_ip"),
        port_label = t(lang, "port"),
        add_watcher = t(lang, "add_watcher"),
        traffic_label = t(lang, "traffic"),
        speed_label = t(lang, "speed"),
        actions_label = t(lang, "actions"),
        traffic_watchers_table = traffic_watchers_table,
        speed_limit_title = t(lang, "speed_limits"),
        speed_limit_note = copy(
            lang,
            "این محدودیت برای همان پورت روی همان اینترفیس اعمال می‌شود، نه برای کل اینترنت سرور.",
            "This shaping rule targets the selected port on the selected interface instead of capping all server traffic.",
        ),
        interface_label = t(lang, "interface"),
        rate_label = t(lang, "rate"),
        rate_unit_label = t(lang, "rate_unit"),
        add_speed_limit = t(lang, "add_speed_limit"),
        applied_label = t(lang, "applied"),
        status_label = t(lang, "status"),
        speed_limits_table = speed_limits_table,
        apply_speed_limits = t(lang, "apply_speed_limits"),
        tcp_limit_title = t(lang, "tcp_conn_limit"),
        tcp_limit_note = copy(
            lang,
            "این محدودیت اکنون به‌صورت per-port اعمال می‌شود تا فقط همان ورودی یا سرویس مشخص در برابر هجوم اتصال محافظت شود.",
            "This TCP guard is now per-port, so you can protect a single inbound or service instead of affecting every TCP listener.",
        ),
        enabled_label = t(lang, "enabled"),
        tcp_enabled_yes = if data.tcp_conn_limit.enabled { "selected" } else { "" },
        tcp_enabled_no = if data.tcp_conn_limit.enabled { "" } else { "selected" },
        yes = t(lang, "yes"),
        no = t(lang, "no"),
        tcp_target_port_value = data.tcp_conn_limit.target_port,
        limit_per_ip = t(lang, "limit_per_ip"),
        tcp_limit_value = data.tcp_conn_limit.limit_per_ip,
        apply_tcp_limit = t(lang, "apply_tcp_limit"),
        tcp_limit_status = t(lang, "tcp_limit_status"),
        tcp_limit_status_value = html_escape(&data.tcp_conn_limit.last_status),
    )
}

fn render_admin_forwarding_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::Forwarding, lang);
    let interface_options = render_forward_interface_options(&data.host_ip_inventory, lang);
    let rules_table = if data.port_forward_rules.is_empty() {
        format!(
            r#"<tr><td colspan="10" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز قانون فورواردی اضافه نشده است.",
                "No forwarding rule has been added yet.",
            )
        )
    } else {
        data.port_forward_rules
            .iter()
            .map(|rule| {
                format!(
                    r#"<tr>
  <td>{label}</td>
  <td>{protocol}</td>
  <td>{family}</td>
  <td>{interface_name}</td>
  <td>{source_ip}</td>
  <td>{listen_port}</td>
  <td>{target_host}</td>
  <td>{target_port}</td>
  <td>{status}</td>
  <td class="actions-cell">
    <div class="actions-wrap">
      <form method="post" action="/admin/forward-rules/delete">
        <input type="hidden" name="return_to" value="{return_to}">
        <input type="hidden" name="rule_id" value="{rule_id}">
        <button type="submit" class="ghost ghost--danger">{delete_label}</button>
      </form>
    </div>
  </td>
</tr>"#,
                    label = html_escape(&rule.label),
                    protocol = html_escape(&rule.protocol),
                    family = html_escape(&rule.family),
                    interface_name = html_escape(if rule.interface_name.trim().is_empty() {
                        copy(lang, "همه", "Any")
                    } else {
                        &rule.interface_name
                    }),
                    source_ip = html_escape(if rule.source_ip.trim().is_empty() {
                        copy(lang, "همه", "Any")
                    } else {
                        &rule.source_ip
                    }),
                    listen_port = if rule.protocol.eq_ignore_ascii_case("icmp") {
                        "-".to_string()
                    } else {
                        rule.listen_port.to_string()
                    },
                    target_host = html_escape(&rule.target_host),
                    target_port = if rule.protocol.eq_ignore_ascii_case("icmp") {
                        "-".to_string()
                    } else {
                        rule.target_port.to_string()
                    },
                    status = html_escape(&rule.last_status),
                    return_to = html_escape(&return_to),
                    rule_id = rule.id,
                    delete_label = t(lang, "delete"),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="split-columns">
      <div class="subpanel stack-form">
        <div>
          <h3>{builder_title}</h3>
          <p class="muted">{builder_note}</p>
        </div>
        <form method="post" action="/admin/forward-rules/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{label_label}</label><input type="text" name="label" required></div>
            <div><label>{protocol_label}</label><select name="protocol" id="forwardProtocolSelect"><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option></select></div>
            <div data-forward-fields="1"><label>{family_label}</label><select name="family"><option value="ipv4">ipv4</option><option value="ipv6">ipv6</option></select></div>
            <div data-forward-fields="1"><label>{interface_label}</label><select name="interface_name"><option value="">{interface_any}</option>{interface_options}</select></div>
            <div data-forward-fields="1"><label>{source_ip_label}</label><input type="text" name="source_ip" placeholder="198.51.100.10"></div>
            <div data-forward-fields="1" data-forward-port-fields="1"><label>{listen_port_label}</label><input type="number" min="0" max="65535" name="listen_port" placeholder="443"></div>
            <div data-forward-fields="1"><label>{target_host_label}</label><input type="text" name="target_host" placeholder="10.37.47.1" required></div>
            <div data-forward-fields="1" data-forward-port-fields="1"><label>{target_port_label}</label><input type="number" min="0" max="65535" name="target_port" placeholder="443"></div>
            <div><label>{enabled_label}</label><select name="enabled"><option value="1">{yes}</option><option value="0">{no}</option></select></div>
          </div>
          <div class="field-hint">{builder_hint}</div>
          <button type="submit">{add_rule_label}</button>
        </form>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{table_title}</h3>
          <p class="muted">{table_note}</p>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{label_label}</th><th>{protocol_label}</th><th>{family_label}</th><th>{interface_label}</th><th>{source_ip_label}</th><th>{listen_port_label}</th><th>{target_host_label}</th><th>{target_port_label}</th><th>{status_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{rules_table}</tbody>
          </table>
        </div>
        <form method="post" action="/admin/controls/apply-forward-rules" class="inline-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <button type="submit">{apply_rules_label}</button>
        </form>
      </div>
    </div>
  </div>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "پورت فورواردینگ", "Port Forwarding"),
            copy(
                lang,
                "ترافیک TCP، UDP یا ICMP را از این سرور به IP دیگری منتقل کنید",
                "Forward TCP, UDP, or ICMP traffic from this server to another IP.",
            ),
            String::new(),
        ),
        builder_title = copy(lang, "قانون جدید", "New Rule"),
        builder_note = copy(
            lang,
            "اول پروتکل را انتخاب کنید. بعد می‌توانید پورت ورودی، پورت مقصد، اینترفیس ورودی و IP مبدأ را محدود کنید.",
            "Choose the protocol first, then limit the inbound port, destination port, inbound interface, and source IP if needed.",
        ),
        return_to = html_escape(&return_to),
        label_label = t(lang, "label"),
        family_label = t(lang, "family"),
        protocol_label = t(lang, "protocol"),
        interface_label = t(lang, "interface"),
        interface_any = copy(lang, "همه اینترفیس‌ها", "Any interface"),
        source_ip_label = t(lang, "source_ip"),
        listen_port_label = copy(lang, "پورت ورودی", "Listen Port"),
        target_host_label = copy(lang, "IP مقصد", "Target IP"),
        target_port_label = copy(lang, "پورت مقصد", "Target Port"),
        enabled_label = t(lang, "enabled"),
        yes = t(lang, "yes"),
        no = t(lang, "no"),
        builder_hint = copy(
            lang,
            "برای TCP و UDP هر دو پورت لازم‌اند. در ICMP فقط IP مقصد استفاده می‌شود و پورت‌ها نادیده گرفته می‌شوند.",
            "TCP and UDP need both ports. ICMP uses only the target IP and ignores the port fields.",
        ),
        add_rule_label = copy(lang, "افزودن قانون فوروارد", "Add Forwarding Rule"),
        table_title = copy(lang, "قوانین فعال", "Active Rules"),
        table_note = copy(
            lang,
            "این قوانین مستقیم روی همین سرور اعمال می‌شوند.",
            "These rules are applied directly on this server.",
        ),
        status_label = t(lang, "status"),
        actions_label = t(lang, "actions"),
        rules_table = rules_table,
        interface_options = interface_options,
        apply_rules_label = copy(lang, "اعمال دوباره‌ی قوانین", "Reapply Forwarding Rules"),
    )
}

fn render_admin_source_ip_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::SourceIp, lang);
    let interface_options = render_forward_interface_options(&data.host_ip_inventory, lang);
    let rules_table = if data.source_ip_rules.is_empty() {
        format!(
            r#"<tr><td colspan="11" class="empty-cell">{}</td></tr>"#,
            copy(
                lang,
                "هنوز قانونی برای IP مبدأ ثبت نشده است.",
                "No source IP rule has been created yet.",
            )
        )
    } else {
        data
            .source_ip_rules
            .iter()
            .map(|rule| {
                let interface_name = if rule.interface_name.trim().is_empty() {
                    copy(lang, "همه", "Any")
                } else {
                    &rule.interface_name
                };
                let translate_ip = if rule.translate_ip.trim().is_empty() {
                    "-"
                } else {
                    &rule.translate_ip
                };
                format!(
                    r#"<tr>
  <td>{label}</td>
  <td>{mode}</td>
  <td>{family}</td>
  <td>{protocol}</td>
  <td>{match_port}</td>
  <td>{iface}</td>
  <td>{destination}</td>
  <td>{source}</td>
  <td>{translate}</td>
  <td>{status}</td>
  <td class="actions-cell">
    <form method="post" action="/admin/source-ip/delete" class="inline-form">
      <input type="hidden" name="return_to" value="{return_to}">
      <input type="hidden" name="source_ip_id" value="{rule_id}">
      <button type="submit" class="ghost ghost--danger">{delete_label}</button>
    </form>
  </td>
</tr>"#,
                    label = html_escape(&rule.label),
                    family = html_escape(&rule.family),
                    protocol = html_escape(&rule.protocol),
                    match_port = if rule.match_port == 0 {
                        copy(lang, "همه", "All").to_string()
                    } else {
                        rule.match_port.to_string()
                    },
                    iface = html_escape(interface_name),
                    destination = html_escape(&rule.destination_ip),
                    source = html_escape(&rule.source_ip),
                    translate = html_escape(translate_ip),
                    status = html_escape(&rule.last_status),
                    return_to = html_escape(&return_to),
                    rule_id = rule.id,
                    delete_label = t(lang, "delete"),
                    mode = if rule.mode == "snat" { "SNAT" } else { copy(lang, "جفت دو سرور", "Paired peers") },
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="split-columns">
      <div class="subpanel stack-form">
        <div>
          <h3>{builder_title}</h3>
          <p class="muted">{builder_note}</p>
        </div>
        <form method="post" action="/admin/source-ip/save" class="stack-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <div class="form-grid">
            <div><label>{label_label}</label><input type="text" name="source_ip_label" required></div>
            <div><label>{mode_label}</label><select name="source_ip_mode" id="sourceIpMode"><option value="snat" selected>{snat_label}</option><option value="paired">{paired_label}</option></select></div>
            <div><label>{family_label}</label><select name="source_ip_family" id="sourceIpFamily"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></div>
            <div><label>{protocol_label}</label><input type="text" name="source_ip_protocol" id="sourceIpProtocol" value="all" list="sourceIpProtocols" required spellcheck="false"><datalist id="sourceIpProtocols"><option value="all"><option value="tcp"><option value="udp"><option value="icmp"><option value="icmpv6"><option value="ipip"><option value="ipv6"><option value="gre"><option value="esp"><option value="ah"><option value="etherip"><option value="l2tp"></datalist><div class="field-hint">{protocol_hint}</div></div>
            <div><label>{match_port_label}</label><input type="number" min="0" max="65535" name="source_ip_match_port" placeholder="0"></div>
            <div><label>{interface_label}</label><select name="source_ip_interface"><option value="">{interface_any}</option>{interface_options}</select></div>
            <div><label>{destination_label}</label><input type="text" name="source_ip_destination_ip" placeholder="{destination_placeholder}" required></div>
            <div><label>{source_ip_label}</label><input type="text" name="source_ip_source_ip" placeholder="{source_placeholder}" required></div>
            <div data-source-ip-paired><label>{translate_label}</label><input type="text" name="source_ip_translate_ip" placeholder="{translate_placeholder}"></div>
            <div><label>{enabled_label}</label><select name="source_ip_enabled"><option value="1">{yes}</option><option value="0">{no}</option></select></div>
          </div>
          <div class="guide-callout" id="sourceIpModeHelp" role="status">{builder_hint}</div>
          <button type="submit">{add_rule_label}</button>
        </form>
      </div>
      <div class="subpanel stack-form">
        <div>
          <h3>{table_title}</h3>
          <p class="muted">{table_note}</p>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr><th>{label_label}</th><th>{mode_label}</th><th>{family_label}</th><th>{protocol_label}</th><th>{match_port_label}</th><th>{interface_label}</th><th>{destination_label}</th><th>{source_ip_label}</th><th>{translate_label}</th><th>{status_label}</th><th>{actions_label}</th></tr>
            </thead>
            <tbody>{rules_table}</tbody>
          </table>
        </div>
        <form method="post" action="/admin/source-ip/apply" class="inline-form">
          <input type="hidden" name="return_to" value="{return_to}">
          <button type="submit">{apply_rules_label}</button>
        </form>
      </div>
    </div>
  </div>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "ایپی مبدا", "Source IP"),
            copy(
                lang,
                "آدرس مبدأ خروجی را با SNAT یا بازنویسی هماهنگ دو سرور تنظیم کنید.",
                "Configure outbound source addresses with SNAT or coordinated peer rewriting.",
            ),
            String::new(),
        ),
        builder_title = copy(lang, "قانون جدید", "New Rule"),
        builder_note = copy(
            lang,
            "حالت SNAT برای تغییر آدرس مبدأ خروجی است. حالت جفت، رفتار قدیمی دو سرور را حفظ می‌کند.",
            "SNAT changes the outgoing source address. Paired mode preserves the existing two-server behavior.",
        ),
        return_to = html_escape(&return_to),
        label_label = t(lang, "label"),
        mode_label = copy(lang, "روش بازنویسی", "Rewrite mode"),
        snat_label = copy(lang, "SNAT · مبدأ خروجی محلی", "SNAT · local outbound source"),
        paired_label = copy(lang, "جفت دو سرور · IPv4", "Paired peers · IPv4"),
        protocol_hint = copy(lang, "نام پروتکل یا شماره IP از ۰ تا ۲۵۵؛ all برای همه.", "Protocol name or IP protocol number 0–255; all matches any protocol."),
        family_label = t(lang, "family"),
        protocol_label = t(lang, "protocol"),
        match_port_label = copy(lang, "پورت", "Port"),
        interface_label = t(lang, "interface"),
        interface_any = copy(lang, "همه اینترفیس‌ها", "Any interface"),
        destination_label = copy(lang, "IP یا شبکه مقصد", "Destination IP / network"),
        source_ip_label = t(lang, "source_ip"),
        translate_label = copy(lang, "IP ترجمه برگشت", "Return Translate IP"),
        destination_placeholder = copy(lang, "Target IP", "Target IP"),
        source_placeholder = copy(lang, "ایپی مبدا", "Source IP"),
        translate_placeholder = copy(lang, "Target IP", "Target IP"),
        enabled_label = t(lang, "enabled"),
        yes = t(lang, "yes"),
        no = t(lang, "no"),
        builder_hint = copy(
            lang,
            "SNAT آدرس مبدأ بسته‌های خروجی به مقصد انتخابی را تغییر می‌دهد. آدرس مبدأ باید روی این سرور قابل استفاده باشد و مسیر برگشت به آن برسد. IPv4 و IPv6 پشتیبانی می‌شوند؛ IP ترجمه برگشت در این حالت کاربرد ندارد.",
            "SNAT rewrites outgoing packets to the chosen destination. The source address must be usable by this server, with a return route to it. IPv4 and IPv6 are supported; Return Translate IP is unused in this mode.",
        ),
        add_rule_label = copy(lang, "افزودن قانون IP مبدأ", "Add Source IP Rule"),
        table_title = copy(lang, "قوانین فعال", "Active Rules"),
        table_note = copy(
            lang,
            "این قوانین روی همین سرور اعمال می‌شوند.",
            "These rules are applied on this server.",
        ),
        status_label = t(lang, "status"),
        actions_label = t(lang, "actions"),
        rules_table = rules_table,
        interface_options = interface_options,
        apply_rules_label = copy(lang, "اعمال دوباره‌ی قوانین", "Reapply Source IP Rules"),
    )
}

fn render_admin_sockets_section(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let return_to = admin_section_href(AdminSection::Sockets, lang);
    let socket_rows = if data.socket_inventory.is_empty() {
        format!(
            r#"<tr><td colspan="6" class="empty-cell">{}</td></tr>"#,
            copy(lang, "فعلاً سوکتی برای نمایش پیدا نشد.", "No socket entry is available right now.")
        )
    } else {
        data
            .socket_inventory
            .iter()
            .map(|socket| {
                let primary_name = if socket.process.is_empty() {
                    if socket.service_unit.is_empty() {
                        "-"
                    } else {
                        &socket.service_unit
                    }
                } else {
                    &socket.process
                };
                let service_label = if socket.service_unit.is_empty() {
                    copy(lang, "فرآیند مستقیم / بدون systemd", "Direct process / no systemd unit")
                } else {
                    &socket.service_unit
                };
                let action_bar = render_socket_action_bar(socket, &return_to, lang);
                let badges = if socket.is_protected {
                    format!(
                        r#"<div class="socket-badge-row">
  <span class="pill socket-guard-pill">iMonitor</span>
  <span class="pill pill--soft">{}</span>
</div>"#,
                        copy(lang, "محافظت‌شده", "Protected")
                    )
                } else {
                    String::new()
                };
                let row_class = if socket.is_protected {
                    "socket-row socket-row--protected"
                } else {
                    "socket-row"
                };
                format!(
                    r#"<tr class="{row_class}">
  <td>
    <div class="table-primary">{process}</div>
    <div class="table-secondary">{service_label}</div>
    <div class="table-secondary">PID {pid}</div>
    {badges}
  </td>
  <td>{proto}</td>
  <td>{state}</td>
  <td>{local}</td>
  <td>{remote}</td>
  <td class="actions-cell actions-cell--wide">{action_bar}</td>
</tr>"#,
                    row_class = row_class,
                    process = html_escape(primary_name),
                    service_label = html_escape(service_label),
                    pid = html_escape(if socket.pid.is_empty() { "-" } else { &socket.pid }),
                    badges = badges,
                    proto = html_escape(&socket.proto),
                    state = html_escape(&socket.state),
                    local = html_escape(&socket.local_address),
                    remote = html_escape(&socket.remote_address),
                    action_bar = action_bar,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    format!(
        r#"<section class="page-grid page-grid--admin">
  <div class="card section-card fade-up">
    {section_header}
    <div class="table-shell">
      <table>
        <thead><tr><th>{process_label}</th><th>{protocol_label}</th><th>{state_label}</th><th>{local_label}</th><th>{remote_label}</th><th>{actions_label}</th></tr></thead>
        <tbody>{socket_rows}</tbody>
      </table>
    </div>
  </div>
</section>"#,
        section_header = render_section_header(
            "",
            copy(lang, "پورت/سوکت ها", "Ports / Sockets"),
            "",
            String::new(),
        ),
        process_label = t(lang, "process"),
        protocol_label = t(lang, "protocol"),
        state_label = t(lang, "state"),
        local_label = t(lang, "local"),
        remote_label = t(lang, "remote"),
        actions_label = t(lang, "actions"),
        socket_rows = socket_rows,
    )
}

fn render_socket_action_bar(
    socket: &crate::app_types::AppSocketRecord,
    return_to: &str,
    lang: UiLanguage,
) -> String {
    if socket.is_protected {
        return format!(
            r#"<div class="socket-actions-note">{}</div>"#,
            copy(
                lang,
                "iMonitor برای جلوگیری از قطع شدن پنل از این بخش قابل stop/start/restart نیست.",
                "iMonitor is protected here so the panel is not accidentally stopped or restarted.",
            ),
        );
    }

    let mut actions = Vec::new();
    if socket.can_start {
        actions.push(render_socket_action_form(
            "start",
            copy(lang, "شروع", "Start"),
            "",
            socket,
            return_to,
        ));
    }
    if socket.can_restart {
        actions.push(render_socket_action_form(
            "restart",
            copy(lang, "ری‌استارت", "Restart"),
            "ghost",
            socket,
            return_to,
        ));
    }
    if socket.can_stop {
        actions.push(render_socket_action_form(
            "stop",
            copy(lang, "توقف", "Stop"),
            "ghost ghost--danger",
            socket,
            return_to,
        ));
    }

    if actions.is_empty() {
        format!(
            r#"<div class="socket-actions-note">{}</div>"#,
            copy(
                lang,
                "برای این ردیف فقط مشاهده در دسترس است.",
                "This row is view-only right now.",
            ),
        )
    } else {
        format!(r#"<div class="socket-action-bar">{}</div>"#, actions.join(""))
    }
}

fn render_socket_action_form(
    action: &str,
    label: &str,
    button_class: &str,
    socket: &crate::app_types::AppSocketRecord,
    return_to: &str,
) -> String {
    let class_attr = if button_class.trim().is_empty() {
        String::new()
    } else {
        format!(r#" class="{}""#, html_escape(button_class))
    };
    format!(
        r#"<form method="post" action="/admin/socket-control" class="socket-action-form">
  <input type="hidden" name="return_to" value="{return_to}">
  <input type="hidden" name="action" value="{action}">
  <input type="hidden" name="service_unit" value="{service_unit}">
  <input type="hidden" name="pid" value="{pid}">
  <input type="hidden" name="is_protected" value="{is_protected}">
  <button type="submit"{class_attr}>{label}</button>
</form>"#,
        return_to = html_escape(return_to),
        action = html_escape(action),
        service_unit = html_escape(&socket.service_unit),
        pid = html_escape(&socket.pid),
        is_protected = if socket.is_protected { "1" } else { "0" },
        class_attr = class_attr,
        label = html_escape(label),
    )
}

fn render_admin_reports_section(_data: &AdminDashboardData, _lang: UiLanguage) -> String {
    String::new()
}

fn render_admin_monitor_analytics_modal(lang: UiLanguage) -> String {
    format!(
        r##"<div id="monitorAnalyticsModal" class="dialog-shell" hidden>
  <div class="dialog-backdrop" data-close-analytics="1"></div>
  <div class="dialog-card">
    <div class="dialog-header">
      <div>
        <h3 id="analyticsTitle">{title}</h3>
        <p class="muted" id="analyticsSubtitle">{subtitle}</p>
      </div>
      <button type="button" class="ghost" data-close-analytics="1">{close}</button>
    </div>
    <div class="dialog-toolbar">
      <div class="inline-form inline-form--stretch">
        <button type="button" class="ghost" data-range-preset="6h">6H</button>
        <button type="button" class="ghost" data-range-preset="24h">24H</button>
        <button type="button" class="ghost" data-range-preset="7d">7D</button>
        <button type="button" class="ghost" data-range-preset="30d">30D</button>
        <button type="button" class="ghost" data-range-preset="all">{all_ranges}</button>
      </div>
      <div class="inline-form inline-form--stretch">
        <input type="datetime-local" id="analyticsFrom">
        <input type="datetime-local" id="analyticsTo">
        <button type="button" class="ghost" data-zoom-range="in">{zoom_in}</button>
        <button type="button" class="ghost" data-zoom-range="out">{zoom_out}</button>
        <button type="button" id="analyticsApply">{apply}</button>
      </div>
      <div class="inline-form">
        <a class="ghost" id="analyticsExportCsv" href="#" target="_blank">CSV</a>
        <a class="ghost" id="analyticsExportPdf" href="#" target="_blank">PDF</a>
        <a class="ghost" id="analyticsExportXlsx" href="#" target="_blank">XLSX</a>
      </div>
    </div>
    <div class="analytics-stat-grid" id="analyticsStats"></div>
    <div class="analytics-chart-card">
      <svg id="analyticsChart" viewBox="0 0 960 320" role="img" aria-label="monitor analytics chart"></svg>
      <div id="analyticsChartEmpty" class="empty-state">{empty_chart}</div>
    </div>
    <div class="table-shell analytics-table-shell">
      <table>
        <thead>
          <tr>
            <th>{time_label}</th>
            <th>{status_label}</th>
            <th>{latency_label}</th>
            <th>{duration_label}</th>
            <th>{endpoint_label}</th>
            <th>{message_label}</th>
          </tr>
        </thead>
        <tbody id="analyticsRows"></tbody>
      </table>
    </div>
  </div>
</div>"##,
        title = copy(lang, "تحلیل مانیتور", "Monitor Analytics"),
        subtitle = copy(
            lang,
            "بازه زمانی را انتخاب کنید، روی داده‌ها زوم کنید و خروجی تحلیلی بگیرید.",
            "Choose a time range, zoom the data, and export analytics.",
        ),
        close = copy(lang, "بستن", "Close"),
        all_ranges = copy(lang, "همه", "All"),
        zoom_in = copy(lang, "بزرگ‌نمایی", "Zoom In"),
        zoom_out = copy(lang, "کوچک‌نمایی", "Zoom Out"),
        apply = copy(lang, "اعمال", "Apply"),
        empty_chart = copy(lang, "برای این بازه هنوز داده‌ای ثبت نشده است.", "No data has been captured for this range yet."),
        time_label = t(lang, "time"),
        status_label = t(lang, "status"),
        latency_label = t(lang, "latency"),
        duration_label = copy(lang, "مدت اجرا", "Duration"),
        endpoint_label = t(lang, "endpoint"),
        message_label = t(lang, "message"),
    )
}

fn render_admin_tunnel_diagnostics_modal(lang: UiLanguage) -> String {
    format!(
        r##"<div id="tunnelDiagnosticsModal" class="dialog-shell" hidden>
  <div class="dialog-backdrop" data-close-tunnel-diagnostics="1"></div>
  <div class="dialog-card">
    <div class="dialog-header">
      <div>
        <h3 id="tunnelDiagTitle">{title}</h3>
        <p class="muted" id="tunnelDiagSubtitle">{subtitle}</p>
      </div>
      <button type="button" class="ghost" data-close-tunnel-diagnostics="1">{close}</button>
    </div>
    <div class="tunnel-diag-shell">
      <div class="dialog-toolbar">
        <div class="tunnel-diag-toolbar">
          <div class="inline-alert inline-alert--soft">{note}</div>
          <button type="button" id="tunnelDiagRun">{run_label}</button>
        </div>
      </div>
      <div class="analytics-stat-grid tunnel-diag-meta" id="tunnelDiagMeta"></div>
      <div class="tunnel-speed-grid">
        <article class="tunnel-meter-card tunnel-meter-card--upload">
          <div class="tunnel-meter-card__head">
            <div>
              <strong>{upload_title}</strong>
              <div class="table-secondary">{native_test_label}</div>
            </div>
            <span class="pill pill--soft">{live_chip}</span>
          </div>
          <div class="tunnel-speedometer" id="tunnelDiagUploadGauge">
            <div class="tunnel-speedometer__arc"></div>
            <div class="tunnel-speedometer__needle"></div>
            <div class="tunnel-speedometer__readout">
              <strong id="tunnelDiagUploadText">-</strong>
              <span>Mbps</span>
            </div>
          </div>
          <details class="soft-details tunnel-diag-details">
            <summary>{raw_output_label}</summary>
            <pre class="code-block small" id="tunnelDiagUploadRaw">-</pre>
          </details>
        </article>
        <article class="tunnel-meter-card tunnel-meter-card--download">
          <div class="tunnel-meter-card__head">
            <div>
              <strong>{download_title}</strong>
              <div class="table-secondary">{native_test_label}</div>
            </div>
            <span class="pill pill--soft">{live_chip}</span>
          </div>
          <div class="tunnel-speedometer" id="tunnelDiagDownloadGauge">
            <div class="tunnel-speedometer__arc"></div>
            <div class="tunnel-speedometer__needle"></div>
            <div class="tunnel-speedometer__readout">
              <strong id="tunnelDiagDownloadText">-</strong>
              <span>Mbps</span>
            </div>
          </div>
          <details class="soft-details tunnel-diag-details">
            <summary>{raw_output_label}</summary>
            <pre class="code-block small" id="tunnelDiagDownloadRaw">-</pre>
          </details>
        </article>
        <article class="tunnel-meter-card tunnel-meter-card--ping">
          <div class="tunnel-meter-card__head">
            <div>
              <strong>{ping_title}</strong>
              <div class="table-secondary">{ping_hint}</div>
            </div>
            <span class="pill pill--soft">{ping_chip}</span>
          </div>
          <div class="tunnel-speedometer tunnel-speedometer--ping" id="tunnelDiagPingGauge">
            <div class="tunnel-speedometer__arc"></div>
            <div class="tunnel-speedometer__needle"></div>
            <div class="tunnel-speedometer__readout">
              <strong id="tunnelDiagPingText">-</strong>
              <span>ms</span>
            </div>
          </div>
          <details class="soft-details tunnel-diag-details">
            <summary>{raw_output_label}</summary>
            <pre class="code-block small" id="tunnelDiagPingRaw">-</pre>
          </details>
        </article>
      </div>
    </div>
  </div>
</div>"##,
        native_test_label = copy(lang,"تست داخلی iMonitor","Native iMonitor test"),
        title = copy(lang, "پینگ و سرعت تونل", "Tunnel Ping & Speed"),
        subtitle = copy(
            lang,
            "این پنجره به‌صورت زنده ۴ پینگ ICMP و تست سرعت upload / download را روی inner probe همین تونل اجرا می‌کند.",
            "This modal runs a live 4-packet ICMP probe and upload/download speed test against this tunnel's inner probe.",
        ),
        close = copy(lang, "بستن", "Close"),
        run_label = copy(lang, "اجرای دوباره تست", "Run Test Again"),
        live_chip = copy(lang, "زنده", "Live"),
        note = copy(
            lang,
            "تست داخلی، سرعت ارسال و دریافت از مسیر تونل را نشان می‌دهد. شنونده تست iMonitor باید در سرور مقابل فعال باشد؛ نصب ابزار جداگانه لازم نیست. تست برای مدت کوتاه پهنای باند تونل را مصرف می‌کند.",
            "The built-in test measures upload and download through your tunnel, with live progress. Enable the iMonitor test listener on the peer; no external speed-test package is needed. A test briefly uses tunnel bandwidth.",
        ),
        ping_title = copy(lang, "میانگین پینگ", "Ping Average"),
        ping_hint = copy(lang, "میانگین ۴ درخواست ICMP", "4 ICMP requests average"),
        ping_chip = copy(lang, "۴ درخواست", "4 requests"),
        upload_title = copy(lang, "سرعت Upload", "Upload Speed"),
        download_title = copy(lang, "سرعت Download", "Download Speed"),
        raw_output_label = copy(lang, "خروجی خام", "Raw Output"),
    )
}

fn admin_release_gap(current: &str, latest: &str) -> i32 {
    let parse = |value: &str| -> i32 {
        value
            .split('.')
            .enumerate()
            .fold(0_i32, |acc, (index, part)| {
                let factor = match index {
                    0 => 10_000,
                    1 => 100,
                    _ => 1,
                };
                acc + part.parse::<i32>().unwrap_or(0) * factor
            })
    };
    (parse(latest) - parse(current)).max(0)
}

fn admin_release_status_class(current: &str, latest: &str) -> &'static str {
    let gap = admin_release_gap(current, latest);
    if gap <= 0 {
        "pill--success"
    } else if gap <= 100 {
        "pill--warn"
    } else {
        "pill--danger"
    }
}

fn admin_release_button_class(current: &str, latest: &str) -> &'static str {
    let gap = admin_release_gap(current, latest);
    if gap <= 0 {
        "ghost--success"
    } else if gap <= 100 {
        "ghost--warn"
    } else {
        "ghost--danger"
    }
}

fn admin_release_status_text(current: &str, latest: &str, lang: UiLanguage) -> String {
    let gap = admin_release_gap(current, latest);
    if gap <= 0 {
        copy(lang, "آخرین نسخه", "Latest version").to_string()
    } else {
        format!(
            "{} {}",
            copy(lang, "نسخه جدید", "Latest"),
            latest
        )
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0_usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn render_server_health_map(report: &crate::app_types::ServerHealthReport) -> String {
    let accessible_markers = report
        .accessible_regions
        .iter()
        .filter_map(|probe| {
            server_health_country_position(&probe.country_code).map(|(x, y)| {
                format!(
                    r#"<g class="server-health-map__marker server-health-map__marker--up"><title>{label}</title><circle cx="{x}" cy="{y}" r="5.5"></circle></g>"#,
                    x = x,
                    y = y,
                    label = html_escape(&probe.label),
                )
            })
        })
        .collect::<Vec<_>>()
        .join("");
    let blocked_markers = report
        .blocked_regions
        .iter()
        .filter_map(|probe| {
            server_health_country_position(&probe.country_code).map(|(x, y)| {
                format!(
                    r#"<g class="server-health-map__marker server-health-map__marker--down"><title>{label}</title><circle cx="{x}" cy="{y}" r="3.5"></circle></g>"#,
                    x = x,
                    y = y,
                    label = html_escape(&probe.label),
                )
            })
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<svg class="server-health-map" viewBox="0 0 1200 620" role="img" aria-label="server reachability map">
  <defs>
    <linearGradient id="server-health-ocean" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="rgba(7,28,24,0.98)"/>
      <stop offset="100%" stop-color="rgba(9,38,30,0.98)"/>
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="1200" height="620" rx="34" fill="url(#server-health-ocean)" stroke="rgba(120,160,136,0.18)"/>
  <g class="server-health-map__grid">
    <line x1="120" y1="90" x2="120" y2="530"/><line x1="300" y1="90" x2="300" y2="530"/><line x1="480" y1="90" x2="480" y2="530"/><line x1="660" y1="90" x2="660" y2="530"/><line x1="840" y1="90" x2="840" y2="530"/><line x1="1020" y1="90" x2="1020" y2="530"/>
    <line x1="70" y1="150" x2="1130" y2="150"/><line x1="70" y1="260" x2="1130" y2="260"/><line x1="70" y1="370" x2="1130" y2="370"/><line x1="70" y1="480" x2="1130" y2="480"/>
  </g>
  <g class="server-health-map__land">
    <path d="M92 226c28-58 96-118 178-136 90-20 152 4 186 46 34 42 50 60 88 72 26 8 38 26 36 48-2 30-30 48-58 60-22 10-34 28-54 44-34 28-76 44-130 44-94 0-188-34-258-96-40-36-48-54-46-82z"/>
    <path d="M446 118c58-40 162-56 252-46 78 10 128 30 154 62 24 28 32 62 18 90-10 22-28 38-54 48-20 8-44 12-54 30-20 34-48 72-90 92-54 26-136 32-218 12-88-22-144-72-162-140-16-64 6-118 54-148z"/>
    <path d="M804 162c38-20 90-34 146-32 66 2 120 16 156 44 48 36 58 68 34 98-14 18-40 30-62 42-20 12-38 26-54 46-20 28-42 58-82 74-56 24-136 28-198 8-54-18-84-48-102-90-16-40-20-96 10-136 28-36 74-44 152-54z"/>
    <path d="M960 420c26-16 68-16 102 0 34 16 62 48 72 88 10 42-2 68-34 82-46 20-118 8-156-26-44-40-48-100-10-134 8-6 16-8 26-10z"/>
    <path d="M704 454c24-18 54-26 82-24 22 2 40 10 50 24 10 14 10 30 2 46-10 20-30 34-52 44-18 8-42 14-64 6-28-8-48-32-46-54 0-18 10-30 28-42z"/>
    <path d="M540 442c14-8 34-8 50 2 16 8 28 24 28 38 0 20-14 34-34 40-24 8-54-2-66-24-12-18-2-42 22-56z"/>
  </g>
  {blocked_markers}
  {accessible_markers}
</svg>"#,
        accessible_markers = accessible_markers,
        blocked_markers = blocked_markers,
    )
}

fn server_health_country_position(country_code: &str) -> Option<(i32, i32)> {
    match country_code.to_ascii_uppercase().as_str() {
        "AE" => Some((763, 332)),
        "AT" => Some((621, 217)),
        "BG" => Some((657, 241)),
        "BR" => Some((382, 433)),
        "CA" => Some((224, 159)),
        "CH" => Some((607, 223)),
        "CY" => Some((690, 265)),
        "DE" => Some((617, 201)),
        "ES" => Some((556, 252)),
        "FI" => Some((648, 130)),
        "FR" => Some((584, 225)),
        "HK" => Some((924, 289)),
        "HU" => Some((640, 220)),
        "ID" => Some((944, 430)),
        "IL" => Some((701, 281)),
        "IN" => Some((823, 320)),
        "IR" => Some((746, 263)),
        "IT" => Some((618, 248)),
        "JP" => Some((1000, 252)),
        "KZ" => Some((789, 197)),
        "LT" => Some((646, 177)),
        "MD" => Some((672, 210)),
        "NL" => Some((595, 191)),
        "PL" => Some((646, 190)),
        "PT" => Some((523, 256)),
        "RO" => Some((668, 224)),
        "RS" => Some((646, 232)),
        "RU" => Some((752, 158)),
        "SE" => Some((625, 128)),
        "SG" => Some((884, 392)),
        "SI" => Some((624, 227)),
        "TR" => Some((700, 247)),
        "UA" => Some((689, 204)),
        "US" => Some((208, 239)),
        "VN" => Some((888, 343)),
        _ => None,
    }
}

fn display_kind_label(kind: &str) -> &'static str {
    match kind.to_ascii_lowercase().as_str() {
        "icmp" => "ICMP",
        "tcp" => "TCP",
        "udp" => "UDP",
        "ssh" => "SSH",
        "sftp" => "SFTP",
        "http" => "HTTP",
        "https" => "HTTPS",
        "dns" => "DNS",
        "rdp" => "RDP",
        "ftp" => "FTP",
        "tunnel" => "Tunnel",
        "v2ray" | "v2ray_simulation" => "V2Ray",
        _ => "Monitor",
    }
}

fn render_named_status_chip(class_name: &str, label: &str) -> String {
    format!(
        r#"<span class="status-chip {class_name}">{label}</span>"#,
        class_name = html_escape(class_name),
        label = html_escape(label),
    )
}

fn render_result_status_chip(status: crate::types::CheckStatus, lang: UiLanguage) -> String {
    match status {
        crate::types::CheckStatus::Up => {
            render_named_status_chip("up", copy(lang, "سالم", "Up"))
        }
        crate::types::CheckStatus::Degraded => {
            render_named_status_chip("degraded", copy(lang, "اختلال", "Degraded"))
        }
        crate::types::CheckStatus::Down => {
            render_named_status_chip("down", copy(lang, "قطع", "Down"))
        }
    }
}

pub fn render_public_page(payload: &PublicStatusPayload, lang: UiLanguage) -> String {
    let branding = &payload.settings;
    let public_logo = render_logo(&branding.logo_url, &branding.title);
    let summary_tiles = render_public_summary_tiles(&payload.summary, lang);
    let (overall_class, overall_badge, overall_title) =
        public_overall_copy(&payload.summary, lang);
    let updated_text = public_updated_copy(payload.summary.observed_at_unix, lang);
    let theme_toggle_label = if branding.dark_mode_default {
        copy(lang, "حالت روشن", "Light mode")
    } else {
        copy(lang, "حالت تاریک", "Dark mode")
    };
    let public_theme_script = render_public_theme_script(lang);

    let (folder_groups, standalone_monitors) = collect_public_monitor_folders(&payload.latest_results);
    let availability_rows = if payload.latest_results.is_empty() {
        format!(
            r#"<div class="empty-state">{}</div>"#,
            copy(
                lang,
                "داده‌ای برای نمایش عمومی موجود نیست.",
                "There is no public data to display yet.",
            )
        )
    } else {
        folder_groups
            .iter()
            .map(|folder| render_public_monitor_folder(folder, lang))
            .chain(
                standalone_monitors
                    .iter()
                    .map(|check| render_public_monitor_card(check, lang)),
            )
            .collect::<Vec<_>>()
            .join("")
    };

    let timeline_cells = if payload.history.is_empty() {
        format!(
            r#"<div class="empty-state">{}</div>"#,
            copy(
                lang,
                "هنوز تاریخچه‌ای برای نمایش ثبت نشده است.",
                "No historical availability timeline has been captured yet.",
            )
        )
    } else {
        payload
            .history
            .iter()
            .map(|point| render_overall_timeline_cell(point, lang))
            .collect::<Vec<_>>()
            .join("")
    };

    let timeline_count = if payload.history.is_empty() {
        copy(lang, "بدون تاریخچه", "No history").to_string()
    } else if matches!(lang, UiLanguage::Fa) {
        format!("{} بازه اخیر", payload.history.len())
    } else {
        format!("{} recent checks", payload.history.len())
    };

    let services_count = if payload.latest_results.is_empty() {
        copy(lang, "۰ سرویس", "0 services").to_string()
    } else if matches!(lang, UiLanguage::Fa) {
        format!("{} سرویس", payload.latest_results.len())
    } else {
        format!("{} services", payload.latest_results.len())
    };

    let contact_items = [
        (!branding.contact_email.trim().is_empty())
            .then(|| format!("{}: {}", t(lang, "contact_email"), html_escape(&branding.contact_email))),
        (!branding.contact_telegram.trim().is_empty())
            .then(|| format!("{}: {}", t(lang, "contact_telegram"), html_escape(&branding.contact_telegram))),
        (!branding.contact_phone.trim().is_empty())
            .then(|| format!("{}: {}", t(lang, "contact_phone"), html_escape(&branding.contact_phone))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let contact_html = if contact_items.is_empty() {
        String::new()
    } else {
        format!(
            r#"<section class="public-footer fade-up">
  <div class="public-footer__items">{items}</div>
</section>"#,
            items = contact_items
                .iter()
                .map(|item| format!(r#"<span>{item}</span>"#))
                .collect::<Vec<_>>()
                .join("")
        )
    };

    let body = format!(
        r##"
<section class="public-simple-hero fade-up">
  <div class="public-simple-top">
    <div class="public-simple-brand">
      <div class="brand-line brand-line--large">
        {logo}
        <div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
      </div>
    </div>
    <div class="hero-actions hero-actions--simple">
      <button type="button" class="ghost ghost--subtle theme-toggle" id="themeToggle">{theme_toggle_label}</button>
      <a class="ghost ghost--subtle" href="/?lang=fa">فارسی</a>
      <a class="ghost ghost--subtle" href="/?lang=en">English</a>
    </div>
  </div>
  <div class="public-simple-headline">
    <span class="overall-pill overall-pill--{overall_class}">{overall_badge}</span>
    <h2>{overall_title}</h2>
    <p>{updated_text}</p>
  </div>
  <div class="public-summary-grid">{summary_tiles}</div>
</section>

<section class="page-grid public-grid public-grid--simple">
  <div class="card section-card fade-up public-simple-section">
    <div class="public-simple-section__head">
      <div>
        <h2>{timeline_title}</h2>
        <p>{timeline_copy}</p>
      </div>
      <span class="public-simple-count">{timeline_count}</span>
    </div>
    <div class="radar-strip-shell radar-strip-shell--simple">
      <div class="radar-strip radar-strip--overview">
        {timeline_cells}
      </div>
    </div>
    <div class="radar-legend">
      <span><i class="legend-dot legend-dot--up"></i>{legend_up}</span>
      <span><i class="legend-dot legend-dot--degraded"></i>{legend_degraded}</span>
      <span><i class="legend-dot legend-dot--down"></i>{legend_down}</span>
    </div>
  </div>

  <div class="card section-card fade-up public-simple-section">
    <div class="public-simple-section__head">
      <div>
        <h2>{services_title}</h2>
        <p>{services_copy}</p>
      </div>
      <span class="public-simple-count">{services_count}</span>
    </div>
    <div class="public-status-stack">{availability_rows}</div>
  </div>
</section>
{public_ad}
{contact_html}
{public_theme_script}
"##,
        logo = public_logo,
        title = html_escape(&branding.title),
        subtitle = html_escape(&branding.subtitle),
        theme_toggle_label = html_escape(theme_toggle_label),
        overall_class = overall_class,
        overall_badge = overall_badge,
        overall_title = overall_title,
        updated_text = updated_text,
        summary_tiles = summary_tiles,
        timeline_title = copy(lang, "وضعیت کلی", "Overall status"),
        timeline_copy = copy(lang, "روند اخیر همه مانیتورها.", "Recent history across all public monitors."),
        timeline_count = timeline_count,
        timeline_cells = timeline_cells,
        legend_up = copy(lang, "سالم", "Healthy"),
        legend_degraded = copy(lang, "اختلال", "Degraded"),
        legend_down = copy(lang, "قطع", "Down"),
        services_title = copy(lang, "سرویس‌ها", "Services"),
        services_copy = copy(lang, "وضعیت فعلی هر مانیتور عمومی.", "Current status for each public monitor."),
        services_count = services_count,
        availability_rows = availability_rows,
        public_ad = crate::ads::render_slot("public", lang),
        contact_html = contact_html,
        public_theme_script = public_theme_script,
    );

    render_layout(branding, lang, &branding.title, body, false)
}

fn collect_public_monitor_folders(
    checks: &[PublicCheckView],
) -> (Vec<PublicMonitorFolder>, Vec<PublicCheckView>) {
    let mut folders: Vec<PublicMonitorFolder> = Vec::new();
    let mut folder_indexes: BTreeMap<String, usize> = BTreeMap::new();
    let mut standalone: Vec<PublicCheckView> = Vec::new();

    for check in checks {
        let group_name = check.group_name.trim();
        if group_name.is_empty() {
            standalone.push(check.clone());
            continue;
        }

        let key = group_name.to_string();
        if let Some(index) = folder_indexes.get(&key).copied() {
            let folder: &mut PublicMonitorFolder = &mut folders[index];
            if folder.logo_url.is_empty() && !check.group_logo_url.trim().is_empty() {
                folder.logo_url = check.group_logo_url.trim().to_string();
            }
            if folder.logo_shape == "rounded" && !check.group_logo_shape.trim().is_empty() {
                folder.logo_shape =
                    normalize_group_logo_shape(&check.group_logo_shape).to_string();
            }
            folder.monitors.push(check.clone());
            continue;
        }

        folder_indexes.insert(key.clone(), folders.len());
        folders.push(PublicMonitorFolder {
            name: key,
            logo_url: check.group_logo_url.trim().to_string(),
            logo_shape: normalize_group_logo_shape(&check.group_logo_shape).to_string(),
            monitors: vec![check.clone()],
        });
    }

    (folders, standalone)
}

fn render_folder_logo_markup(name: &str, logo_url: &str, logo_shape: &str) -> String {
    let shape = normalize_group_logo_shape(logo_shape);
    let initials = name
        .split_whitespace()
        .filter_map(|segment| segment.chars().next())
        .take(2)
        .collect::<String>();
    let fallback = if initials.is_empty() {
        "M".to_string()
    } else {
        initials
    };

    if logo_url.trim().is_empty() {
        format!(
            r#"<span class="public-folder__logo public-folder__logo--{shape}"><span>{fallback}</span></span>"#,
            shape = html_escape(shape),
            fallback = html_escape(&fallback),
        )
    } else {
        let src = resolve_public_asset_href(logo_url);
        format!(
            r#"<span class="public-folder__logo public-folder__logo--{shape}" data-auto-aspect-frame><img src="{src}" alt="{alt}" loading="lazy" data-auto-aspect></span>"#,
            shape = html_escape(shape),
            src = html_escape(&src),
            alt = html_escape(name),
        )
    }
}

fn render_public_folder_logo(folder: &PublicMonitorFolder) -> String {
    render_folder_logo_markup(&folder.name, &folder.logo_url, &folder.logo_shape)
}

fn render_public_folder_status_chip(status_class: &str, lang: UiLanguage) -> String {
    let label = match status_class {
        "down" => copy(lang, "قطع گسترده", "Major outage"),
        "degraded" => copy(lang, "اختلال", "Issues"),
        _ => copy(lang, "سالم", "Operational"),
    };
    render_named_status_chip(status_class, label)
}

fn folder_status_from_counts(
    total_checks: usize,
    _up_checks: usize,
    degraded_checks: usize,
    down_checks: usize,
) -> &'static str {
    if total_checks == 0 || (down_checks == 0 && degraded_checks == 0) {
        "up"
    } else if down_checks >= total_checks {
        "down"
    } else {
        "degraded"
    }
}

fn public_surface_status_from_counts(
    total_checks: usize,
    up_checks: usize,
    degraded_checks: usize,
    down_checks: usize,
) -> &'static str {
    folder_status_from_counts(total_checks, up_checks, degraded_checks, down_checks)
}

fn render_public_monitor_folder(folder: &PublicMonitorFolder, lang: UiLanguage) -> String {
    let mut up_checks = 0;
    let mut degraded_checks = 0;
    let mut down_checks = 0;
    for check in &folder.monitors {
        match check.status {
            crate::types::CheckStatus::Up => up_checks += 1,
            crate::types::CheckStatus::Degraded => degraded_checks += 1,
            crate::types::CheckStatus::Down => down_checks += 1,
        }
    }
    let total_checks = folder.monitors.len();
    let status_class = folder_status_from_counts(total_checks, up_checks, degraded_checks, down_checks);
    let summary_text = if matches!(lang, UiLanguage::Fa) {
        format!(
            "{} مانیتور • {} سالم • {} اختلال • {} قطع",
            total_checks, up_checks, degraded_checks, down_checks
        )
    } else {
        format!(
            "{} monitors • {} up • {} degraded • {} down",
            total_checks, up_checks, degraded_checks, down_checks
        )
    };
    let monitor_cards = folder
        .monitors
        .iter()
        .map(|check| render_public_monitor_card(check, lang))
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<article class="public-folder public-folder--{status_class}" data-folder>
  <button type="button" class="public-folder__toggle" data-folder-toggle aria-expanded="false">
    <div class="public-folder__brand">
      {logo}
      <div class="public-folder__copy">
        <strong>{name}</strong>
        <small>{summary_text}</small>
      </div>
    </div>
    <div class="public-folder__meta">
      {status_chip}
      <span class="public-folder__chevron" aria-hidden="true"></span>
    </div>
  </button>
  <div class="public-folder__panel">
    <div class="public-folder__panel-inner">
      <div class="public-status-stack">{monitor_cards}</div>
    </div>
  </div>
</article>"#,
        status_class = html_escape(status_class),
        logo = render_public_folder_logo(folder),
        name = html_escape(&folder.name),
        summary_text = html_escape(&summary_text),
        status_chip = render_public_folder_status_chip(status_class, lang),
        monitor_cards = monitor_cards,
    )
}

fn render_public_monitor_card(check: &PublicCheckView, lang: UiLanguage) -> String {
    let history_cells = if check.history.is_empty() {
        format!(
            r#"<div class="public-monitor-strip__empty">{}</div>"#,
            copy(
                lang,
                "هنوز تاریخچه‌ای برای این مانیتور ثبت نشده است.",
                "No public history has been captured for this monitor yet.",
            )
        )
    } else {
        check.history
            .iter()
            .map(|point| render_monitor_timeline_cell(check, point, lang))
            .collect::<Vec<_>>()
            .join("")
    };

    let uptime_text = public_monitor_uptime_copy(check, lang);
    let status_class = if check.is_pending {
        "degraded"
    } else {
        check.status.as_str_name()
    };
    let message = if check.is_pending {
        copy(
            lang,
            "در انتظار اولین نتیجه مانیتور.",
            "Waiting for the first monitor result.",
        )
    } else {
        public_message(&check.message, lang)
    };

    format!(
        r#"<article class="public-status-card public-status-card--{status_class}">
  <div class="public-status-row">
    <div class="public-status-row__main">
      <div class="public-status-row__title">
        <strong>{label}</strong>
        <span>{kind}</span>
      </div>
      <p>{message}</p>
    </div>
    <div class="public-status-row__meta">
      {status}
      <small>{uptime_text}</small>
    </div>
  </div>
  <div class="public-monitor-strip">
    <div class="radar-strip radar-strip--service">
      {history_cells}
    </div>
  </div>
</article>"#,
        status_class = html_escape(status_class),
        label = html_escape(&check.label),
        kind = html_escape(display_kind_label(&check.kind)),
        message = html_escape(message),
        status = render_public_status_chip(check, lang),
        uptime_text = html_escape(&uptime_text),
        history_cells = history_cells,
    )
}

fn render_public_theme_script(lang: UiLanguage) -> String {
    format!(
        r#"<script>
(() => {{
  const body = document.body;
  const toggle = document.getElementById('themeToggle');
  if (!body || !toggle) return;

  const storageKey = 'iranmonitor-public-theme';
  const labels = {{
    dark: '{switch_to_light}',
    light: '{switch_to_dark}'
  }};

  const applyTheme = (mode, persist) => {{
    const nextMode = mode === 'light' ? 'light' : 'dark';
    body.classList.remove('light', 'dark');
    body.classList.add(nextMode);
    toggle.textContent = labels[nextMode];
    if (persist) {{
      try {{
        window.localStorage.setItem(storageKey, nextMode);
      }} catch (_error) {{}}
    }}
  }};

  let initial = body.classList.contains('light') ? 'light' : 'dark';
  try {{
    const saved = window.localStorage.getItem(storageKey);
    if (saved === 'light' || saved === 'dark') {{
      initial = saved;
    }}
  }} catch (_error) {{}}

  const tooltip = document.createElement('div');
  tooltip.className = 'timeline-tooltip';
  tooltip.innerHTML = `
    <div class="timeline-tooltip__date"></div>
    <div class="timeline-tooltip__value"></div>
    <div class="timeline-tooltip__meta"></div>
    <div class="timeline-tooltip__detail"></div>
  `;
  document.body.appendChild(tooltip);

  const dateNode = tooltip.querySelector('.timeline-tooltip__date');
  const valueNode = tooltip.querySelector('.timeline-tooltip__value');
  const metaNode = tooltip.querySelector('.timeline-tooltip__meta');
  const detailNode = tooltip.querySelector('.timeline-tooltip__detail');
  const locale = document.documentElement.lang === 'fa' ? 'fa-IR-u-ca-gregory' : 'en-CA';
  const formatter = new Intl.DateTimeFormat(locale, {{
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }});
  const statusClasses = [
    'up',
    'degraded',
    'down',
    'neutral',
    'availability-green',
    'availability-lime',
    'availability-yellow',
    'availability-orange',
    'availability-red',
    'availability-brown',
    'availability-black'
  ];

  const placeTooltip = (target) => {{
    const rect = target.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const top = Math.max(12, rect.top - tooltipRect.height - 12);
    const left = Math.min(
      window.innerWidth - tooltipRect.width - 12,
      Math.max(12, rect.left + (rect.width / 2) - (tooltipRect.width / 2))
    );
    tooltip.style.top = `${{top}}px`;
    tooltip.style.left = `${{left}}px`;
  }};

  const syncImageAspect = (img) => {{
    if (!img || !img.naturalWidth || !img.naturalHeight) return;
    const ratio = `${{img.naturalWidth}} / ${{img.naturalHeight}}`;
    img.style.aspectRatio = ratio;
    const frame = img.closest('[data-auto-aspect-frame]');
    if (!frame || frame.classList.contains('public-folder__logo--circle')) return;
    frame.style.aspectRatio = ratio;
  }};

  const hideTooltip = () => {{
    tooltip.classList.remove('is-visible', ...statusClasses);
  }};

  document.querySelectorAll('img[data-auto-aspect]').forEach((img) => {{
    if (img.complete && img.naturalWidth > 0 && img.naturalHeight > 0) {{
      syncImageAspect(img);
    }} else {{
      img.addEventListener('load', () => syncImageAspect(img), {{ once: true }});
    }}
  }});

  document.querySelectorAll('.timeline-cell[data-tip-ts]').forEach((cell) => {{
    const showTooltip = () => {{
      const ts = Number(cell.dataset.tipTs || '0');
      const date = ts > 0 ? formatter.format(new Date(ts * 1000)) : '';
      if (dateNode) dateNode.textContent = date;
      if (valueNode) valueNode.textContent = cell.dataset.tipValue || '';
      if (metaNode) {{
        const meta = cell.dataset.tipMeta || '';
        metaNode.textContent = meta;
        metaNode.hidden = !meta;
      }}
      if (detailNode) {{
        const detail = cell.dataset.tipDetail || '';
        detailNode.textContent = detail;
        detailNode.hidden = !detail;
      }}
      tooltip.classList.remove(...statusClasses);
      tooltip.classList.add(cell.dataset.tipStatus || '');
      tooltip.classList.add('is-visible');
      placeTooltip(cell);
    }};

    cell.addEventListener('mouseenter', showTooltip);
    cell.addEventListener('focus', showTooltip);
    cell.addEventListener('mouseleave', hideTooltip);
    cell.addEventListener('blur', hideTooltip);
  }});

  document.querySelectorAll('[data-folder]').forEach((folder) => {{
    folder.classList.remove('is-open');
  }});
  document.querySelectorAll('[data-folder-toggle]').forEach((toggleButton) => {{
    toggleButton.setAttribute('aria-expanded', 'false');
    toggleButton.addEventListener('click', () => {{
      const folder = toggleButton.closest('[data-folder]');
      if (!folder) return;
      const isOpen = folder.classList.toggle('is-open');
      toggleButton.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }});
  }});

  window.addEventListener('scroll', hideTooltip, true);
  window.addEventListener('resize', hideTooltip);

  applyTheme(initial, false);
  toggle.addEventListener('click', () => {{
    const next = body.classList.contains('dark') ? 'light' : 'dark';
    applyTheme(next, true);
  }});
}})();
</script>"#,
        switch_to_light = html_escape(copy(lang, "حالت روشن", "Light mode")),
        switch_to_dark = html_escape(copy(lang, "حالت تاریک", "Dark mode")),
    )
}

fn render_overall_timeline_cell(point: &HistoryPoint, lang: UiLanguage) -> String {
    let status_class = history_point_status_class(point);
    let total = point.up_checks + point.degraded_checks + point.down_checks;
    let availability = percent(point.up_checks, total);
    let tooltip_value = if total == 0 {
        copy(lang, "بدون داده", "No data").to_string()
    } else if matches!(lang, UiLanguage::Fa) {
        format!("{availability:.1}% سلامت")
    } else {
        format!("{availability:.1}% availability")
    };
    let tooltip_detail = if matches!(lang, UiLanguage::Fa) {
        format!(
            "{} سالم • {} اختلال • {} قطع",
            point.up_checks, point.degraded_checks, point.down_checks
        )
    } else {
        format!(
            "{} up • {} degraded • {} down",
            point.up_checks, point.degraded_checks, point.down_checks
        )
    };

    render_timeline_cell(
        status_class,
        point.observed_at_unix,
        &tooltip_value,
        None,
        &tooltip_detail,
        false,
    )
}

fn render_monitor_timeline_cell(
    check: &PublicCheckView,
    point: &PublicCheckHistoryPoint,
    lang: UiLanguage,
) -> String {
    let tooltip_value = if check.is_pending {
        copy(lang, "در انتظار", "Pending").to_string()
    } else {
        public_status_label(point.status, lang).to_string()
    };
    let tooltip_detail = if matches!(lang, UiLanguage::Fa) {
        if point.message.trim().is_empty() {
            format!("{} • {}", check.label, display_kind_label(&check.kind))
        } else {
            format!(
                "{} • {} • {}",
                check.label,
                display_kind_label(&check.kind),
                public_message(&point.message, lang)
            )
        }
    } else {
        if point.message.trim().is_empty() {
            format!("{} • {}", check.label, display_kind_label(&check.kind))
        } else {
            format!(
                "{} • {} • {}",
                check.label,
                display_kind_label(&check.kind),
                public_message(&point.message, lang)
            )
        }
    };
    let tooltip_latency = point.latency_ms.map(|value| {
        if matches!(lang, UiLanguage::Fa) {
            format!("{value} ms تاخیر")
        } else {
            format!("{value} ms latency")
        }
    });

    render_timeline_cell(
        point.status.as_str_name(),
        point.observed_at_unix,
        &tooltip_value,
        tooltip_latency.as_deref(),
        &tooltip_detail,
        true,
    )
}

fn render_timeline_cell(
    status_class: &str,
    observed_at_unix: u64,
    tooltip_value: &str,
    tooltip_meta: Option<&str>,
    tooltip_detail: &str,
    mini: bool,
) -> String {
    let mini_class = if mini { " timeline-cell--mini" } else { "" };
    let aria_label = if tooltip_detail.is_empty() {
        tooltip_value.to_string()
    } else {
        format!("{tooltip_value} - {tooltip_detail}")
    };
    format!(
        r#"<span class="timeline-cell timeline-cell--{status_class}{mini_class}" tabindex="0" aria-label="{aria_label}" data-tip-ts="{observed_at_unix}" data-tip-status="{status_class}" data-tip-value="{tooltip_value}" data-tip-meta="{tooltip_meta}" data-tip-detail="{tooltip_detail}"></span>"#,
        status_class = html_escape(status_class),
        mini_class = mini_class,
        aria_label = html_escape(&aria_label),
        observed_at_unix = observed_at_unix,
        tooltip_value = html_escape(tooltip_value),
        tooltip_meta = html_escape(tooltip_meta.unwrap_or("")),
        tooltip_detail = html_escape(tooltip_detail),
    )
}

fn history_point_status_class(point: &HistoryPoint) -> &'static str {
    let total = point.up_checks + point.degraded_checks + point.down_checks;
    if total == 0 {
        "neutral"
    } else {
        availability_band_class(percent(point.up_checks, total))
    }
}

fn render_public_summary_tiles(summary: &SnapshotSummary, lang: UiLanguage) -> String {
    [
        (copy(lang, "مانیتورها", "Monitors"), summary.total_checks.to_string()),
        (copy(lang, "سالم", "Up"), summary.up_checks.to_string()),
        (copy(lang, "اختلال", "Degraded"), summary.degraded_checks.to_string()),
        (copy(lang, "قطع", "Down"), summary.down_checks.to_string()),
    ]
    .into_iter()
    .map(|(label, value)| {
        format!(
            r#"<article class="public-summary-tile">
  <span>{label}</span>
  <strong>{value}</strong>
</article>"#,
            label = html_escape(label),
            value = html_escape(&value),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn public_overall_copy(summary: &SnapshotSummary, lang: UiLanguage) -> (&'static str, &'static str, &'static str) {
    if summary.total_checks == 0 {
        return (
            "neutral",
            copy(lang, "بدون داده", "No data"),
            copy(lang, "هنوز مانیتور عمومی‌ای ثبت نشده است.", "No public monitors are available yet."),
        );
    }

    let overall_class = availability_band_class(percent(summary.up_checks, summary.total_checks));

    match public_surface_status_from_counts(
        summary.total_checks,
        summary.up_checks,
        summary.degraded_checks,
        summary.down_checks,
    ) {
        "down" => (
            overall_class,
            copy(lang, "قطع گسترده", "Major outage"),
            copy(
                lang,
                "بخش زیادی از سرویس‌ها در دسترس نیستند.",
                "A large share of public services are currently unreachable.",
            ),
        ),
        "degraded" => (
            overall_class,
            copy(lang, "اختلال", "Issues"),
            copy(
                lang,
                "بخشی از سرویس‌ها با اختلال روبه‌رو هستند.",
                "Some public services are experiencing issues.",
            ),
        ),
        _ => (
            overall_class,
            copy(lang, "سالم", "Operational"),
            copy(lang, "همه سرویس‌های عمومی پایدار هستند.", "All public services are operational."),
        ),
    }
}

fn availability_band_class(availability: f64) -> &'static str {
    if availability >= 90.0 {
        "availability-green"
    } else if availability >= 75.0 {
        "availability-lime"
    } else if availability >= 60.0 {
        "availability-yellow"
    } else if availability >= 40.0 {
        "availability-orange"
    } else if availability >= 20.0 {
        "availability-red"
    } else if availability > 0.0 {
        "availability-brown"
    } else {
        "availability-black"
    }
}

fn resolve_public_asset_href(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("data:")
    {
        trimmed.to_string()
    } else {
        format!("/assets/group-logo?src={}", url_encode(trimmed))
    }
}

fn public_updated_copy(observed_at_unix: u64, lang: UiLanguage) -> String {
    if observed_at_unix == 0 {
        return copy(lang, "هنوز به‌روزرسانی‌ای ثبت نشده است.", "No updates have been recorded yet.")
            .to_string();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = now.saturating_sub(observed_at_unix);

    if matches!(lang, UiLanguage::Fa) {
        if elapsed < 60 {
            "آخرین به‌روزرسانی کمتر از یک دقیقه پیش".to_string()
        } else if elapsed < 3600 {
            format!("آخرین به‌روزرسانی {} دقیقه پیش", elapsed / 60)
        } else if elapsed < 86_400 {
            format!("آخرین به‌روزرسانی {} ساعت پیش", elapsed / 3600)
        } else {
            format!("آخرین به‌روزرسانی {} روز پیش", elapsed / 86_400)
        }
    } else if elapsed < 60 {
        "Updated less than a minute ago".to_string()
    } else if elapsed < 3600 {
        format!("Updated {} minutes ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("Updated {} hours ago", elapsed / 3600)
    } else {
        format!("Updated {} days ago", elapsed / 86_400)
    }
}

fn public_monitor_uptime_copy(check: &PublicCheckView, lang: UiLanguage) -> String {
    if check.is_pending {
        return copy(
            lang,
            "در انتظار اولین نتیجه",
            "Waiting for first result",
        )
        .to_string();
    }
    let total = check.history.len();
    if total == 0 {
        return copy(lang, "بدون تاریخچه", "No history").to_string();
    }
    let up = check
        .history
        .iter()
        .filter(|point| matches!(point.status, crate::types::CheckStatus::Up))
        .count();
    let uptime = percent(up, total);
    if matches!(lang, UiLanguage::Fa) {
        format!("{uptime:.1}% آپ‌تایم")
    } else {
        format!("{uptime:.1}% uptime")
    }
}

fn render_public_status_chip(check: &PublicCheckView, lang: UiLanguage) -> String {
    let (class_name, label) = if check.is_pending {
        ("degraded", copy(lang, "در انتظار", "Pending"))
    } else {
        (
            check.status.as_str_name(),
            public_status_label(check.status, lang),
        )
    };

    format!(
        r#"<span class="status-chip {class_name}">{label}</span>"#,
        class_name = html_escape(class_name),
        label = html_escape(label),
    )
}

fn public_status_label(status: crate::types::CheckStatus, lang: UiLanguage) -> &'static str {
    match (lang, status) {
        (UiLanguage::Fa, crate::types::CheckStatus::Up) => "سالم",
        (UiLanguage::Fa, crate::types::CheckStatus::Degraded) => "اختلال",
        (UiLanguage::Fa, crate::types::CheckStatus::Down) => "قطع",
        (_, crate::types::CheckStatus::Up) => "Operational",
        (_, crate::types::CheckStatus::Degraded) => "Issues",
        (_, crate::types::CheckStatus::Down) => "Down",
    }
}

pub fn render_plain_error(branding: &PublicBranding, lang: UiLanguage, message: &str) -> String {
    let body = format!(
        r#"<section class="card narrow fade-up">{header}<p>{message}</p></section>"#,
        header = render_section_header(
            copy(lang, "خطا", "Error"),
            t(lang, "error"),
            copy(
                lang,
                "در این مرحله پاسخ مورد انتظار تولید نشد.",
                "The requested response could not be produced at this step.",
            ),
            String::new(),
        ),
        message = html_escape(message)
    );
    render_layout(branding, lang, t(lang, "error"), body, false)
}

pub fn render_access_restart_pending(
    branding: &PublicBranding,
    lang: UiLanguage,
    next_admin_url: &str,
    restart_error: Option<&str>,
) -> String {
    let message = if let Some(error) = restart_error {
        format!(
            r#"<div class="alert alert--warn">{}</div>
<p>{}</p>"#,
            html_escape(error),
            html_escape(copy(
                lang,
                "تنظیمات ذخیره شد، اما برای اعمال پورت جدید باید iranmonitor-node.service را دستی ری‌استارت کنید. بعد از آن از لینک زیر وارد شوید.",
                "The settings were saved, but the service must be restarted manually to apply the new port. After that, open the panel from the link below.",
            )),
        )
    } else {
        format!(
            r#"<div class="alert alert--success">{}</div>
<p>{}</p>"#,
            html_escape(copy(
                lang,
                "تنظیمات دسترسی ذخیره شد.",
                "Access settings saved.",
            )),
            html_escape(copy(
                lang,
                "سرویس در حال ری‌استارت روی پورت جدید است. چند ثانیه دیگر پنل را از آدرس جدید باز می‌کنیم.",
                "The service is restarting on the new port. The panel will open on the new address in a few seconds.",
            )),
        )
    };
    let script = if restart_error.is_none() {
        format!(
            r#"<script>setTimeout(function() {{ window.location.href = {}; }}, 2200);</script>"#,
            serde_json::to_string(next_admin_url).unwrap_or_else(|_| "\"/admin\"".to_string())
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<section class="card narrow fade-up">
  {header}
  {message}
  <div class="inline-form inline-form--stretch">
    <a class="ghost" href="{next_admin_url}">{open_panel}</a>
  </div>
</section>{script}"#,
        header = render_section_header(
            copy(lang, "دسترسی", "Access"),
            copy(lang, "اعمال تنظیمات پنل", "Applying Panel Settings"),
            copy(
                lang,
                "اگر پورت پنل تغییر کرده باشد، آدرس مدیریت نیز به‌روزرسانی می‌شود.",
                "If the panel port changed, the admin URL changes with it.",
            ),
            String::new(),
        ),
        message = message,
        next_admin_url = html_escape(next_admin_url),
        open_panel = copy(lang, "باز کردن پنل", "Open Panel"),
        script = script,
    );
    render_layout(branding, lang, copy(lang, "اعمال تنظیمات", "Applying Settings"), body, false)
}

pub fn render_admin_system_metrics_fragment(sample: Option<&SystemSample>, lang: UiLanguage) -> String {
    match sample {
        Some(sample) => render_system_metrics_cards(sample, lang),
        None => format!(r#"<div class="empty-state">{}</div>"#, t(lang, "no_metrics")),
    }
}

fn render_tunnel_outer_local_options(entries: &[HostIpInventoryEntry], lang: UiLanguage) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                r#"<option value="{value}" data-interface="{interface}">{label}</option>"#,
                value = html_escape(&entry.address),
                interface = html_escape(&entry.interface),
                label = html_escape(&format_host_ip_entry_label(entry, lang)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_tunnel_source_interface_options(entries: &[HostIpInventoryEntry], lang: UiLanguage) -> String {
    let mut by_interface = BTreeMap::<String, HostIpInventoryEntry>::new();
    for entry in entries {
        by_interface
            .entry(entry.interface.clone())
            .and_modify(|current| {
                if (!current.is_public && entry.is_public)
                    || (current.family.eq_ignore_ascii_case("inet6")
                        && entry.family.eq_ignore_ascii_case("inet"))
                {
                    *current = entry.clone();
                }
            })
            .or_insert_with(|| entry.clone());
    }

    by_interface
        .into_values()
        .map(|entry| {
            format!(
                r#"<option value="{value}">{label}</option>"#,
                value = html_escape(&entry.interface),
                label = html_escape(&format!(
                    "{} - {}",
                    entry.interface,
                    format_host_ip_entry_suffix(&entry, lang)
                )),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_forward_interface_options(entries: &[HostIpInventoryEntry], lang: UiLanguage) -> String {
    render_tunnel_source_interface_options(entries, lang)
}

fn monitor_interval_secs_from_json(check_json: &str) -> u64 {
    serde_json::from_str::<crate::config::CheckDefinition>(check_json)
        .map(|definition| definition.interval_secs().max(10))
        .unwrap_or(60)
}

fn format_host_ip_entry_label(entry: &HostIpInventoryEntry, lang: UiLanguage) -> String {
    format!(
        "{} - {} - {}",
        entry.address,
        entry.interface,
        format_host_ip_entry_suffix(entry, lang)
    )
}

fn format_host_ip_entry_suffix(entry: &HostIpInventoryEntry, lang: UiLanguage) -> String {
    let family = if entry.family.eq_ignore_ascii_case("inet6") {
        "IPv6"
    } else {
        "IPv4"
    };
    let visibility = if entry.is_public {
        copy(lang, "عمومی", "public")
    } else {
        copy(lang, "خصوصی", "private")
    };
    format!("{family} / {visibility}")
}

fn normalize_group_logo_shape(shape: &str) -> &'static str {
    match shape.trim().to_ascii_lowercase().as_str() {
        "circle" => "circle",
        "rect" | "rectangle" | "rectangular" => "rect",
        _ => "rounded",
    }
}

fn render_folder_logo_shape_options(selected_shape: &str, lang: UiLanguage) -> String {
    [
        ("rounded", copy(lang, "گرد", "Rounded")),
        ("circle", copy(lang, "دایره‌ای", "Circle")),
        ("rect", copy(lang, "مستطیلی", "Rectangle")),
    ]
    .into_iter()
    .map(|(value, label)| {
        format!(
            r#"<option value="{value}" {selected}>{label}</option>"#,
            value = html_escape(value),
            selected = if value == normalize_group_logo_shape(selected_shape) {
                "selected"
            } else {
                ""
            },
            label = html_escape(label),
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn render_folder_assignment_options(
    folders: &[MonitorFolder],
    current: &str,
    lang: UiLanguage,
) -> String {
    let mut options = vec![format!(
        r#"<option value="" {selected}>{label}</option>"#,
        selected = if current.trim().is_empty() { "selected" } else { "" },
        label = html_escape(copy(lang, "بدون پوشه", "No folder")),
    )];
    options.extend(folders.iter().map(|folder| {
        let is_selected = folder.name.trim() == current.trim();
        format!(
            r#"<option value="{value}" {selected}>{label}</option>"#,
            value = html_escape(&folder.name),
            selected = if is_selected { "selected" } else { "" },
            label = html_escape(&folder.name),
        )
    }));
    options.join("")
}

fn render_theme_preset_selector(settings: &AppSettings, lang: UiLanguage) -> String {
    let current = detect_theme_preset(settings);
    let options = [
        (
            "green_night",
            copy(lang, "سبز پیش‌فرض", "Green Night"),
            "#22c55e",
            "#16a34a",
            "#06110a",
        ),
        (
            "ocean_night",
            copy(lang, "آبی اقیانوسی", "Ocean Night"),
            "#38bdf8",
            "#0ea5e9",
            "#07111b",
        ),
        (
            "amber_night",
            copy(lang, "کهربایی", "Amber Night"),
            "#f59e0b",
            "#d97706",
            "#140d04",
        ),
        (
            "graphite_night",
            copy(lang, "گرافیتی", "Graphite Night"),
            "#a3e635",
            "#65a30d",
            "#0c0f0b",
        ),
        (
            "ruby_night",
            copy(lang, "یاقوتی", "Ruby Night"),
            "#fb7185",
            "#e11d48",
            "#13070a",
        ),
        (
            "purple_night",
            copy(lang, "بنفش", "Purple Night"),
            "#a855f7",
            "#7e22ce",
            "#12061a",
        ),
        (
            "teal_night",
            copy(lang, "فیروزه‌ای", "Teal Night"),
            "#2dd4bf",
            "#0f766e",
            "#05110f",
        ),
        (
            "slate_night",
            copy(lang, "اسلیت", "Slate Night"),
            "#94a3b8",
            "#475569",
            "#0b1120",
        ),
    ];

    let select_options = options
        .iter()
        .map(|(key, label, primary, secondary, background)| {
            format!(
                r#"<option value="{key}" data-primary="{primary}" data-secondary="{secondary}" data-background="{background}" {selected}>{label}</option>"#,
                key = key,
                primary = primary,
                secondary = secondary,
                background = background,
                selected = if *key == current { "selected" } else { "" },
                label = html_escape(label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let select_options = format!(
        "{}<option value=\"custom\" {}>{}</option>",
        select_options,
        if current == "custom" { "selected" } else { "" },
        html_escape(copy(lang, "سفارشی", "Custom"))
    );

    let palette_cards = options
        .iter()
        .map(|(key, label, primary, secondary, background)| {
            format!(
                r#"<div class="palette-card {active}">
  <div class="palette-swatches">
    <span style="background:{primary};"></span>
    <span style="background:{secondary};"></span>
    <span style="background:{background};"></span>
  </div>
  <div class="palette-meta">
    <strong>{label}</strong>
    <small>{primary} / {secondary}</small>
  </div>
</div>"#,
                active = if *key == current { "is-active" } else { "" },
                label = html_escape(label),
                primary = primary,
                secondary = secondary,
                background = background,
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"
<div class="preset-shell">
  <div>
    <label>{theme_preset}</label>
    <select name="theme_preset">
      {select_options}
    </select>
    <div class="field-hint">{hint}</div>
  </div>
  <div class="palette-grid">{palette_cards}</div>
</div>
"#,
        theme_preset = copy(lang, "پالت آماده", "Preset Palette"),
        select_options = select_options,
        hint = copy(
            lang,
            "به‌جای ورود کد هگز، یک پالت آماده انتخاب کنید تا رنگ‌های پنل ادمین و عمومی هماهنگ بمانند.",
            "Pick a preset palette instead of typing hex colors manually so the admin and public panels stay visually consistent.",
        ),
        palette_cards = palette_cards,
    )
}

fn detect_theme_preset(settings: &AppSettings) -> &'static str {
    let primary = settings.primary_color.to_ascii_lowercase();
    let secondary = settings.secondary_color.to_ascii_lowercase();
    let background = settings.background_color.to_ascii_lowercase();

    match (primary.as_str(), secondary.as_str(), background.as_str()) {
        ("#22c55e", "#16a34a", "#06110a") => "green_night",
        ("#38bdf8", "#0ea5e9", "#07111b") => "ocean_night",
        ("#f59e0b", "#d97706", "#140d04") => "amber_night",
        ("#a3e635", "#65a30d", "#0c0f0b") => "graphite_night",
        ("#fb7185", "#e11d48", "#13070a") => "ruby_night",
        ("#a855f7", "#7e22ce", "#12061a") => "purple_night",
        ("#2dd4bf", "#0f766e", "#05110f") => "teal_night",
        ("#94a3b8", "#475569", "#0b1120") => "slate_night",
        _ => "custom",
    }
}

fn render_section_header(_tag: &str, title: &str, subtitle: &str, trailing: String) -> String {
    let subtitle_html = if subtitle.trim().is_empty() {
        String::new()
    } else {
        format!(r#"<p>{}</p>"#, html_escape(subtitle))
    };
    format!(
        r#"<div class="section-header">
  <div>
    <h2>{title}</h2>
    {subtitle_html}
  </div>
  <div class="section-header__side">{trailing}</div>
</div>"#,
        title = html_escape(title),
        subtitle_html = subtitle_html,
        trailing = trailing,
    )
}

fn render_system_metrics_cards(sample: &SystemSample, lang: UiLanguage) -> String {
    let rx = bits_to_human(sample.rx_bps.saturating_mul(8));
    let tx = bits_to_human(sample.tx_bps.saturating_mul(8));
    let cards = vec![
        render_metric_card(
            "CPU",
            &format!("{:.1}%", sample.cpu_percent),
            &format!(
                "{}: {:.2} / {:.2} / {:.2}",
                copy(lang, "لود", "Load"),
                sample.load1,
                sample.load5,
                sample.load15
            ),
            sample.cpu_percent,
        ),
        render_metric_card(
            "RAM",
            &format!("{:.1}%", sample.ram_percent),
            &format!(
                "{} / {}",
                bytes_to_human(sample.used_ram_bytes),
                bytes_to_human(sample.total_ram_bytes)
            ),
            sample.ram_percent,
        ),
        render_metric_card(
            "Swap",
            &format!("{:.1}%", sample.swap_percent),
            &format!(
                "{} / {}",
                bytes_to_human(sample.used_swap_bytes),
                bytes_to_human(sample.total_swap_bytes)
            ),
            sample.swap_percent,
        ),
        render_metric_card(
            "Disk",
            &format!("{:.1}%", sample.disk_percent),
            &format!(
                "{} / {}",
                bytes_to_human(sample.used_disk_bytes),
                bytes_to_human(sample.total_disk_bytes)
            ),
            sample.disk_percent,
        ),
        render_metric_card(
            copy(lang, "دانلود", "Download"),
            &rx,
            copy(lang, "نرخ دریافت فعلی", "Current download rate"),
            0.0,
        ),
        render_metric_card(
            copy(lang, "اپلود", "Upload"),
            &tx,
            copy(lang, "نرخ ارسال فعلی", "Current upload rate"),
            0.0,
        ),
    ];

    format!(r#"<div class="metrics-live-grid">{}</div>"#, cards.join(""))
}

fn render_metric_card(label: &str, value: &str, meta: &str, progress: f64) -> String {
    let clamped = progress.clamp(0.0, 100.0);
    let bar = if clamped > 0.0 {
        format!(
            r#"<div class="metric-bar"><span style="width:{:.1}%"></span></div>"#,
            clamped
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="metric-card">
  <div class="metric-card__eyebrow">{label}</div>
  <div class="metric-card__value">{value}</div>
  <div class="metric-card__meta">{meta}</div>
  {bar}
</article>"#,
        label = html_escape(label),
        value = html_escape(value),
        meta = html_escape(meta),
        bar = bar,
    )
}

fn render_speedometer_icon() -> &'static str {
    r#"<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M4.5 15a7.5 7.5 0 1 1 15 0" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <path d="M12 12l4.5-3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  <circle cx="12" cy="12" r="1.6" fill="currentColor"/>
</svg>"#
}

fn render_branding_asset_preview(url: &str, kind: &str, lang: UiLanguage) -> String {
    let trimmed = url.trim();
    let Some(asset) = asset_href(trimmed, kind) else {
        return format!(
            r#"<div class="branding-asset-preview branding-asset-preview--empty">
  <div class="branding-asset-preview__meta">
    <strong>{title}</strong>
    <span class="small">{body}</span>
  </div>
</div>"#,
            title = copy(lang, "پیش‌نمایش دارایی", "Asset Preview"),
            body = copy(
                lang,
                "هنوز تصویری برای این بخش ثبت نشده است.",
                "No image has been saved for this field yet.",
            ),
        );
    };

    let origin = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        copy(lang, "منبع: آدرس خارجی", "Source: remote URL")
    } else {
        copy(lang, "منبع: فایل محلی مدیریت‌شده", "Source: managed local file")
    };
    let frame_class = if kind == "favicon" {
        "branding-asset-preview__frame branding-asset-preview__frame--favicon"
    } else {
        "branding-asset-preview__frame branding-asset-preview__frame--logo"
    };
    format!(
        r#"<div class="branding-asset-preview">
  <div class="{frame_class}">
    <img src="{asset}" alt="{alt}">
  </div>
  <div class="branding-asset-preview__meta">
    <strong>{title}</strong>
    <span class="small">{origin}</span>
    <code>{path}</code>
  </div>
</div>"#,
        frame_class = frame_class,
        asset = html_escape(&asset),
        alt = copy(lang, "پیش‌نمایش دارایی", "Asset preview"),
        title = copy(lang, "پیش‌نمایش دارایی", "Asset Preview"),
        origin = origin,
        path = html_escape(trimmed),
    )
}

fn render_logo(url: &str, alt: &str) -> String {
    if let Some(asset) = asset_href(url, "logo").or_else(|| Some("/assets/imonitor-mark.svg".to_string())) {
        format!(
            r#"<span class="brand-logo-frame" data-auto-aspect-frame><img src="{}" alt="{}" loading="lazy" data-auto-aspect></span>"#,
            html_escape(&asset),
            html_escape(alt)
        )
    } else {
        String::new()
    }
}

fn asset_href(value: &str, kind: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("data:")
    {
        Some(trimmed.to_string())
    } else {
        Some(format!("/assets/custom?kind={kind}"))
    }
}

fn yes_no(lang: UiLanguage, value: bool) -> &'static str {
    if value {
        t(lang, "yes")
    } else {
        t(lang, "no")
    }
}

fn copy<'a>(lang: UiLanguage, fa: &'a str, en: &'a str) -> &'a str {
    if matches!(lang, UiLanguage::Fa) {
        fa
    } else {
        en
    }
}

fn listen_port_from_bind_addr(bind_addr: &str) -> u16 {
    bind_addr
        .rsplit(':')
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(6060)
}

fn percent(value: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64) * 100.0
    }
}

fn format_unix_time(value: u64) -> String {
    if value == 0 {
        "-".to_string()
    } else {
        value.to_string()
    }
}

fn t(lang: UiLanguage, key: &str) -> &'static str {
    match (lang, key) {
        (UiLanguage::Fa, "admin_panel") => "پنل مدیریت",
        (UiLanguage::Fa, "admin_panel_subtitle") => "کنترل کامل مانیتورینگ، نمایش عمومی و ابزارهای شبکه",
        (UiLanguage::Fa, "admin_login") => "ورود مدیر",
        (UiLanguage::Fa, "username") => "نام کاربری",
        (UiLanguage::Fa, "password") => "رمز عبور",
        (UiLanguage::Fa, "sign_in") => "ورود",
        (UiLanguage::Fa, "login_hint") => "از حساب مدیریتی که هنگام راه‌اندازی ساخته شده استفاده کنید.",
        (UiLanguage::Fa, "public_status") => "نمایش عمومی",
        (UiLanguage::Fa, "logout") => "خروج",
        (UiLanguage::Fa, "server_health") => "سلامت سرور",
        (UiLanguage::Fa, "no_metrics") => "هنوز نمونه‌ای از متریک‌های سیستم ثبت نشده است.",
        (UiLanguage::Fa, "monitoring_management") => "مدیریت مانیتورها",
        (UiLanguage::Fa, "monitoring_management_note") => "برای پشتیبانی از همه پروتکل‌ها، هر مانیتور به صورت JSON ذخیره می‌شود.",
        (UiLanguage::Fa, "label") => "عنوان",
        (UiLanguage::Fa, "public_visible") => "نمایش عمومی",
        (UiLanguage::Fa, "enabled") => "فعال",
        (UiLanguage::Fa, "yes") => "بله",
        (UiLanguage::Fa, "no") => "خیر",
        (UiLanguage::Fa, "monitor_json") => "JSON مانیتور",
        (UiLanguage::Fa, "save_monitor") => "ذخیره مانیتور",
        (UiLanguage::Fa, "save") => "ذخیره",
        (UiLanguage::Fa, "kind") => "نوع",
        (UiLanguage::Fa, "actions") => "عملیات",
        (UiLanguage::Fa, "latest_checks") => "آخرین نتایج مانیتورینگ",
        (UiLanguage::Fa, "status") => "وضعیت",
        (UiLanguage::Fa, "message") => "پیام",
        (UiLanguage::Fa, "latency") => "تاخیر",
        (UiLanguage::Fa, "endpoint") => "مقصد",
        (UiLanguage::Fa, "branding") => "برندینگ و ظاهر",
        (UiLanguage::Fa, "public_title") => "عنوان عمومی",
        (UiLanguage::Fa, "public_subtitle") => "زیرعنوان عمومی",
        (UiLanguage::Fa, "primary_color") => "رنگ اصلی",
        (UiLanguage::Fa, "secondary_color") => "رنگ دوم",
        (UiLanguage::Fa, "background_color") => "رنگ پس‌زمینه",
        (UiLanguage::Fa, "default_language") => "زبان پیش‌فرض",
        (UiLanguage::Fa, "dark_mode") => "حالت نمایش",
        (UiLanguage::Fa, "light") => "روشن",
        (UiLanguage::Fa, "dark") => "تاریک",
        (UiLanguage::Fa, "logo_url") => "آدرس لوگو",
        (UiLanguage::Fa, "favicon_url") => "آدرس آیکون",
        (UiLanguage::Fa, "contact_email") => "ایمیل تماس",
        (UiLanguage::Fa, "contact_telegram") => "تلگرام",
        (UiLanguage::Fa, "contact_phone") => "تلفن",
        (UiLanguage::Fa, "bind_addr") => "آدرس شنود",
        (UiLanguage::Fa, "public_base_url") => "آدرس عمومی",
        (UiLanguage::Fa, "admin_base_url") => "آدرس مدیریت",
        (UiLanguage::Fa, "ssl_mode") => "حالت SSL",
        (UiLanguage::Fa, "server_name") => "دامنه",
        (UiLanguage::Fa, "ssl_cert_path") => "مسیر گواهی",
        (UiLanguage::Fa, "ssl_key_path") => "مسیر کلید",
        (UiLanguage::Fa, "interval_secs") => "فاصله نمونه‌برداری",
        (UiLanguage::Fa, "notes") => "یادداشت",
        (UiLanguage::Fa, "nginx_snippet") => "نمونه تنظیم Nginx برای دامنه و SSL",
        (UiLanguage::Fa, "enterprise_controls") => "کنترل شبکه",
        (UiLanguage::Fa, "enterprise_controls_note") => "این بخش برای دیدن ترافیک، محدودسازی پورت و محدودیت اتصال TCP طراحی شده است.",
        (UiLanguage::Fa, "traffic_watchers") => "ردیاب‌های ترافیک",
        (UiLanguage::Fa, "family") => "خانواده IP",
        (UiLanguage::Fa, "direction") => "جهت",
        (UiLanguage::Fa, "protocol") => "پروتکل",
        (UiLanguage::Fa, "source_ip") => "IP مبدأ",
        (UiLanguage::Fa, "port") => "پورت",
        (UiLanguage::Fa, "traffic") => "ترافیک",
        (UiLanguage::Fa, "speed") => "سرعت",
        (UiLanguage::Fa, "add_watcher") => "افزودن ردیاب",
        (UiLanguage::Fa, "speed_limits") => "محدودیت سرعت",
        (UiLanguage::Fa, "interface") => "اینترفیس",
        (UiLanguage::Fa, "rate") => "نرخ",
        (UiLanguage::Fa, "rate_unit") => "واحد نرخ",
        (UiLanguage::Fa, "add_speed_limit") => "افزودن محدودیت",
        (UiLanguage::Fa, "apply_speed_limits") => "اعمال محدودیت‌های سرعت",
        (UiLanguage::Fa, "applied") => "اعمال‌شده",
        (UiLanguage::Fa, "tcp_conn_limit") => "محدودیت اتصال TCP",
        (UiLanguage::Fa, "limit_per_ip") => "حداکثر اتصال هر IP",
        (UiLanguage::Fa, "apply_tcp_limit") => "اعمال محدودیت TCP",
        (UiLanguage::Fa, "tcp_limit_status") => "وضعیت آخرین اعمال",
        (UiLanguage::Fa, "socket_inventory") => "موجودی سوکت‌ها و اپ‌ها",
        (UiLanguage::Fa, "process") => "پردازش",
        (UiLanguage::Fa, "state") => "State",
        (UiLanguage::Fa, "local") => "لوکال",
        (UiLanguage::Fa, "remote") => "ریموت",
        (UiLanguage::Fa, "payload") => "Payload",
        (UiLanguage::Fa, "response") => "پاسخ",
        (UiLanguage::Fa, "time") => "زمان",
        (UiLanguage::Fa, "availability_chart") => "نمودار در دسترس بودن",
        (UiLanguage::Fa, "system_chart") => "نمودار مصرف سیستم",
        (UiLanguage::Fa, "public_nodes") => "وضعیت مانیتورهای عمومی",
        (UiLanguage::Fa, "contact") => "تماس با ما",
        (UiLanguage::Fa, "live_charts") => "نمودار زنده",
        (UiLanguage::Fa, "delete") => "حذف",
        (UiLanguage::Fa, "delete_confirm") => "حذف شود؟",
        (UiLanguage::Fa, "error") => "خطا",
        (_, "admin_panel") => "Admin Panel",
        (_, "admin_panel_subtitle") => "Full control over monitoring, public status, and network tools",
        (_, "admin_login") => "Administrator Login",
        (_, "username") => "Username",
        (_, "password") => "Password",
        (_, "sign_in") => "Sign In",
        (_, "login_hint") => "Use the administrator account created during setup.",
        (_, "public_status") => "Public Status",
        (_, "logout") => "Logout",
        (_, "server_health") => "Server Health",
        (_, "no_metrics") => "No system sample has been captured yet.",
        (_, "monitoring_management") => "Monitoring Management",
        (_, "monitoring_management_note") => "Check websites, service ports, DNS records, and proxy connections here.",
        (_, "label") => "Label",
        (_, "public_visible") => "Public",
        (_, "enabled") => "Enabled",
        (_, "yes") => "Yes",
        (_, "no") => "No",
        (_, "monitor_json") => "Monitor JSON",
        (_, "save_monitor") => "Save Monitor",
        (_, "save") => "Save",
        (_, "kind") => "Kind",
        (_, "actions") => "Actions",
        (_, "latest_checks") => "Latest Monitoring Results",
        (_, "status") => "Status",
        (_, "message") => "Message",
        (_, "latency") => "Latency",
        (_, "endpoint") => "Endpoint",
        (_, "branding") => "Branding & UI",
        (_, "public_title") => "Public Title",
        (_, "public_subtitle") => "Public Subtitle",
        (_, "primary_color") => "Primary Color",
        (_, "secondary_color") => "Secondary Color",
        (_, "background_color") => "Background Color",
        (_, "default_language") => "Default Language",
        (_, "dark_mode") => "Theme Mode",
        (_, "light") => "Light",
        (_, "dark") => "Dark",
        (_, "logo_url") => "Logo URL",
        (_, "favicon_url") => "Favicon URL",
        (_, "contact_email") => "Contact Email",
        (_, "contact_telegram") => "Telegram",
        (_, "contact_phone") => "Phone",
        (_, "bind_addr") => "Listen Address",
        (_, "public_base_url") => "Public Base URL",
        (_, "admin_base_url") => "Admin Base URL",
        (_, "ssl_mode") => "SSL Mode",
        (_, "server_name") => "Server Name",
        (_, "ssl_cert_path") => "SSL Certificate Path",
        (_, "ssl_key_path") => "SSL Key Path",
        (_, "interval_secs") => "Sampling Interval",
        (_, "notes") => "Notes",
        (_, "nginx_snippet") => "Suggested Nginx snippet for domain and SSL",
        (_, "enterprise_controls") => "Network controls",
        (_, "enterprise_controls_note") => "This section is built for traffic visibility, port speed limits, and TCP connection protection.",
        (_, "traffic_watchers") => "Traffic Watchers",
        (_, "family") => "Family",
        (_, "direction") => "Direction",
        (_, "protocol") => "Protocol",
        (_, "source_ip") => "Source IP",
        (_, "port") => "Port",
        (_, "traffic") => "Traffic",
        (_, "speed") => "Speed",
        (_, "add_watcher") => "Add Watcher",
        (_, "speed_limits") => "Speed Limits",
        (_, "interface") => "Interface",
        (_, "rate") => "Rate",
        (_, "rate_unit") => "Rate Unit",
        (_, "add_speed_limit") => "Add Limit",
        (_, "apply_speed_limits") => "Apply Speed Limits",
        (_, "applied") => "Applied",
        (_, "tcp_conn_limit") => "TCP Connection Limit",
        (_, "limit_per_ip") => "Per-IP Connection Limit",
        (_, "apply_tcp_limit") => "Apply TCP Limit",
        (_, "tcp_limit_status") => "Last Apply Status",
        (_, "socket_inventory") => "Socket / App Inventory",
        (_, "process") => "Process",
        (_, "state") => "State",
        (_, "local") => "Local",
        (_, "remote") => "Remote",
        (_, "payload") => "Payload",
        (_, "response") => "Response",
        (_, "time") => "Time",
        (_, "availability_chart") => "Availability Chart",
        (_, "system_chart") => "System Utilization Chart",
        (_, "public_nodes") => "Public Monitor Nodes",
        (_, "contact") => "Contact Us",
        (_, "live_charts") => "Live Charts",
        (_, "delete") => "Delete",
        (_, "delete_confirm") => "Delete this item?",
        (_, "error") => "Error",
        _ => "",
    }
}

trait StatusExt {
    fn as_str_name(&self) -> &'static str;
}

impl StatusExt for crate::types::CheckStatus {
    fn as_str_name(&self) -> &'static str {
        match self {
            crate::types::CheckStatus::Up => "up",
            crate::types::CheckStatus::Down => "down",
            crate::types::CheckStatus::Degraded => "degraded",
        }
    }
}


fn render_template(template: &str, values: &[(&str, String)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find("@@") {
        rendered.push_str(&remaining[..start]);
        let token = &remaining[start + 2..];
        let Some(end) = token.find("@@") else {
            rendered.push_str(&remaining[start..]);
            return rendered;
        };
        let key = &token[..end];
        if let Some((_, value)) = values.iter().find(|(name, _)| *name == key) {
            rendered.push_str(value);
        } else {
            rendered.push_str(&remaining[start..start + end + 4]);
        }
        remaining = &token[end + 2..];
    }
    rendered.push_str(remaining);
    rendered
}

include!("ui/tunnel.rs");
include!("ui/guide.rs");
include!("ui/tests.rs");

fn public_message(message: &str, lang: UiLanguage) -> &str {
    match message {
        "Service is responding normally." => copy(lang,"سرویس به‌طور معمول پاسخ می‌دهد.","Service is responding normally."),
        "Service has reduced availability or performance." => copy(lang,"دسترسی یا عملکرد سرویس کاهش یافته است.","Service has reduced availability or performance."),
        "Service is unavailable." => copy(lang,"سرویس در دسترس نیست.","Service is unavailable."),
        _ => message,
    }
}

include!("ui/monitoring.rs");

include!("ui/navigation.rs");

include!("ui/scripts.rs");

include!("ui/layout.rs");
