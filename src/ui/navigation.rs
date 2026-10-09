fn render_admin_sidebar_nav(current: AdminSection, lang: UiLanguage) -> String {
    let groups = [
        (copy(lang,"فضای شما","WORKSPACE"), vec![AdminSection::Overview, AdminSection::Monitors, AdminSection::Tunnels, AdminSection::Guide]),
        (copy(lang,"پایش و مدیریت","MONITOR & MANAGE"), vec![AdminSection::Folders, AdminSection::Notifications, AdminSection::ServerHealth, AdminSection::Backups]),
        (copy(lang,"ابزارهای شبکه","NETWORK TOOLS"), vec![AdminSection::NetworkControls, AdminSection::SourceIp, AdminSection::Forwarding, AdminSection::Sockets]),
        (copy(lang,"تنظیمات","PREFERENCES"), vec![AdminSection::Settings]),
    ];
    groups.into_iter().map(|(label, sections)| {
        let links=sections.into_iter().map(|section| format!(r#"<a href="{href}" data-nav="{key}" class="admin-sidebar__link {active}"{aria}><span class="admin-nav-icon" aria-hidden="true">{icon}</span><span>{label}</span></a>"#,
            href=html_escape(&admin_section_href(section,lang)),key=admin_section_key(section),active=if section==current { "is-active" } else { "" },aria=if section==current { " aria-current=\"page\"" } else { "" },icon=admin_nav_icon(section),label=html_escape(admin_section_label(section,lang))
        )).collect::<Vec<_>>().join("");
        format!(r#"<div class="admin-nav-group">{label}</div>{links}"#)
    }).collect::<Vec<_>>().join("")
}

fn admin_section_key(section: AdminSection) -> &'static str {
    match section { AdminSection::Overview => "overview", _ => section.path().trim_start_matches("/admin/") }
}

fn admin_nav_icon(section: AdminSection) -> String {
    let path = match section {
        AdminSection::Overview => "M3 10 12 3l9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1Z",
        AdminSection::Monitors => "M3 12h4l3-7 4 14 3-7h4",
        AdminSection::Tunnels => "M4 7h5v10H4ZM15 7h5v10h-5ZM9 12h6M11 10l2 2-2 2",
        AdminSection::Guide => "M4 4h6l2 2 2-2h6v15h-6l-2 2-2-2H4ZM12 6v15",
        AdminSection::Folders => "M3 7V5h6l2 3h10v12H3Z",
        AdminSection::Notifications => "M5 17h14l-2-3V9a5 5 0 0 0-10 0v5ZM10 20h4",
        AdminSection::ServerHealth => "M4 3h16v7H4ZM4 14h16v7H4ZM7 6h.01M7 17h.01M15 6h2M15 17h2",
        AdminSection::Backups => "M5 5h14v15H5ZM3 2h18v3H3ZM9 10h6M12 10v6M9 14l3 3 3-3",
        AdminSection::NetworkControls => "M4 6h16M4 12h16M4 18h16M8 4v4M16 10v4M10 16v4",
        AdminSection::SourceIp => "M12 21s7-6 7-12a7 7 0 1 0-14 0c0 6 7 12 7 12ZM9 9a3 3 0 1 0 6 0 3 3 0 0 0-6 0",
        AdminSection::Forwarding => "M4 7h14M14 3l4 4-4 4M20 17H6M10 13l-4 4 4 4",
        AdminSection::Sockets => "M9 3v5M15 3v5M6 8h12v4a6 6 0 0 1-12 0ZM12 18v4",
        AdminSection::Settings => "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2",
        AdminSection::Reports => "M5 3h14v18H5ZM9 8h6M9 12h6M9 16h4",
    };
    format!(r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="{path}"/></svg>"#)
}

fn admin_section_href(section: AdminSection, lang: UiLanguage) -> String {
    format!("{}?lang={}", section.path(), lang.as_str())
}

fn admin_section_label(section: AdminSection, lang: UiLanguage) -> &'static str {
    match (section, lang) {
        (AdminSection::Overview, UiLanguage::Fa) => "نمای کلی",
        (AdminSection::Overview, _) => "Overview",
        (AdminSection::ServerHealth, UiLanguage::Fa) => "سلامت سرور",
        (AdminSection::ServerHealth, _) => "Server Health",
        (AdminSection::Monitors, UiLanguage::Fa) => "مانیتورینگ",
        (AdminSection::Tunnels, UiLanguage::Fa) => "تونل‌ها",
        (AdminSection::Tunnels, _) => "Tunnels",
        (AdminSection::Guide, UiLanguage::Fa) => "راهنما و آموزش",
        (AdminSection::Guide, _) => "Getting started",
        (AdminSection::Monitors, _) => "Monitoring",
        (AdminSection::Folders, UiLanguage::Fa) => "پوشه مانیتور ها",
        (AdminSection::Folders, _) => "Monitor Folders",
        (AdminSection::Notifications, UiLanguage::Fa) => "اطلاع رسانی",
        (AdminSection::Notifications, _) => "Notifications",
        (AdminSection::Backups, UiLanguage::Fa) => "بکاپ",
        (AdminSection::Backups, _) => "Backup",
        (AdminSection::Settings, UiLanguage::Fa) => "تنظیمات پنل",
        (AdminSection::Settings, _) => "Panel Settings",
        (AdminSection::NetworkControls, UiLanguage::Fa) => "کنترل شبکه",
        (AdminSection::NetworkControls, _) => "Network Controls",
        (AdminSection::SourceIp, UiLanguage::Fa) => "ایپی مبدا",
        (AdminSection::SourceIp, _) => "Source IP",
        (AdminSection::Forwarding, UiLanguage::Fa) => "پورت فورواردینگ",
        (AdminSection::Forwarding, _) => "Port Forwarding",
        (AdminSection::Sockets, UiLanguage::Fa) => "پورت/سوکت ها",
        (AdminSection::Sockets, _) => "Ports / Sockets",
        (AdminSection::Reports, UiLanguage::Fa) => "گزارش‌ها",
        (AdminSection::Reports, _) => "Reports",
    }
}

