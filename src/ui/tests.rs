#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_types::TcpConnLimitPolicy;
    use crate::types::{CheckResult, CheckStatus};

    fn fixture() -> AdminDashboardData {
        let settings = AppSettings::default();
        let summary = SnapshotSummary { observed_at_unix: 1791500000, total_checks: 2, up_checks: 1, degraded_checks: 1, down_checks: 0 };
        let branding = PublicBranding {
            title: "IranMonitor".into(), subtitle: "Live service availability".into(), logo_url: String::new(), favicon_url: String::new(),
            primary_color: settings.primary_color.clone(), secondary_color: settings.secondary_color.clone(), background_color: settings.background_color.clone(),
            dark_mode_default: true, contact_email: String::new(), contact_telegram: String::new(), contact_phone: String::new(),
        };
        let checks = [
            ("website-example", "Example website", "https", serde_json::json!({"kind":"https", "id":"website-example", "host":"example.com", "interval_secs":60, "timeout_ms":3000})),
            ("tunnel-example", "Tehran ↔ Frankfurt", "tunnel", serde_json::json!({"kind":"tunnel", "id":"tunnel-example", "protocol":"gre", "interface":"gre100", "outer_remote":"198.51.100.20", "local_outer":"203.0.113.10", "inner_local_cidr":"10.20.0.1/30", "inner_probe":"10.20.0.2", "auto_create_interface":true, "require_bidirectional_traffic":false, "interval_secs":60, "timeout_ms":3000})),
        ].into_iter().enumerate().map(|(index,(id,label,kind,json))| MonitorCheckRow {
            db_id:index as i64+1,check_id:id.into(),label:label.into(),kind:kind.into(),enabled:true,public_visible:true,display_group:String::new(),group_logo_url:String::new(),group_logo_shape:"rounded".into(),check_json:json.to_string(),created_at_unix:1791500000,updated_at_unix:1791500000
        }).collect::<Vec<_>>();
        let latest_results = checks.iter().enumerate().map(|(index,row)| CheckResult {
            id:row.check_id.clone(),kind:row.kind.clone(),status:if index==0 {CheckStatus::Up} else {CheckStatus::Degraded},message:if index==0 {"HTTPS responded with status 200".into()} else {"Peer did not reply. Check the other end and firewall.".into()},observed_at_unix:1791500000,duration_ms:80,latency_ms:Some(24),ip_version:Some("ipv4".into()),endpoint:Some(if index==0 {"example.com:443".into()} else {"10.20.0.2".into()}),details:BTreeMap::new()
        }).collect::<Vec<_>>();
        let public_results = latest_results.iter().zip(checks.iter()).map(|(result,row)| PublicCheckView {
            id:result.id.clone(),label:row.label.clone(),kind:row.kind.clone(),status:result.status,message:if matches!(result.status,CheckStatus::Up) {"Service is responding normally.".into()} else {"Service has reduced availability or performance.".into()},latency_ms:result.latency_ms,endpoint:None,observed_at_unix:result.observed_at_unix,group_name:String::new(),group_logo_url:String::new(),group_logo_shape:"rounded".into(),history:vec![PublicCheckHistoryPoint {observed_at_unix:1791500000,status:result.status,latency_ms:result.latency_ms,message:String::new()}],is_pending:false
        }).collect();
        let sample = SystemSample {observed_at_unix:1791500000,cpu_percent:12.4,ram_percent:37.2,swap_percent:0.0,disk_percent:22.0,rx_bps:4500000,tx_bps:2200000,load1:0.2,load5:0.15,load15:0.1,total_ram_bytes:8*1024*1024*1024,used_ram_bytes:3*1024*1024*1024,total_swap_bytes:0,used_swap_bytes:0,total_disk_bytes:100*1024*1024*1024,used_disk_bytes:22*1024*1024*1024};
        AdminDashboardData {
            settings, admin_username:"admin".into(),current_release_version:"2.1.0".into(),latest_release_version:"1.2.2".into(),checks,monitor_folders:vec![],latest_results,latest_summary:summary.clone(),latest_system:Some(sample.clone()),
            public_payload:PublicStatusPayload {settings:branding,summary,latest_results:public_results,history:vec![HistoryPoint {observed_at_unix:1791500000,up_checks:1,degraded_checks:1,down_checks:0}],system_history:vec![sample]},
            traffic_watchers:vec![],speed_limits:vec![],tcp_conn_limit:TcpConnLimitPolicy::default(),backup_targets:vec![],backup_jobs:vec![],backup_job_links:vec![],backup_records:vec![],source_ip_rules:vec![crate::app_types::SourceIpRule{id:1,label:"IPv6 outbound service".into(),mode:"snat".into(),family:"ipv6".into(),protocol:"udp".into(),match_port:27015,interface_name:"eth0".into(),destination_ip:"2001:db8:2::/64".into(),source_ip:"2001:db8:1::10".into(),translate_ip:String::new(),enabled:true,last_status:"Pending apply".into(),created_at_unix:1791500000,updated_at_unix:1791500000}],port_forward_rules:vec![],recent_reports:vec![],socket_inventory:vec![],host_ip_inventory:vec![HostIpInventoryEntry{interface:"eth0".into(),address:"203.0.113.10".into(),family:"ipv4".into(),is_public:true}],server_health:None,warnings:vec![]
        }
    }

    #[test]
    fn monitoring_and_tunnels_show_distinct_saved_checks_and_forms() {
        let data=fixture();
        let monitor=render_admin_dashboard(&data,UiLanguage::En,None,"",AdminSection::Monitors);
        let tunnel=render_admin_dashboard(&data,UiLanguage::En,None,"",AdminSection::Tunnels);
        assert!(monitor.contains("data-edit-label=\"Example website\""));
        assert!(!monitor.contains("data-edit-label=\"Tehran"));
        assert!(!monitor.contains("name=\"tunnel_protocol\""));
        assert!(tunnel.contains("data-edit-label=\"Tehran"));
        assert!(!tunnel.contains("data-edit-label=\"Example website\""));
        assert!(tunnel.contains("data-tunnel-wizard"));
        assert!(tunnel.contains("name=\"speedtest_token\""));
        assert!(tunnel.contains("name=\"esp_key_derivation\""));
        assert!(tunnel.contains("name=\"esp_cipher\""));
    }

    #[test]
    fn all_monitor_and_tunnel_types_are_available_without_commercial_prompts() {
        let monitors=render_monitor_kind_options(UiLanguage::En);
        let tunnels=render_tunnel_protocol_options(UiLanguage::En);
        assert!(monitors.contains("value=\"tcp\""));
        assert!(tunnels.contains("value=\"wireguard\""));
        assert!(tunnels.contains("value=\"vxlan\""));
        assert!(tunnels.contains("value=\"geneve\""));
        assert!(tunnels.contains("value=\"gretap\""));
        assert!(!monitors.contains("disabled"));
        assert!(!tunnels.contains("disabled"));
        for section in [AdminSection::Overview,AdminSection::Settings,AdminSection::NetworkControls] {
            let html=render_admin_dashboard(&fixture(),UiLanguage::En,None,"",section);
            assert!(!html.contains("License Key"));
            assert!(!html.contains("/admin/license/"));
            assert!(!html.contains("Enterprise plan"));
        }
    }

    #[test]
    fn user_text_is_escaped_and_template_values_are_never_reprocessed() {
        let mut data=fixture();
        data.checks[0].label="<script>alert(1)</script>".into();
        let html=render_admin_dashboard(&data,UiLanguage::En,None,"",AdminSection::Monitors);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert_eq!(render_template("@@name@@ @@path@@",&[("name","@@path@@".into()),("path","/admin/".into())]),"@@path@@ /admin/");
    }

    #[test]
    fn every_section_renders_in_both_languages_without_unresolved_asset_tokens() {
        let data=fixture();
        for lang in [UiLanguage::Fa,UiLanguage::En] {
            for section in [AdminSection::Overview,AdminSection::Monitors,AdminSection::Tunnels,AdminSection::Guide,AdminSection::Folders,AdminSection::Notifications,AdminSection::Backups,AdminSection::Settings,AdminSection::NetworkControls,AdminSection::SourceIp,AdminSection::Forwarding,AdminSection::Sockets,AdminSection::ServerHealth] {
                let html=render_admin_dashboard(&data,lang,None,"",section);
                assert!(!html.contains("@@"),"Unresolved asset token in {:?}/{:?}",lang,section);
                assert!(!html.contains("پلن سازمانی"));
                assert!(html.contains("width=device-width"));
                assert!(html.contains("font-family: \"IBM Plex Sans\""));
                assert!(html.contains("/assets/fonts/vazirmatn.ttf"));
                assert!(!html.contains("https://fonts.googleapis.com"));
            }
            let public=render_public_page(&data.public_payload,lang);
            assert!(!public.contains("@@"));
            assert!(public.contains("data-ad-placement=\"public\""));
        }
    }

    #[test]
    fn native_diagnostics_explain_peer_listener_instead_of_external_dependency() {
        let html=render_admin_tunnel_diagnostics_modal(UiLanguage::En);
        assert!(html.contains("Native iMonitor test"));
        assert!(html.contains("no external speed-test package is needed"));
        assert!(!html.contains("iperf3"));
    }

    #[test]
    #[ignore = "Writes realistic HTML fixtures for optional browser review"]
    fn export_ui_preview_fixtures() {
        let output=std::env::var_os("IMONITOR_UI_PREVIEW_DIR").map(std::path::PathBuf::from).unwrap_or_else(||std::path::PathBuf::from("../ui-previews"));
        std::fs::create_dir_all(&output).unwrap();
        let data=fixture();
        for lang in [UiLanguage::Fa,UiLanguage::En] {
            for section in [AdminSection::Overview,AdminSection::Monitors,AdminSection::Tunnels,AdminSection::Guide,AdminSection::Settings,AdminSection::NetworkControls,AdminSection::SourceIp] {
                let html=render_admin_dashboard(&data,lang,None,"",section);
                std::fs::write(output.join(format!("{}-{}.html",admin_section_key(section),lang.as_str())),html).unwrap();
            }
            std::fs::write(output.join(format!("public-{}.html",lang.as_str())),render_public_page(&data.public_payload,lang)).unwrap();
        }
    }
}
