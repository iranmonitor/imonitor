fn render_tunnel_builder(data: &AdminDashboardData, lang: UiLanguage) -> String {
    let mut advanced = render_tunnel_advanced_fields(lang);
    // The connection step owns the local address. Keep exactly one submitted field.
    if let Some(start) = advanced.find("    <div>\n      <label>") {
        if let Some(end) = advanced[start..].find("    </div>") {
            advanced.replace_range(start..start + end + "    </div>".len(), "");
        }
    }
    let text = |fa: &str, en: &str| html_escape(copy(lang, fa, en));
    render_template(include_str!("tunnel.html"), &[
        ("return_to", admin_section_href(AdminSection::Tunnels, lang)),
        ("new_tunnel", text("یک تونل جدید بسازید", "Create a new connection")),
        ("intro", text("در سه مرحله دو سرور را به هم متصل کنید. سرور دوم هم باید تنظیم شود.", "Connect two servers in three steps. The other server needs a matching setup.")),
        ("reset", text("شروع دوباره", "Start again")),
        ("steps_label", text("مراحل ساخت تونل", "Tunnel setup steps")),
        ("step1", text("نوع اتصال", "Choose a connection")),
        ("step2", text("دو سرور", "Connect the servers")),
        ("step3", text("بررسی و ساخت", "Review & create")),
        ("name", text("نام اتصال", "Connection name")),
        ("preset_title", text("اتصال را برای چه کاری می‌خواهید؟", "What is this connection for?")),
        ("preset_gaming", text("بازی و تأخیر کم", "Gaming & low latency")),
        ("preset_secure", text("اتصال امن", "Secure connection")),
        ("preset_custom", text("تنظیم دلخواه", "Custom setup")),
        ("preset_custom_hint", text("انتخاب همه گزینه‌ها", "Choose every option")),
        ("preset_hint", text("یک نقطه شروع انتخاب کنید؛ تنظیمات قبل از ذخیره قابل بررسی‌اند.", "Choose a starting point. Review the settings before saving.")),
        ("secure_protocol", text("پروتکل امن", "Secure protocol")),
        ("tuning_title", text("اندازه بسته و تنظیم مسیر", "Packet size & path settings")),
        ("tuning_hint", text("خالی گذاشتن، رفتار فعلی کرنل و پروتکل را حفظ می‌کند. عدد مناسب به مسیر دو سرور بستگی دارد؛ سرعت و تأخیر واقعی را پس از اتصال تست کنید.", "Empty fields preserve the protocol and kernel defaults. Suitable values depend on the path between both servers. Test actual latency and throughput after connecting.")),
        ("mtu_hint", text("۵۷۶ تا ۹۰۰۰؛ برای IPv6 داخل تونل حداقل ۱۲۸۰. MTU بزرگ‌تر از مسیر می‌تواند باعث افت یا قطع بسته‌ها شود.", "576–9000; at least 1280 for IPv6 inside the tunnel. Exceeding the path MTU can cause packet loss.")),
        ("traffic_class", text("کلاس ترافیک / TOS", "Traffic class / TOS")),
        ("traffic_class_hint", text("بایت DSCP/ECN بیرونی از ۰ تا ۲۵۵. به‌خودی‌خود تضمین اولویت شبکه ایجاد نمی‌کند.", "Outer DSCP/ECN byte, 0–255. This does not guarantee network priority.")),
        ("vni_hint", text("شناسه شبکه؛ در هر دو سمت یکسان. مقدار پیش‌فرض ۴۲ است.", "Network identifier. Use the same value on both ends; the default is 42.")),
        ("lanes", text("جریان‌های موازی TUN", "Parallel TUN streams")),
        ("lanes_hint", text("۱ تا ۸، فقط برای TCP یا ICMP. پیش‌فرض ۱ است؛ جریان بیشتر لزوماً تأخیر یا سرعت را بهتر نمی‌کند.", "1–8, for TCP or ICMP only. The default is 1. More streams do not necessarily improve latency or speed.")),
        ("name_hint", text("نامی انتخاب کنید که بعداً به‌راحتی پیدا شود.", "Choose a name you can recognize later.")),
        ("protocol", text("پروتکل تونل", "Tunnel protocol")),
        ("protocol_hint", text("GRE مسیر مستقیم سبک است. برای رمزگذاری از WireGuard استفاده کنید.", "GRE is a lightweight direct path. Choose WireGuard when you need encryption.")),
        ("protocol_options", render_tunnel_protocol_options(lang)),
        ("two_servers", text("تونل همیشه دو سمت دارد", "A tunnel has two ends")),
        ("two_servers_hint", text("iMonitor را روی هر دو سرور نصب کنید. پروتکل یکسان، آدرس‌های معکوس و کلیدهای مشترک را در سمت دوم وارد کنید. راهنمای سمت دوم در مرحله آخر ساخته می‌شود.", "Install iMonitor on both servers. Use the same protocol, swap the local and peer addresses, and share the required keys. The last step gives you a guide for the other end.")),
        ("this_server", text("این سرور", "This server")),
        ("other_server", text("سرور مقابل", "Other server")),
        ("peer_public", text("IP عمومی سرور مقابل", "Other server's public IP")),
        ("peer_public_hint", text("آدرس اینترنتی سرور B؛ آدرس داخل تونل نیست.", "The Internet address of server B, before the tunnel exists.")),
        ("local_public", text("IP عمومی این سرور", "This server's public IP")),
        ("local_public_hint", text("اگر چند IP دارید، IP مسیر اتصال به سرور مقابل را انتخاب کنید.", "If the server has multiple addresses, choose the one used to reach the other server.")),
        ("automatic", text("انتخاب خودکار", "Choose automatically")),
        ("local_options", render_tunnel_outer_local_options(&data.host_ip_inventory, lang)),
        ("local_inner", text("آدرس این سمت داخل تونل / CIDR", "This end's tunnel IP / CIDR")),
        ("local_inner_hint", text("برای مثال 10.20.0.1/30. شبکه‌ای انتخاب کنید که در سرور استفاده نشده باشد.", "For example 10.20.0.1/30. Pick a private network that is unused on both servers.")),
        ("peer_inner", text("آدرس سمت مقابل داخل تونل", "Other end's tunnel IP")),
        ("peer_inner_hint", text("برای مثال 10.20.0.2. این IP برای تست اتصال و سرعت استفاده می‌شود.", "For example 10.20.0.2. iMonitor uses this address to check connectivity and test speed.")),
        ("address_example", text("یک مثال ساده", "A simple example")),
        ("address_example_hint", text("سمت A: آدرس محلی 10.20.0.1/30 و مقابل 10.20.0.2. سمت B: آدرس محلی 10.20.0.2/30 و مقابل 10.20.0.1.", "Server A: local 10.20.0.1/30, peer 10.20.0.2. Server B: local 10.20.0.2/30, peer 10.20.0.1.")),
        ("advanced_fields", advanced),
        ("esp_derivation", text("روش کلید ESP", "ESP key derivation")),
        ("esp_cipher", text("رمزگذاری و احراز اصالت ESP", "ESP encryption & authentication")),
        ("esp_gcm_legacy", text("AES-GCM قدیمی؛ فقط حفظ نشست‌های فعال موجود", "Legacy AES-GCM; preserve existing live states only")),
        ("esp_secure", text("امن؛ برای تونل جدید", "Secure; for new tunnels")),
        ("esp_legacy", text("قدیمی و ناامن؛ فقط برای سازگاری موجود", "Legacy and insecure; existing peers only")),
        ("esp_hint", text("راه‌اندازی جدید ESP از AES-CBC و HMAC-SHA256 با کلیدهای جداگانه HKDF استفاده می‌کند. کلید تصادفی حداقل ۳۲ نویسه، روش و رمزگذاری باید در هر دو سمت یکسان باشند. کلیدهای قدیمی قابل حدس‌اند؛ AES-GCM با کلید ثابت پس از بازسازی نشست خطر تکرار nonce دارد. نشست‌های فعال قدیمی بدون تغییر حفظ می‌شوند، اما ایجاد یا بازسازی آن‌ها انجام نمی‌شود. برای مهاجرت، هر دو سمت را هم‌زمان تغییر دهید یا مدیریت IKE بیرونی و حالت «فقط بررسی اینترفیس موجود» را انتخاب کنید.", "New ESP setups use AES-CBC with HMAC-SHA256 and separate HKDF keys. Both ends need the same random secret of at least 32 characters, derivation, and cipher. Legacy keys are predictable; static-key AES-GCM can reuse nonces after SA recreation. Matching existing live states are preserved, but cannot be created or recreated. Migrate both peers together, or use external IKE management with Check an existing interface only.")),
        ("esp_generate", text("ساخت کلید امن ESP", "Generate secure ESP key")),
        ("advanced_title", text("گزینه‌های بیشتر", "More options")),
        ("identifier", text("شناسه اتصال", "Connection identifier")),
        ("identifier_hint", text("از روی نام به‌صورت خودکار ساخته می‌شود؛ در صورت نیاز تغییر دهید.", "Generated from the name. Change it only if you need a particular identifier.")),
        ("interface", text("نام اینترفیس", "Interface name")),
        ("interface_hint", text("نامی کوتاه و منحصربه‌فرد؛ به‌صورت خودکار پیشنهاد می‌شود.", "A short, unique name. iMonitor suggests one automatically.")),
        ("source_interface", text("اینترفیس مسیر اتصال", "Connection source interface")),
        ("source_options", render_tunnel_source_interface_options(&data.host_ip_inventory, lang)),
        ("interval", text("فاصله بررسی، ثانیه", "Check interval, seconds")),
        ("public_visible", text("نمایش در صفحه وضعیت عمومی", "Show on the public status page")),
        ("private", text("فقط مدیر", "Admin only")),
        ("public", text("نمایش عمومی", "Publicly visible")),
        ("expected_state", text("وضعیت مورد انتظار اینترفیس", "Expected interface state")),
        ("creation_mode", text("راه‌اندازی اینترفیس", "Interface setup")),
        ("create_interface", text("ساخت و تنظیم خودکار", "Create & configure automatically")),
        ("existing_interface", text("فقط بررسی اینترفیس موجود", "Check an existing interface only")),
        ("traffic_requirement", text("شرط فعالیت ترافیک", "Traffic activity requirement")),
        ("idle_allowed", text("اتصال بدون ترافیک هم سالم است", "Allow an idle connection")),
        ("traffic_required", text("ارسال و دریافت مداوم لازم است", "Require traffic in both directions")),
        ("traffic_hint", text("برای بیشتر تونل‌ها حالت اول مناسب است. شرط ترافیک فعال می‌تواند تونل بیکار ولی سالم را دارای مشکل نشان دهد.", "Allow idle for most tunnels. Requiring active traffic can flag a healthy quiet tunnel as degraded.")),
        ("speedtest_title", text("تست سرعت داخلی", "Built-in speed test")),
        ("speedtest_hint", text("نیازی به iperf3 نیست. ارسال و دریافت هرکدام ۱۰ ثانیه تست می‌شوند. در هر دو سمت همان کلید را ذخیره کنید؛ شنونده روی IP داخل تونل فعال می‌شود.", "No iperf3 installation is needed. Upload and download are tested for 10 seconds each. Save the same key on both ends; the listener binds to the tunnel IP.")),
        ("speedtest_token", text("کلید مشترک تست سرعت", "Shared speed-test key")),
        ("speedtest_token_hint", text("حداقل ۳۲ نویسه. فقط با مدیر سمت مقابل به اشتراک بگذارید. خالی گذاشتن، شنونده تست را غیرفعال می‌کند.", "At least 32 characters. Share it privately with the other server's administrator. Leave it empty to disable the test listener.")),
        ("speedtest_port", text("پورت تست داخل تونل", "Test port inside the tunnel")),
        ("generate", text("ساخت کلید", "Generate key")),
        ("peer_label", text("سرور B", "SERVER B")),
        ("peer_title", text("راهنمای سمت مقابل", "Set up the other end")),
        ("peer_hint", text("این تنظیمات را در بخش تونل‌های سرور مقابل وارد کنید. آدرس عمومی این سرور را پیش از ارسال بررسی کنید. این راهنما ممکن است کلید مشترک داشته باشد؛ خصوصی نگه دارید.", "Enter these settings in Tunnels on the other server. Check this server's public IP before sharing. This guide may contain a shared key; keep it private.")),
        ("copy", text("کپی راهنما", "Copy guide")),
        ("after_save", text("بعد از ذخیره چه می‌شود؟", "What happens after saving?")),
        ("after_save_hint", text("iMonitor تنظیم این سمت را انجام می‌دهد. پس از تکمیل سمت مقابل، نتیجه اتصال را در جدول بررسی کنید. دکمه عیب‌یابی، پینگ و تست سرعت را اجرا می‌کند. نتیجه خطا را همراه با راهنمای پایین صفحه بخوانید.", "iMonitor configures this end. Finish the other end, then check the connection in the table. Use Diagnostics to run ping and speed tests. Read any failure alongside the troubleshooting guide.")),
        ("back", text("قبلی", "Back")),
        ("next", text("ادامه", "Continue")),
        ("save", text("ذخیره و ساخت تونل", "Save & create tunnel")),
        ("no_script", text("برای راهنمای مرحله‌ای جاوااسکریپت را فعال کنید. همه فیلدها همچنان در دسترس‌اند.", "Enable JavaScript for the step-by-step helper. All fields remain available without it.")),
    ])
}

fn render_tunnel_advanced_fields(lang: UiLanguage) -> String {
    format!(
        r#"
<div class="subpanel subpanel--soft tunnel-advanced-panel">
  <div class="panel-title">{advanced_title}</div>
  <div class="field-hint">{advanced_hint}</div>
  <div class="form-grid">
    <div>
      <label>{inner_local_cidr}</label>
      <input type="text" name="inner_local_cidr" placeholder="10.10.10.2">
      <div class="field-hint">{inner_local_cidr_hint}</div>
    </div>
    <div data-tunnel-protocols="gre,gretap,esp,tun">
      <label>{tunnel_key}</label>
      <input type="text" name="tunnel_key" placeholder="100 or 0x100">
      <div class="field-hint">{tunnel_key_hint}</div>
    </div>
    <div data-tunnel-protocols="tun">
      <label>{tun_transport}</label>
      <select name="tun_transport">
        <option value="udp">UDP</option>
        <option value="tcp">TCP</option>
        <option value="icmp">ICMP</option>
      </select>
      <div class="field-hint">{tun_transport_hint}</div>
    </div>
    <div data-tunnel-protocols="encap,l2tp,wireguard,tun,ssh,reverse_ssh,vxlan,geneve">
      <label>{transport_port}</label>
      <input type="number" min="1" max="65535" name="transport_port" placeholder="1701 / 51820 / 5555">
      <div class="field-hint">{transport_port_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp,wireguard,tun">
      <label>{listen_port}</label>
      <input type="number" min="1" max="65535" name="listen_port" placeholder="51820">
      <div class="field-hint">{listen_port_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp">
      <label>{l2tp_tunnel_id}</label>
      <input type="number" min="1" name="l2tp_tunnel_id" placeholder="1">
      <div class="field-hint">{l2tp_tunnel_id_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp">
      <label>{l2tp_peer_tunnel_id}</label>
      <input type="number" min="1" name="l2tp_peer_tunnel_id" placeholder="1">
      <div class="field-hint">{l2tp_peer_tunnel_id_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp">
      <label>{l2tp_session_id}</label>
      <input type="number" min="1" name="l2tp_session_id" placeholder="1">
      <div class="field-hint">{l2tp_session_id_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp">
      <label>{l2tp_peer_session_id}</label>
      <input type="number" min="1" name="l2tp_peer_session_id" placeholder="1">
      <div class="field-hint">{l2tp_peer_session_id_hint}</div>
    </div>
    <div data-tunnel-protocols="l2tp">
      <label>{l2tp_encapsulation}</label>
      <select name="l2tp_encapsulation">
        <option value="udp">UDP</option>
        <option value="ip">IP</option>
      </select>
      <div class="field-hint">{l2tp_encapsulation_hint}</div>
    </div>
    <div class="span-2" data-tunnel-protocols="wireguard">
      <label>{wireguard_private_key}</label>
      <input type="password" name="wireguard_private_key" autocomplete="off" placeholder="base64 private key">
      <div class="field-hint">{wireguard_private_key_hint}</div>
    </div>
    <div class="span-2" data-tunnel-protocols="wireguard">
      <label>{wireguard_peer_public_key}</label>
      <input type="text" name="wireguard_peer_public_key" placeholder="base64 peer public key">
      <div class="field-hint">{wireguard_peer_public_key_hint}</div>
    </div>
    <div class="span-2" data-tunnel-protocols="wireguard">
      <label>{wireguard_preshared_key}</label>
      <input type="password" name="wireguard_preshared_key" autocomplete="off" placeholder="optional preshared key">
      <div class="field-hint">{wireguard_preshared_key_hint}</div>
    </div>
    <div class="span-2" data-tunnel-protocols="wireguard">
      <label>{wireguard_allowed_ips}</label>
      <input type="text" name="wireguard_allowed_ips" placeholder="0.0.0.0/0, ::/0">
      <div class="field-hint">{wireguard_allowed_ips_hint}</div>
    </div>
    <div data-tunnel-protocols="ssh,reverse_ssh">
      <label>{ssh_username}</label>
      <input type="text" name="ssh_username" placeholder="root">
      <div class="field-hint">{ssh_username_hint}</div>
    </div>
    <div data-tunnel-protocols="ssh,reverse_ssh">
      <label>{ssh_password}</label>
      <input type="password" name="ssh_password" placeholder="optional">
      <div class="field-hint">{ssh_password_hint}</div>
    </div>
    <div class="span-2" data-tunnel-protocols="ssh,reverse_ssh">
      <label>{ssh_private_key}</label>
      <textarea name="ssh_private_key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
      <div class="field-hint">{ssh_private_key_hint}</div>
    </div>
  </div>
</div>
"#,
        advanced_title = copy(lang, "تنظیمات پروتکل", "Protocol settings"),
        advanced_hint = copy(
            lang,
            "فقط گزینه‌های پروتکل انتخابی دیده می‌شوند. حامل و کلیدهای مشترک دو سمت باید یکسان باشند.",
            "Only fields needed for your chosen protocol appear here. Keep the same transport settings and shared keys on both ends.",
        ),
        inner_local_cidr = copy(lang, "آدرس محلی تونل / CIDR", "Local Tunnel Address / CIDR"),
        inner_local_cidr_hint = copy(
            lang,
            "آدرس همین سرور روی خود اینترفیس تونل. اگر خالی بماند و Inner Probe آدرس peer تونل باشد، برنامه معمولاً /30 یا /127 را خودش حدس می‌زند.",
            "This server's own address on the tunnel interface. If left blank and Inner Probe is the peer tunnel IP, the app usually derives a matching /30 or /127 automatically.",
        ),
        tunnel_key = copy(lang, "کلید GRE / کلید مشترک ESP", "GRE key / ESP shared secret"),
        tunnel_key_hint = copy(
            lang,
            "برای GRE یک کلید عددی و برای ESP امن یک کلید مشترک تصادفی حداقل ۳۲ نویسه‌ای وارد کنید. کلید و روش رمزگذاری دو سمت باید یکسان باشند.",
            "Use a numeric GRE key or a random shared secret of at least 32 characters for secure ESP. Both ends need matching keys and ESP derivation.",
        ),
        tun_transport = copy(lang, "حامل TUN", "TUN Transport"),
        tun_transport_hint = copy(
            lang,
            "حامل باید در دو سمت یکسان و پشتیبانی‌شده باشد. پروفایل‌های قدیمی BIP در حالت سازگاری UDP هستند و هنگام ویرایش مشخص می‌شوند.",
            "Choose the transport supported and configured on both ends. Existing BIP profiles use legacy UDP compatibility and are labeled when edited.",
        ),
        transport_port = copy(lang, "پورت ترنسپورت", "Transport Port"),
        transport_port_hint = copy(
            lang,
            "برای ENCAP/GUE، L2TP/UDP، WireGuard، TUN و SSH استفاده می‌شود. در TUN/ICMP این پورت پل TCP داخلی سمت listener است و در SSH همان پورت SSH سرور مقابل است.",
            "Used for ENCAP/GUE, L2TP over UDP, WireGuard, TUN, and SSH. For TUN over ICMP this is the listener-side local TCP bridge port, and for SSH it is the remote SSH port.",
        ),
        listen_port = copy(lang, "پورت شنود محلی", "Local Listen Port"),
        listen_port_hint = copy(
            lang,
            "برای WireGuard و TUN استفاده می‌شود. در TUN/ICMP این پورت local forward روی سمت client است.",
            "Used for WireGuard and TUN. For TUN over ICMP, this is the client-side local forward port.",
        ),
        l2tp_tunnel_id = copy(lang, "Tunnel ID در L2TP", "L2TP Tunnel ID"),
        l2tp_tunnel_id_hint = copy(
            lang,
            "شناسه‌ی local تونل L2TP. اگر خالی بماند، ایران‌مانیتور از روی آدرس‌های local/remote یک مقدار پایدار تولید می‌کند.",
            "The local L2TP tunnel ID. Leave it blank to let IranMonitor generate a stable value from the local and remote endpoints.",
        ),
        l2tp_peer_tunnel_id = copy(lang, "Peer Tunnel ID در L2TP", "L2TP Peer Tunnel ID"),
        l2tp_peer_tunnel_id_hint = copy(
            lang,
            "شناسه‌ای که سمت مقابل برای tunnel خودش استفاده می‌کند. اگر خالی بماند، مقدار متناظر peer به‌صورت خودکار ساخته می‌شود.",
            "The tunnel ID used by the far-end peer. Leave it blank to let IranMonitor generate the matching peer value automatically.",
        ),
        l2tp_session_id = copy(lang, "Session ID در L2TP", "L2TP Session ID"),
        l2tp_session_id_hint = copy(
            lang,
            "شناسه‌ی session محلی L2TP. اگر خالی بماند، ایران‌مانیتور مقدار پایدار خودش را می‌سازد.",
            "The local L2TP session ID. Leave it blank to let IranMonitor generate a stable value automatically.",
        ),
        l2tp_peer_session_id = copy(lang, "Peer Session ID در L2TP", "L2TP Peer Session ID"),
        l2tp_peer_session_id_hint = copy(
            lang,
            "شناسه‌ی session سمت مقابل در L2TP. اگر خالی بماند، مقدار peer به‌صورت خودکار ساخته می‌شود.",
            "The far-end L2TP session ID. Leave it blank to let IranMonitor generate the matching peer value automatically.",
        ),
        l2tp_encapsulation = copy(lang, "کپسوله‌سازی L2TP", "L2TP Encapsulation"),
        l2tp_encapsulation_hint = copy(
            lang,
            "در بیشتر سناریوها روی UDP بماند. فقط وقتی peer شما واقعاً L2TP/IP خالص دارد آن را روی IP بگذارید.",
            "Leave this on UDP for most setups. Change it to IP only when the peer really uses raw L2TP/IP.",
        ),
        wireguard_private_key = copy(lang, "کلید خصوصی WireGuard", "WireGuard Private Key"),
        wireguard_private_key_hint = copy(
            lang,
            "برای ساخت خودکار اینترفیس WireGuard لازم است. اگر خالی بماند، ایران‌مانیتور خودش یک کلید خصوصی local می‌سازد.",
            "Required for automatic WireGuard creation. Leave it blank to let IranMonitor generate a local private key automatically.",
        ),
        wireguard_peer_public_key = copy(lang, "کلید عمومی Peer در WireGuard", "WireGuard Peer Public Key"),
        wireguard_peer_public_key_hint = copy(
            lang,
            "PublicKey سمت مقابل که باید به این اینترفیس وصل شود.",
            "The far-end peer PublicKey that this interface should connect to.",
        ),
        wireguard_preshared_key = copy(lang, "Preshared Key در WireGuard", "WireGuard Preshared Key"),
        wireguard_preshared_key_hint = copy(
            lang,
            "اختیاری است. اگر تنظیم می‌کنید، مقدار یکسان در دو سمت وارد کنید. در صورت عدم استفاده از PSK خالی بگذارید.",
            "Optional. If supplied, copy exactly the same preshared key to both ends. Leave it empty when you are not using a PSK.",
        ),
        wireguard_allowed_ips = copy(lang, "Allowed IPs در WireGuard", "WireGuard Allowed IPs"),
        wireguard_allowed_ips_hint = copy(
            lang,
            "مثلاً <code>0.0.0.0/0, ::/0</code> یا فقط شبکه‌های داخل تونل. اگر خالی بماند و Inner Probe یک IP باشد، همان peer IP به‌صورت /32 یا /128 استفاده می‌شود.",
            "For example <code>0.0.0.0/0, ::/0</code> or only the tunnel networks. If left blank and Inner Probe is an IP, that peer IP is used automatically as /32 or /128.",
        ),
        ssh_username = copy(lang, "کاربر SSH", "SSH Username"),
        ssh_username_hint = copy(
            lang,
            "برای SSH TUN نام کاربری سرور مقابل. اگر خالی بماند root در نظر گرفته می‌شود.",
            "The remote username for SSH TUN. If left empty, IranMonitor falls back to root.",
        ),
        ssh_password = copy(lang, "رمز SSH", "SSH Password"),
        ssh_password_hint = copy(
            lang,
            "اگر با رمز به peer وصل می‌شوید این فیلد را پر کنید. در صورت داشتن کلید خصوصی می‌توانید این را خالی بگذارید.",
            "Fill this when the peer is reached with password authentication. Leave it empty when you use a private key instead.",
        ),
        ssh_private_key = copy(lang, "کلید خصوصی SSH", "SSH Private Key"),
        ssh_private_key_hint = copy(
            lang,
            "کلید خصوصی OpenSSH برای ساخت SSH TUN. اگر این فیلد پر شود، از آن به‌جای رمز عبور استفاده می‌شود.",
            "An OpenSSH private key for SSH TUN creation. When this field is filled, it is used instead of a password.",
        ),
    )
}

