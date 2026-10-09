fn render_monitor_builder_form(
    lang: UiLanguage,
    return_to: &str,
    _folders: &[MonitorFolder],
    _checks: &[MonitorCheckRow],
    _host_ip_inventory: &[HostIpInventoryEntry],
) -> String {
    let hint_auto_id = copy(
        lang,
        "اگر این فیلد را خالی بگذارید، از روی عنوان به‌صورت خودکار ساخته می‌شود.",
        "If left empty, this will be generated from the label automatically.",
    );
    let monitor_kind_options = render_monitor_kind_options(lang);
    format!(
        r#"
<form method="post" action="/admin/checks/save" class="stack-form monitor-builder" id="monitorBuilder">
  <input type="hidden" name="return_to" value="{return_to}">
  <input type="hidden" name="original_check_id" id="monitorOriginalCheckId">
  <div class="builder-mode-bar">
    <div class="builder-mode-copy">
      <strong id="monitorBuilderModeLabel">{builder_mode_title}</strong>
      <span class="muted">{builder_mode_note}</span>
    </div>
    <button type="button" class="ghost" id="monitorFormReset">{reset_builder}</button>
  </div>
  <div class="form-grid form-grid--wide">
    <div>
      <label>{label}</label>
      <input type="text" name="label" id="monitorLabel" placeholder="Google HTTPS" required>
      <div class="field-hint">{label_hint}</div>
    </div>
    <div>
      <label>{monitor_type}</label>
      <select name="kind" id="monitorKind" required>
        {monitor_kind_options}
      </select>
    </div>
    <div>
      <label>{monitor_interval}</label>
      <input type="number" min="10" step="1" name="interval_secs" value="60">
      <div class="field-hint">{monitor_interval_hint}</div>
    </div>
  </div>

  <div class="builder-view-toggle" id="monitorBuilderView" data-mode="simple" role="tablist" aria-label="{builder_switch_label}">
    <span class="builder-view-toggle__thumb" aria-hidden="true"></span>
    <button
      type="button"
      class="builder-view-toggle__button is-active"
      data-builder-view-trigger="simple"
      aria-selected="true"
    >{simple_setup_title}</button>
    <button
      type="button"
      class="builder-view-toggle__button"
      data-builder-view-trigger="advanced"
      aria-selected="false"
    >{advanced_setup_title}</button>
  </div>

  <div class="stack-form monitor-builder-sections" id="monitorBuilderPanels" data-mode="simple">
    <div class="subpanel stack-form builder-view-panel" data-builder-panel="simple">
      <div>
        <h3>{simple_setup_title}</h3>
        <p class="muted">{simple_setup_note}</p>
      </div>

      <div class="form-panel" data-simple-kinds="icmp">
        <div class="panel-title">ICMP</div>
        <div class="form-grid">
          <div>
            <label>{target}</label>
            <input type="text" name="simple_target" placeholder="8.8.8.8 or example.com">
            <div class="field-hint">{icmp_target_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-simple-kinds="tcp,udp,ssh,sftp,rdp,ftp">
        <div class="panel-title">{network_target_title}</div>
        <div class="form-grid">
          <div>
            <label>{target}</label>
            <input type="text" name="simple_target" placeholder="198.51.100.10 or server.example.com">
            <div class="field-hint">{target_hint}</div>
          </div>
          <div>
            <label>{port}</label>
            <input type="number" min="1" max="65535" name="simple_port" placeholder="443">
            <div class="field-hint">{port_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-simple-kinds="http,https">
        <div class="panel-title">HTTP / HTTPS</div>
        <div class="form-grid">
          <div>
            <label>{host}</label>
            <input type="text" name="simple_host" placeholder="www.google.com">
            <div class="field-hint">{host_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-simple-kinds="dns">
        <div class="panel-title">DNS</div>
        <div class="form-grid">
          <div>
            <label>{record_name}</label>
            <input type="text" name="simple_record_name" placeholder="example.com">
          </div>
        </div>
      </div>

      <div class="form-panel" data-simple-kinds="v2ray">
        <div class="panel-title">V2Ray</div>
        <div class="form-grid">
          <div>
            <label>{proxy_type}</label>
            <select name="simple_proxy_type" id="simpleV2rayProtocolType">
              <option value="socks5">SOCKS5 Proxy</option>
              <option value="http">HTTP Proxy</option>
              <option value="https">HTTPS Proxy</option>
              <option value="vmess">VMess</option>
              <option value="vless" selected>VLESS</option>
              <option value="trojan">Trojan</option>
              <option value="wireguard">WireGuard</option>
              <option value="shadowsocks">Shadowsocks</option>
              <option value="other_v2ray">Other V2Ray / Xray</option>
            </select>
          </div>
          <div class="span-2">
            <label>{profile_import}</label>
            <textarea name="simple_profile_import" rows="5" placeholder="vmess://...&#10;vless://...&#10;trojan://...&#10;ss://..."></textarea>
            <div class="field-hint">{profile_import_hint}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="subpanel stack-form builder-view-panel" data-builder-panel="advanced">
      <div>
        <h3>{advanced_setup_title}</h3>
        <p class="muted">{advanced_setup_note}</p>
      </div>

      <div class="form-grid form-grid--wide">
        <div>
          <label>{check_id}</label>
          <input type="text" name="check_id" id="monitorCheckId" placeholder="google-https">
          <div class="field-hint">{hint_auto_id}</div>
        </div>
        <div>
          <label>{ip_version}</label>
          <select name="ip_version">
            <option value="any">any</option>
            <option value="ipv4">ipv4</option>
            <option value="ipv6">ipv6</option>
          </select>
        </div>
        <div>
          <label>{timeout_ms}</label>
          <input type="number" min="500" step="100" name="timeout_ms" value="3000">
        </div>
        <div>
          <label>{public_visible}</label>
          <select name="public_visible">
            <option value="1">{yes}</option>
            <option value="0">{no}</option>
          </select>
        </div>
        <div>
          <label>{enabled}</label>
          <select name="enabled">
            <option value="1">{yes}</option>
            <option value="0">{no}</option>
          </select>
        </div>
      </div>

      <div class="form-panel" data-kinds="icmp">
        <div class="panel-title">ICMP</div>
        <div class="form-grid">
          <div>
            <label>{target}</label>
            <input type="text" name="target" placeholder="8.8.8.8 or example.com">
            <div class="field-hint">{icmp_target_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="tcp,udp,ssh,sftp,rdp,ftp">
        <div class="panel-title">{network_target_title}</div>
        <div class="form-grid">
          <div>
            <label>{target}</label>
            <input type="text" name="target" placeholder="198.51.100.10 or server.example.com">
            <div class="field-hint">{target_hint}</div>
          </div>
          <div>
            <label>{port}</label>
            <input type="number" min="1" max="65535" name="port" placeholder="443">
            <div class="field-hint">{port_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="udp">
        <div class="panel-title">UDP</div>
        <div class="form-grid">
          <div>
            <label>{udp_payload}</label>
            <input type="text" name="udp_payload" placeholder="ping">
            <div class="field-hint">{udp_payload_hint}</div>
          </div>
          <div>
            <label>{expect_response}</label>
            <select name="expect_response">
              <option value="0">{no}</option>
              <option value="1">{yes}</option>
            </select>
          </div>
          <div>
            <label>{response_contains}</label>
            <input type="text" name="response_contains" placeholder="pong">
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="ssh,sftp">
        <div class="panel-title">SSH / SFTP</div>
        <div class="form-grid">
          <div>
            <label>{expect_banner_prefix}</label>
            <input type="text" name="expect_banner_prefix" placeholder="SSH-2.0">
            <div class="field-hint">{banner_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="http,https">
        <div class="panel-title">HTTP / HTTPS</div>
        <div class="form-grid">
          <div>
            <label>{host}</label>
            <input type="text" name="host" placeholder="www.google.com">
            <div class="field-hint">{host_hint}</div>
          </div>
          <div>
            <label>{connect_host}</label>
            <input type="text" name="connect_host" placeholder="203.0.113.20">
            <div class="field-hint">{connect_host_hint}</div>
          </div>
          <div>
            <label>{host_header}</label>
            <input type="text" name="host_header" placeholder="status.example.com">
          </div>
          <div>
            <label>{tls_server_name}</label>
            <input type="text" name="tls_server_name" placeholder="status.example.com">
          </div>
          <div>
            <label>{port}</label>
            <input type="number" min="1" max="65535" name="port" placeholder="443">
          </div>
          <div>
            <label>{http_method}</label>
            <select name="method">
              <option value="GET">GET</option>
              <option value="HEAD">HEAD</option>
              <option value="POST">POST</option>
            </select>
          </div>
          <div>
            <label>{http_path}</label>
            <input type="text" name="path" placeholder="/">
          </div>
          <div>
            <label>{expected_status}</label>
            <input type="text" name="expected_status" placeholder="200,301,302">
            <div class="field-hint">{expected_status_hint}</div>
          </div>
          <div>
            <label>{body_contains}</label>
            <input type="text" name="body_contains" placeholder="welcome">
          </div>
          <div class="span-2">
            <label>{headers}</label>
            <textarea name="headers" rows="4" placeholder="User-Agent: IranMonitor&#10;Cache-Control: no-cache"></textarea>
            <div class="field-hint">{headers_hint}</div>
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="dns">
        <div class="panel-title">DNS</div>
        <div class="form-grid">
          <div>
            <label>{dns_server}</label>
            <input type="text" name="dns_server" placeholder="1.1.1.1">
          </div>
          <div>
            <label>{dns_port}</label>
            <input type="number" min="1" max="65535" name="dns_port" value="53">
          </div>
          <div>
            <label>{record_name}</label>
            <input type="text" name="record_name" placeholder="example.com">
          </div>
          <div>
            <label>{record_type}</label>
            <select name="record_type">
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="CNAME">CNAME</option>
              <option value="MX">MX</option>
              <option value="NS">NS</option>
              <option value="TXT">TXT</option>
            </select>
          </div>
          <div>
            <label>{expect_answers_min}</label>
            <input type="number" min="1" name="expect_answers_min" value="1">
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="ftp">
        <div class="panel-title">FTP</div>
        <div class="form-grid">
          <div>
            <label>{username_optional}</label>
            <input type="text" name="username" placeholder="demo">
          </div>
          <div>
            <label>{password_optional}</label>
            <input type="password" name="password" placeholder="secret">
          </div>
        </div>
      </div>

      <div class="form-panel" data-kinds="v2ray">
        <div class="panel-title">V2Ray</div>
        <div class="field-hint">{v2ray_intro}</div>
        <div class="form-grid">
          <div class="span-2">
            <label>{profile_import}</label>
            <textarea name="profile_import" id="v2rayProfileImport" rows="6" placeholder="vmess://...&#10;vless://...&#10;trojan://...&#10;ss://...&#10;&#10;[Interface]&#10;PrivateKey = ...&#10;[Peer]&#10;Endpoint = 185.239.2.22:22221"></textarea>
            <div class="field-hint">{profile_import_hint}</div>
          </div>
          <div>
            <label>{proxy_type}</label>
            <select name="proxy_type" id="v2rayProtocolType">
              <option value="socks5">SOCKS5 Proxy</option>
              <option value="http">HTTP Proxy</option>
              <option value="https">HTTPS Proxy</option>
              <option value="vmess">VMess</option>
              <option value="vless" selected>VLESS</option>
              <option value="trojan">Trojan</option>
              <option value="wireguard">WireGuard</option>
              <option value="shadowsocks">Shadowsocks</option>
              <option value="other_v2ray">Other V2Ray / Xray</option>
            </select>
            <div class="field-hint">{v2ray_protocol_hint}</div>
          </div>
          <div data-v2ray-section="proxy">
            <label>{local_entry_type}</label>
            <select name="local_entry_type" id="v2rayLocalEntryType">
              <option value="direct">Direct listener only</option>
              <option value="socks5">SOCKS5</option>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
            </select>
            <div class="field-hint">{local_entry_hint}</div>
          </div>
        </div>

        <div class="form-grid" data-v2ray-section="proxy">
          <div>
            <label>{proxy_host}</label>
            <input type="text" name="proxy_host" placeholder="127.0.0.1">
            <div class="field-hint">{proxy_host_hint}</div>
          </div>
          <div>
            <label>{proxy_port}</label>
            <input type="number" min="1" max="65535" name="proxy_port" value="1080">
            <div class="field-hint">{proxy_port_hint}</div>
          </div>
          <div class="span-2">
            <label>{test_url}</label>
            <input type="text" name="test_url" placeholder="https://www.google.com/generate_204">
            <div class="field-hint">{test_url_hint}</div>
          </div>
          <div>
            <label>{username_optional}</label>
            <input type="text" name="username" placeholder="optional">
          </div>
          <div>
            <label>{password_optional}</label>
            <input type="password" name="password" placeholder="optional">
          </div>
          <div>
            <label>{expected_status}</label>
            <input type="text" name="expected_status" placeholder="204">
          </div>
          <div>
            <label>{body_contains}</label>
            <input type="text" name="body_contains" placeholder="optional body text">
          </div>
        </div>

        <div class="form-grid" data-v2ray-section="xray">
          <div class="span-2">
            <strong>{remote_listener_title}</strong>
            <div class="field-hint">{remote_listener_hint}</div>
          </div>
          <div>
            <label>{server_host}</label>
            <input type="text" name="server_host" placeholder="edge.example.com">
          </div>
          <div>
            <label>{server_port}</label>
            <input type="number" min="1" max="65535" name="server_port" value="443">
          </div>
          <div>
            <label>{server_name}</label>
            <input type="text" name="server_name" placeholder="edge.example.com">
            <div class="field-hint">{server_name_hint}</div>
          </div>
          <div>
            <label>{transport}</label>
            <input type="text" name="transport" placeholder="tcp+tls / ws / grpc / reality">
            <div class="field-hint">{transport_hint}</div>
          </div>
        </div>

        <div class="form-grid" data-v2ray-section="wireguard">
          <div class="span-2">
            <strong>{wireguard_title}</strong>
            <div class="field-hint">{wireguard_hint}</div>
          </div>
          <div>
            <label>{wireguard_interface}</label>
            <input type="text" name="wireguard_interface" placeholder="wg0">
            <div class="field-hint">{wireguard_interface_hint}</div>
          </div>
          <div>
            <label>{wireguard_peer}</label>
            <input type="text" name="wireguard_peer" placeholder="peer public key or endpoint">
            <div class="field-hint">{wireguard_peer_hint}</div>
          </div>
          <div>
            <label>{inner_probe}</label>
            <input type="text" name="inner_probe" placeholder="10.66.0.1">
            <div class="field-hint">{inner_probe_hint}</div>
          </div>
          <div>
            <label>{source_interface}</label>
            <input type="text" name="source_interface" placeholder="eth0">
            <div class="field-hint">{source_interface_hint}</div>
          </div>
          <div>
            <label>{max_handshake_age}</label>
            <input type="number" min="1" name="max_handshake_age_secs" placeholder="180">
            <div class="field-hint">{max_handshake_age_hint}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <button type="submit">{save_monitor}</button>
</form>
"#,
        return_to = html_escape(return_to),
        builder_mode_title = copy(lang, "ساخت مانیتور جدید", "Create a New Monitor"),
        builder_mode_note = copy(
            lang,
            "برای ویرایش یک ردیف از لیست پایین، دکمه ویرایش همان ردیف را بزنید.",
            "Use the Edit action in the list below to load an existing monitor into this form.",
        ),
        reset_builder = copy(lang, "پاک‌سازی فرم", "Reset Form"),
        builder_switch_label = copy(lang, "حالت ساخت مانیتور", "Monitor builder mode"),
        label = t(lang, "label"),
        monitor_kind_options = monitor_kind_options,
        label_hint = copy(
            lang,
            "این نام در پنل مدیریت و پنل عمومی دیده می‌شود.",
            "This name is shown in both the admin and public panel.",
        ),
        check_id = copy(lang, "شناسه مانیتور", "Monitor ID"),
        hint_auto_id = hint_auto_id,
        monitor_type = copy(lang, "نوع مانیتور", "Monitor Type"),
        simple_setup_title = copy(lang, "راه‌اندازی ساده", "Simple Setup"),
        simple_setup_note = copy(
            lang,
            "در این بخش فقط نام، پروتکل، بازه مانیتورینگ و حداقل فیلدهای لازم را پر کنید.",
            "Use this section for the name, protocol, interval, and only the minimum fields needed to start.",
        ),
        advanced_setup_title = copy(lang, "راه‌اندازی پیشرفته", "Advanced Setup"),
        advanced_setup_note = copy(
            lang,
            "اگر به کنترل بیشتر نیاز دارید، جزئیات دقیق هر پروتکل، شناسه پایدار، تایم‌اوت و گزینه‌های نمایش عمومی را از این بخش تنظیم کنید.",
            "Use this section when you need fine-grained protocol fields, a stable ID, timeout control, or public visibility settings.",
        ),
        ip_version = copy(lang, "نسخه IP", "IP Version"),
        timeout_ms = copy(lang, "مهلت (میلی‌ثانیه)", "Timeout (ms)"),
        monitor_interval = copy(lang, "بازه مانیتورینگ", "Monitor Interval"),
        monitor_interval_hint = copy(
            lang,
            "این مانیتور هر چند ثانیه یک‌بار اجرا شود. حداقل مقدار ۱۰ ثانیه است.",
            "How often this monitor should run. The minimum value is 10 seconds.",
        ),
        public_visible = t(lang, "public_visible"),
        enabled = t(lang, "enabled"),
        yes = t(lang, "yes"),
        no = t(lang, "no"),
        target = copy(lang, "مقصد", "Target"),
        icmp_target_hint = copy(
            lang,
            "برای پینگ ساده، IP یا دامنه‌ای مثل 8.8.8.8 وارد کنید.",
            "For a basic ping, enter an IP or hostname such as 8.8.8.8.",
        ),
        network_target_title = copy(lang, "مقصد شبکه", "Network Target"),
        target_hint = copy(
            lang,
            "IP مستقیم یا دامنه‌ی سرویس را وارد کنید.",
            "Enter the service IP or hostname.",
        ),
        port = t(lang, "port"),
        port_hint = copy(
            lang,
            "برای SSH معمولاً 22، برای HTTPS معمولاً 443، و برای RDP معمولاً 3389 است.",
            "Typical ports: 22 for SSH, 443 for HTTPS, and 3389 for RDP.",
        ),
        udp_payload = copy(lang, "Payload ارسالی", "Payload"),
        udp_payload_hint = copy(
            lang,
            "اگر سرویس UDP شما برای پاسخ دادن نیاز به داده دارد، این فیلد را پر کنید.",
            "Use this when the UDP service expects a probe payload before replying.",
        ),
        expect_response = copy(lang, "انتظار پاسخ", "Expect Response"),
        response_contains = copy(lang, "پاسخ باید شامل", "Response Contains"),
        expect_banner_prefix = copy(lang, "پیشوند بنر", "Banner Prefix"),
        banner_hint = copy(
            lang,
            "برای نمونه SSH-2.0 تا مطمئن شوید سرور بنر درست می‌فرستد.",
            "For example SSH-2.0 to make sure the server banner is correct.",
        ),
        host = copy(lang, "هاست", "Host"),
        host_hint = copy(
            lang,
            "نام دامنه‌ای که در URL و Host header استفاده می‌شود.",
            "The hostname used in the URL and Host header.",
        ),
        connect_host = copy(lang, "هاست اتصال", "Connect Host"),
        connect_host_hint = copy(
            lang,
            "اگر می‌خواهید به یک IP خاص وصل شوید ولی هدر هاست چیز دیگری باشد، این فیلد را پر کنید.",
            "Use this to connect to a specific IP while keeping a different host header.",
        ),
        host_header = copy(lang, "Host Header", "Host Header"),
        tls_server_name = copy(lang, "TLS Server Name", "TLS Server Name"),
        http_method = copy(lang, "متد HTTP", "HTTP Method"),
        http_path = copy(lang, "مسیر", "Path"),
        expected_status = copy(lang, "کدهای وضعیت مجاز", "Allowed Status Codes"),
        expected_status_hint = copy(
            lang,
            "کدها را با کاما جدا کنید. اگر خالی باشد، همه پاسخ‌های 200 تا 399 پذیرفته می‌شوند.",
            "Comma separated. Leave empty to accept any 200-399 response.",
        ),
        body_contains = copy(lang, "متن مورد انتظار در پاسخ", "Expected Body Text"),
        headers = copy(lang, "هدرهای اضافه", "Extra Headers"),
        headers_hint = copy(
            lang,
            "هر خط به شکل Key: Value نوشته شود.",
            "Write one header per line in the form Key: Value.",
        ),
        dns_server = copy(lang, "سرور DNS", "DNS Server"),
        dns_port = copy(lang, "پورت DNS", "DNS Port"),
        record_name = copy(lang, "نام رکورد", "Record Name"),
        record_type = copy(lang, "نوع رکورد", "Record Type"),
        expect_answers_min = copy(lang, "حداقل تعداد پاسخ", "Minimum Answer Count"),
        username_optional = copy(lang, "نام کاربری اختیاری", "Optional Username"),
        password_optional = copy(lang, "رمز عبور اختیاری", "Optional Password"),
        inner_probe = copy(lang, "ایپی لوکال مبدا", "Source Local IP"),
        inner_probe_hint = copy(
            lang,
            "IP داخل تونل که باید از این سرور قابل دسترس باشد؛ مقدار ساده‌ی پیشنهادی <code>10.10.10.1</code> است.",
            "The inside-tunnel IP that must be reachable from this server; the suggested simple value is <code>10.10.10.1</code>.",
        ),
        source_interface = copy(lang, "اینترفیس مبدأ", "Source Interface"),
        source_interface_hint = copy(
            lang,
            "برای probeهای outer و ساخت تونل از همین uplink استفاده می‌شود. Inner Probe خودکار از اینترفیس تونل عبور می‌کند، پس این فیلد را فقط برای سمت بیرونی عوض کنید.",
            "This is used for outer-side probing and tunnel creation on the uplink side. Inner Probe automatically uses the tunnel interface itself, so only change this for the outer side.",
        ),
        proxy_type = copy(lang, "خانواده پروتکل", "Protocol Family"),
        profile_import = copy(lang, "ایمپورت لینک یا کانفیگ", "Import Link or Config"),
        profile_import_hint = copy(
            lang,
            "می‌توانید مستقیم <code>vmess://</code>، <code>vless://</code>، <code>trojan://</code>، <code>ss://</code> یا متن کامل کانفیگ WireGuard را paste کنید. مقادیر parse شده به‌صورت خودکار وارد می‌شوند، و لینک‌های اشتراکی به‌صورت پیش‌فرض روی Direct می‌مانند تا ناخواسته به local proxy اشتباه وصل نشوید.",
            "You can paste a full <code>vmess://</code>, <code>vless://</code>, <code>trojan://</code>, or <code>ss://</code> share link, or a full WireGuard config block here. Parsed values are applied automatically, and share links stay on Direct by default so you do not accidentally point the monitor at a local proxy that does not exist.",
        ),
        v2ray_intro = copy(
            lang,
            "برای شروع سریع، لینک اشتراک یا کانفیگ را paste کنید. برای HTTP/SOCKS مستقیم همان پراکسی واقعی را تست کنید. برای VMess/VLESS/Trojan/Shadowsocks ابتدا با Direct شروع کنید، و فقط وقتی local entry واقعی دارید به SOCKS5/HTTP/HTTPS بروید. برای WireGuard هم کانفیگ کامل یا endpoint را وارد کنید.",
            "For the fastest setup, paste a share link or config block first. Native HTTP/SOCKS checks can target the real proxy directly. For VMess, VLESS, Trojan, and Shadowsocks, start with Direct and move to SOCKS5, HTTP, or HTTPS only when a real local entry already exists on this server. WireGuard profiles can be imported from a full config or endpoint details.",
        ),
        v2ray_protocol_hint = copy(
            lang,
            "این فیلد مشخص می‌کند مانیتور درباره‌ی چه خانواده‌ای گزارش بدهد و کدام بخش‌های فرم نمایش داده شود.",
            "This decides which protocol family the monitor reports on and which configuration fields are shown below.",
        ),
        local_entry_type = copy(lang, "نوع Local Entry", "Local Entry Type"),
        local_entry_hint = copy(
            lang,
            "برای لینک‌های VMess/VLESS/Trojan/Shadowsocks بهتر است اول روی <code>Direct listener only</code> بمانید. فقط وقتی این گزینه را به SOCKS5/HTTP/HTTPS تغییر دهید که واقعاً یک inbound محلی Xray یا sing-box روی همین سرور در حال listen باشد.",
            "For VMess, VLESS, Trojan, and Shadowsocks share links, keep this on <code>Direct listener only</code> first. Change it to SOCKS5, HTTP, or HTTPS only when a real local Xray or sing-box inbound is already listening on this same server.",
        ),
        proxy_host = copy(lang, "هاست Local Entry / Proxy", "Local Entry / Proxy Host"),
        proxy_host_hint = copy(
            lang,
            "برای پروکسی‌های بومی، آدرس همان پراکسی را وارد کنید. برای Xray-family فقط در حالت local entry این فیلد لازم است و معمولاً <code>127.0.0.1</code> یا آدرس loopback دیگری خواهد بود.",
            "For native proxies, enter the actual proxy address. For Xray-family transports, this field is needed only in local-entry mode and is usually <code>127.0.0.1</code> or another loopback address.",
        ),
        proxy_port = copy(lang, "پورت Local Entry / Proxy", "Local Entry / Proxy Port"),
        proxy_port_hint = copy(
            lang,
            "فقط در حالت local entry پر می‌شود. مقدار رایج <code>1080</code> برای SOCKS5 و <code>8080</code> برای HTTP است، یا هر پورتی که inbound محلی شما واقعاً روی آن listen می‌کند.",
            "Fill this only for local-entry mode. Typical values are <code>1080</code> for SOCKS5 and <code>8080</code> for HTTP, or whatever port your local inbound is really listening on.",
        ),
        test_url = copy(lang, "URL تست", "Test URL"),
        test_url_hint = copy(
            lang,
            "این فیلد فقط در حالت local entry استفاده می‌شود تا مسیر کامل خروجی سنجیده شود. اگر خالی بماند، به‌صورت خودکار <code>https://www.google.com/generate_204</code> استفاده می‌شود.",
            "This field is used only in local-entry mode to verify the full outbound path. If you leave it empty, the monitor automatically uses <code>https://www.google.com/generate_204</code>.",
        ),
        remote_listener_title = copy(lang, "Listener Remote", "Remote Listener"),
        remote_listener_hint = copy(
            lang,
            "این بخش وقتی استفاده می‌شود که روی <code>Direct listener only</code> بمانید یا عمداً آن را انتخاب کنید. در این حالت فقط reachability ساده‌ی listener با TCP connect سنجیده می‌شود. اگر شبیه‌سازی واقعی مسیر کاربر را می‌خواهید، باید local entry واقعی بدهید.",
            "This section is used when you keep or intentionally choose <code>Direct listener only</code>. In that mode, the monitor performs only a plain TCP reachability check against the VMess, VLESS, Trojan, or Shadowsocks listener. If you want real user-path simulation, you need a real local entry.",
        ),
        server_host = copy(lang, "هاست Listener", "Listener Host"),
        server_port = copy(lang, "پورت Listener", "Listener Port"),
        server_name = copy(lang, "SNI / Server Name", "SNI / Server Name"),
        server_name_hint = copy(
            lang,
            "برای TLS، REALITY یا دامنه‌ی upstream مفید است و فقط برای مستندسازی و خروجی مانیتور ذخیره می‌شود.",
            "Useful for TLS, REALITY, or upstream domain context. It is stored for operator clarity and result details.",
        ),
        transport = copy(lang, "Transport", "Transport"),
        transport_hint = copy(
            lang,
            "مثلاً <code>tcp+tls</code>، <code>ws</code>، <code>grpc</code> یا <code>reality</code>. این فیلد برای مستندسازی و خروجی پنل است.",
            "For example <code>tcp+tls</code>, <code>ws</code>, <code>grpc</code>, or <code>reality</code>. This helps document the route in the panel and results.",
        ),
        wireguard_title = copy(lang, "WireGuard", "WireGuard"),
        wireguard_hint = copy(
            lang,
            "این بخش وجود اینترفیس، peer انتخابی، تازگی handshake و inner probe را بررسی می‌کند. چون WireGuard در حالت idle ساکت است، age handshake فقط وقتی لازم دارید وارد کنید.",
            "This section checks interface presence, an optional selected peer, handshake freshness, and an inner probe. Because WireGuard is quiet when idle, only set a handshake-age target when you truly need that requirement.",
        ),
        wireguard_interface = copy(lang, "اینترفیس WireGuard", "WireGuard Interface"),
        wireguard_interface_hint = copy(
            lang,
            "نام اینترفیس محلی مثل <code>wg0</code> یا <code>iran-wg</code>.",
            "The local interface name, such as <code>wg0</code> or <code>iran-wg</code>.",
        ),
        wireguard_peer = copy(lang, "فیلتر Peer", "Peer Filter"),
        wireguard_peer_hint = copy(
            lang,
            "می‌تواند بخشی از public key یا endpoint peer باشد تا در <code>wg show</code> همان peer انتخاب شود.",
            "This can be part of a peer public key or endpoint so the monitor picks the intended peer from <code>wg show</code> output.",
        ),
        max_handshake_age = copy(lang, "حداکثر سن Handshake (ثانیه)", "Max Handshake Age (s)"),
        max_handshake_age_hint = copy(
            lang,
            "اگر پر شود، peer باید handshake تازه‌تری از این بازه داشته باشد. برای تونل‌های idle بهتر است خالی بماند.",
            "If filled, the selected peer must have a handshake newer than this limit. Leave it empty for mostly idle tunnels.",
        ),
        save_monitor = t(lang, "save_monitor"),
    )
}

