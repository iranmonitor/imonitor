/* Shared first-visit tour, accessible form helpers, and the tunnel setup wizard. */
(() => {
  'use strict';
  const fa = document.documentElement.lang === 'fa';
  const say = (persian, english) => fa ? persian : english;
  const shell = document.querySelector('[data-workspace-section]');
  if (!shell) return;
  document.querySelectorAll('time[data-unix]').forEach(element => {
    const timestamp = Number(element.dataset.unix);
    if (!Number.isFinite(timestamp) || timestamp <= 0) return;
    const date = new Date(timestamp * 1000);
    element.dateTime = date.toISOString();
    element.textContent = new Intl.DateTimeFormat(fa ? 'fa-IR' : 'en', { dateStyle: 'short', timeStyle: 'short' }).format(date);
  });

  // Associate legacy labels with their actual controls, including conditional panels.
  document.querySelectorAll('label:not([for])').forEach((label, index) => {
    const field = label.parentElement.querySelector('input:not([type="hidden"]), select, textarea');
    if (!field) return;
    if (!field.id) field.id = `imonitor-field-${index}`;
    label.htmlFor = field.id;
  });
  const monitorForm = document.querySelector('#monitorBuilder:not([data-tunnel-wizard])');
  if (monitorForm) {
    monitorForm.addEventListener('submit', event => {
      const mode = document.getElementById('monitorBuilderPanels')?.dataset.mode || 'simple';
      if (mode !== 'simple') return;
      const panel = [...monitorForm.querySelectorAll('[data-simple-kinds]')].find(item => !item.hidden);
      const target = panel?.querySelector('input[type="text"], textarea');
      if (!target || target.value.trim()) return;
      event.preventDefault();
      target.setCustomValidity(say('آدرس یا تنظیمات مقصد را وارد کنید.', 'Enter the target address or connection profile.'));
      target.reportValidity();
      target.addEventListener('input', () => target.setCustomValidity(''), { once: true });
    });
  }

  const sourceMode = document.getElementById('sourceIpMode');
  if (sourceMode) {
    const form = sourceMode.closest('form');
    const sourceFamily = document.getElementById('sourceIpFamily');
    const sourceProtocol = document.getElementById('sourceIpProtocol');
    const port = form.querySelector('[name="source_ip_match_port"]');
    const destination = form.querySelector('[name="source_ip_destination_ip"]');
    const source = form.querySelector('[name="source_ip_source_ip"]');
    const translate = form.querySelector('[name="source_ip_translate_ip"]');
    const updateSourceMode = () => {
      const paired = sourceMode.value === 'paired';
      sourceFamily.querySelector('[value="ipv6"]').disabled = paired;
      if (paired) sourceFamily.value = 'ipv4';
      form.querySelector('[data-source-ip-paired]').hidden = !paired;
      translate.disabled = !paired;
      const protocol = sourceProtocol.value.trim().toLowerCase();
      const transportPort = ['all', 'any', 'tcp', 'udp', '6', '17'].includes(protocol);
      port.disabled = !transportPort;
      const portLabel = form.querySelector(`label[for="${port.id}"]`);
      if (portLabel) portLabel.textContent = paired ? say('پورت مبدأ یا مقصد', 'Source or destination port') : say('پورت مقصد', 'Destination port');
      const ipv6 = sourceFamily.value === 'ipv6';
      destination.placeholder = paired ? '198.51.100.20' : ipv6 ? '2001:db8:2::/64' : '198.51.100.0/24';
      source.placeholder = ipv6 ? '2001:db8:1::10' : '203.0.113.10';
      translate.placeholder = '198.51.100.20';
      sourceProtocol.setCustomValidity(!paired && ['ah', '51'].includes(protocol) ? say('AH آدرس‌ها را احراز می‌کند و با SNAT سازگار نیست.', 'AH authenticates addresses and cannot be used with SNAT.') : '');
      document.getElementById('sourceIpModeHelp').textContent = paired
        ? say('فقط ترافیک محلی IPv4: بسته‌های خروجی به IP مقصد از IP مبدأ انتخابی ارسال می‌شوند و بسته‌های ورودی از آن IP به IP ترجمه برگشت بازنویسی می‌شوند. هر دو سرور باید قانون معکوس داشته باشند؛ این حالت SNAT معمولی نیست. پورت مبدأ یا مقصد فقط برای TCP، UDP یا all کاربرد دارد.', 'Local-origin IPv4 traffic only: outbound packets to Destination IP use the chosen Source IP; inbound packets from that IP have their source rewritten to Return Translate IP. Both peers need inverse rules. This differs from conventional SNAT. Source or destination port matching applies only to TCP, UDP, or all.')
        : say('SNAT آدرس مبدأ بسته‌های خروجی محلی یا فوروارد شده را به مقصد IP یا CIDR انتخابی تغییر می‌دهد؛ IPv4 و IPv6 پشتیبانی می‌شوند. IP مبدأ باید روی این سرور قابل استفاده باشد و مسیر برگشت به آن برسد. AH با SNAT سازگار نیست. پورت مقصد ۰ یعنی همه؛ پورت با all شامل TCP و UDP می‌شود.', 'SNAT rewrites local or forwarded outgoing packets to the chosen destination IP or CIDR, for IPv4 or IPv6. The source address must be usable by this server and have a return route. AH cannot use SNAT. Destination port 0 means all; choosing all with a port matches TCP and UDP.');
    };
    form.addEventListener('change', updateSourceMode);
    sourceProtocol.addEventListener('input', updateSourceMode);
    updateSourceMode();
  }

  const tourKey = `imonitor-tour-v2:${shell.dataset.account || 'admin'}`;
  const storage = {
    read: () => { try { return localStorage.getItem(tourKey); } catch (_) { return null; } },
    done: () => { try { localStorage.setItem(tourKey, 'done'); } catch (_) { /* The tour still closes. */ } }
  };
  const tourSteps = [
    ['overview', say('به iMonitor خوش آمدید', 'Welcome to iMonitor'), say('این پنل به شما کمک می‌کند سلامت سرویس‌ها را بررسی کنید و بین سرورها تونل بسازید. همه امکانات رایگان است. یک دور کوتاه با هم آشنا می‌شویم.', 'Check service health and connect your servers from one place. Every feature is free. Let’s take a short look around.')],
    ['overview', say('نمای کلی، نقطه شروع شما', 'Your overview'), say('تعداد مانیتورها و تونل‌ها، مصرف CPU، حافظه و شبکه این سرور را یک‌جا ببینید. برای ساخت اولین اتصال از دکمه‌های بالای صفحه شروع کنید.', 'See your monitors, tunnels, CPU, memory, and network usage together. The buttons at the top start your first check or connection.')],
    ['monitors', say('مانیتورینگ، بررسی یک سرویس', 'Monitoring checks a service'), say('برای یک وب‌سایت HTTPS، برای یک آدرس IP پینگ و برای یک پورت TCP انتخاب کنید. آدرس را وارد کنید و ذخیره کنید؛ نتیجه و تاریخچه در همین بخش دیده می‌شود.', 'Choose HTTPS for a website, ping for an IP address, or TCP for a service port. Add its address and save. Results and history appear in Monitoring.')],
    ['tunnels', say('تونل‌ها، یک فضای جداگانه', 'Tunnels have their own space'), say('راهنمای سه‌مرحله‌ای از انتخاب پروتکل تا اتصال دو سرور همراه شماست. تونل دو سمت دارد؛ تنظیمات سمت دوم را هم باید وارد کنید. راهنمای آن در مرحله آخر آماده می‌شود.', 'The three-step helper takes you from choosing a protocol to connecting two servers. A tunnel has two ends, so the second server also needs configuration. You’ll receive its setup guide before saving.')],
    ['tunnels', say('مشکل اتصال را بفهمید', 'Understand a connection problem'), say('در جدول تونل‌ها، عیب‌یابی را باز کنید. پینگ نشان می‌دهد سمت مقابل پاسخ می‌دهد یا نه؛ تست داخلی سرعت ارسال و دریافت را اندازه می‌گیرد. کلید مشترک تست باید روی هر دو سمت یکسان باشد.', 'Open Diagnostics from a tunnel’s row. Ping checks whether the other end responds; the built-in test measures upload and download. Save the same test key on both ends first.')],
    ['folders', say('مانیتورها را مرتب کنید', 'Keep things organized'), say('مانیتورهای یک پروژه یا منطقه را در پوشه قرار دهید تا در پنل و صفحه وضعیت عمومی راحت‌تر پیدا شوند.', 'Put monitors for a project or location into folders so they are easy to find in the panel and on the public status page.')],
    ['notifications', say('وقتی مشکلی پیش آمد، باخبر شوید', 'Know when something needs attention'), say('ربات تلگرام و مقصد پیام را در اطلاع‌رسانی وارد کنید و ارسال آزمایشی را امتحان کنید. چند شکست متوالی می‌تواند پیش از ارسال هشدار لازم باشد.', 'Add your Telegram bot and destination in Notifications, then send a test message. You can require repeated failures before an alert is sent.')],
    ['server-health', say('سلامت سرور و مسیر شبکه', 'Your server and network path'), say('مشخصات سیستم و نتیجه بررسی دسترسی به مقصدهای مختلف را اینجا ببینید. عدم پاسخ به یک بررسی به‌تنهایی دلیل قطع کامل مسیر نیست؛ متن نتیجه را بخوانید.', 'Review system information and reachability checks here. A missing response alone doesn’t prove that an entire path is down; read the result details.')],
    ['backups', say('یک نسخه امن از تنظیمات', 'Keep a copy of your settings'), say('قبل از تغییرهای مهم یک بکاپ بگیرید و کپی آن را خارج از سرور نگه دارید. تنظیمات مقصد و زمان‌بندی نسخه‌های بعدی در بخش بکاپ است.', 'Create a backup before important changes and keep a copy outside this server. Backup destinations and schedules live in Backups.')],
    ['network-controls', say('ابزارهای شبکه، وقتی لازم دارید', 'Network tools when you need them'), say('کنترل شبکه، IP مبدأ، پورت فورواردینگ و سوکت‌ها ابزارهای تخصصی‌تر هستند. تغییر آن‌ها می‌تواند ترافیک فعال را تحت تأثیر بگذارد؛ اول راهنما را بخوانید.', 'Network controls, source IPs, port forwarding, and sockets are more advanced tools. Changes can affect active traffic, so read the guides first.')],
    ['panel-settings', say('ظاهر و دسترسی، مطابق نیاز شما', 'Make the panel yours'), say('نام کاربری، رمز عبور، پورت، رنگ‌ها و برند صفحه وضعیت عمومی را در تنظیمات تغییر دهید. دکمه صفحه وضعیت، نمایی را نشان می‌دهد که دیگران می‌بینند.', 'Change your username, password, port, colors, and public-page branding in Panel Settings. The Public Status link shows the page visitors see.')],
    ['guide', say('همیشه یک راهنما دارید', 'Help is always here'), say('بخش راهنما، مثال‌های اتصال دو سرور و مراحل پیدا کردن خطا را دارد. از دکمه راهنما می‌توانید این آموزش را دوباره ببینید. حالا آماده‌اید شروع کنید.', 'Getting Started contains connection examples and troubleshooting steps. Use Help & Tour to replay this introduction at any time. You’re ready to begin.')]
  ];
  let activeTour = null;
  function startTour() {
    if (activeTour) return;
    const returnFocus = document.activeElement;
    const frame = document.querySelector('.frame');
    const overlay = document.createElement('div');
    overlay.className = 'tour-overlay';
    const panes = ['top', 'bottom', 'left', 'right'].map(side => {
      const pane = document.createElement('div');
      pane.className = 'tour-blur-pane';
      pane.dataset.side = side;
      pane.setAttribute('aria-hidden', 'true');
      overlay.append(pane);
      return pane;
    });
    const spotlight = document.createElement('div');
    spotlight.className = 'tour-spotlight';
    spotlight.setAttribute('aria-hidden', 'true');
    overlay.append(spotlight);
    const card = document.createElement('section');
    card.className = 'tour-card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    card.setAttribute('aria-labelledby', 'tourTitle');
    card.setAttribute('aria-describedby', 'tourDescription');
    overlay.append(card);
    document.body.append(overlay);
    const previousInert = frame ? frame.inert : false;
    if (frame) frame.inert = true;
    document.body.classList.add('tour-open');
    let step = 0;
    let highlight = null;
    let layoutFrame = 0;
    const place = (element, x, y, width, height) => {
      Object.assign(element.style, { left: `${x}px`, top: `${y}px`, width: `${Math.max(0, width)}px`, height: `${Math.max(0, height)}px` });
    };
    const position = () => {
      layoutFrame = 0;
      const width = document.documentElement.clientWidth;
      const height = window.innerHeight;
      const margin = 16;
      const gap = 18;
      const target = highlight?.getBoundingClientRect();
      const hole = target && target.width && target.height && target.right > 0 && target.left < width && target.bottom > 0 && target.top < height ? {
        left: Math.max(0, target.left - 7), top: Math.max(0, target.top - 7),
        right: Math.min(width, target.right + 7), bottom: Math.min(height, target.bottom + 7)
      } : null;
      spotlight.hidden = !hole;
      if (hole) {
        place(spotlight, hole.left, hole.top, hole.right - hole.left, hole.bottom - hole.top);
        place(panes[0], 0, 0, width, hole.top);
        place(panes[1], 0, hole.bottom, width, height - hole.bottom);
        place(panes[2], 0, hole.top, hole.left, hole.bottom - hole.top);
        place(panes[3], hole.right, hole.top, width - hole.right, hole.bottom - hole.top);
      } else {
        place(panes[0], 0, 0, width, height);
        panes.slice(1).forEach(pane => place(pane, 0, 0, 0, 0));
      }
      card.style.maxHeight = `${height - margin * 2}px`;
      const bounds = card.getBoundingClientRect();
      const clamp = (number, min, max) => Math.min(Math.max(number, min), Math.max(min, max));
      const centerX = hole ? (hole.left + hole.right) / 2 : width / 2;
      const centerY = hole ? (hole.top + hole.bottom) / 2 : height / 2;
      let left = clamp(centerX - bounds.width / 2, margin, width - bounds.width - margin);
      let top = clamp(centerY - bounds.height / 2, margin, height - bounds.height - margin);
      let side = 'floating';
      if (hole) {
        if (width - hole.right - gap - margin >= bounds.width) { left = hole.right + gap; side = 'right'; }
        else if (hole.left - gap - margin >= bounds.width) { left = hole.left - gap - bounds.width; side = 'left'; }
        else if (height - hole.bottom - gap - margin >= bounds.height) { top = hole.bottom + gap; side = 'below'; }
        else if (hole.top - gap - margin >= bounds.height) { top = hole.top - gap - bounds.height; side = 'above'; }
        else {
          const below = height - hole.bottom - gap - margin;
          const above = hole.top - gap - margin;
          const available = Math.max(below, above);
          if (available >= 180) {
            card.style.maxHeight = `${available}px`;
            top = below >= above ? hole.bottom + gap : margin;
            side = below >= above ? 'below' : 'above';
          }
        }
      }
      Object.assign(card.style, { left: `${left}px`, top: `${top}px` });
      card.dataset.placement = side;
    };
    const schedulePosition = event => {
      if (event?.type === 'resize') highlight?.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      if (!layoutFrame) layoutFrame = requestAnimationFrame(position);
    };
    const observer = new ResizeObserver(schedulePosition);
    observer.observe(card);
    const close = () => {
      highlight?.classList.remove('tour-target');
      if (frame) frame.inert = previousInert;
      document.body.classList.remove('tour-open');
      document.removeEventListener('keydown', keys);
      window.removeEventListener('resize', schedulePosition);
      window.removeEventListener('scroll', schedulePosition, true);
      window.visualViewport?.removeEventListener('resize', schedulePosition);
      observer.disconnect();
      cancelAnimationFrame(layoutFrame);
      overlay.remove();
      storage.done();
      activeTour = null;
      if (returnFocus instanceof HTMLElement) returnFocus.focus({ preventScroll: true });
    };
    const draw = () => {
      highlight?.classList.remove('tour-target');
      const [section, title, description] = tourSteps[step];
      highlight = document.querySelector(`[data-nav="${section}"]`);
      highlight?.classList.add('tour-target');
      highlight?.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      card.replaceChildren();
      const eyebrow = document.createElement('p');
      eyebrow.className = 'eyebrow';
      eyebrow.textContent = `${say('راهنمای پنل', 'PANEL GUIDE')} · ${step + 1} / ${tourSteps.length}`;
      const illustration = document.createElement('div');
      illustration.className = 'tour-illustration';
      illustration.setAttribute('aria-hidden', 'true');
      illustration.innerHTML = '<svg viewBox="0 0 72 72" fill="none"><rect x="8" y="10" width="56" height="52" rx="14" stroke="currentColor" stroke-width="1.5"/><path d="M25 10v52M8 28h56M33 40h21M33 47h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="16" cy="19" r="2" fill="currentColor"/></svg>';
      const heading = document.createElement('h2');
      heading.id = 'tourTitle';
      heading.textContent = title;
      const paragraph = document.createElement('p');
      paragraph.id = 'tourDescription';
      paragraph.textContent = description;
      const progress = document.createElement('div');
      progress.className = 'tour-progress';
      progress.setAttribute('aria-hidden', 'true');
      tourSteps.forEach((_, index) => {
        const dot = document.createElement('i');
        if (index === step) dot.className = 'is-active';
        progress.append(dot);
      });
      const actions = document.createElement('div');
      actions.className = 'tour-actions';
      const skip = document.createElement('button');
      skip.type = 'button';
      skip.className = 'ghost ghost--subtle';
      skip.textContent = say('رد کردن آموزش', 'Skip tour');
      skip.onclick = close;
      const back = document.createElement('button');
      back.type = 'button';
      back.className = 'ghost';
      back.textContent = say('قبلی', 'Back');
      back.disabled = step === 0;
      back.onclick = () => { step--; draw(); };
      const next = document.createElement('button');
      next.type = 'button';
      next.textContent = step === tourSteps.length - 1 ? say('شروع کنیم', 'Get started') : say('ادامه', 'Continue');
      next.onclick = () => { if (++step === tourSteps.length) close(); else draw(); };
      actions.append(skip, back, next);
      card.append(eyebrow, illustration, heading, paragraph, progress, actions);
      position();
      next.focus({ preventScroll: true });
    };
    const keys = event => {
      if (event.key === 'Escape') { event.preventDefault(); close(); }
      if (event.key !== 'Tab') return;
      const buttons = [...card.querySelectorAll('button:not(:disabled)')];
      if (event.shiftKey && document.activeElement === buttons[0]) {
        event.preventDefault(); buttons.at(-1).focus();
      } else if (!event.shiftKey && document.activeElement === buttons.at(-1)) {
        event.preventDefault(); buttons[0].focus();
      }
    };
    activeTour = overlay;
    document.addEventListener('keydown', keys);
    window.addEventListener('resize', schedulePosition);
    window.addEventListener('scroll', schedulePosition, true);
    window.visualViewport?.addEventListener('resize', schedulePosition);
    draw();
  }
  document.querySelectorAll('[data-start-tour]').forEach(button => button.addEventListener('click', startTour));
  // Runs once for each local browser/account; skipping marks the tour complete too.
  if (storage.read() !== 'done') window.setTimeout(startTour, 450);

  const wizard = document.querySelector('[data-tunnel-wizard]');
  if (!wizard) return;
  const field = name => wizard.querySelector(`[name="${name}"]`);
  const value = name => field(name)?.value.trim() || '';
  const steps = [...wizard.querySelectorAll('[data-wizard-step]')];
  const markers = [...wizard.querySelectorAll('[data-wizard-marker]')];
  const next = wizard.querySelector('[data-wizard-next]');
  const back = wizard.querySelector('[data-wizard-back]');
  const save = wizard.querySelector('[data-wizard-save]');
  const error = document.getElementById('tunnelWizardError');
  const protocolHelp = document.getElementById('tunnelProtocolHelp');
  const presetHelp = document.getElementById('tunnelPresetHelp');
  const secureChoice = document.getElementById('tunnelSecureProtocol');
  let preset = 'custom';
  let step = 0;
  const explanations = {
    gre: say('GRE: سریع و سبک، بدون رمزگذاری. فایروال و ارائه‌دهنده باید پروتکل IP شماره 47 را در هر دو سمت اجازه دهند.', 'GRE: lightweight and fast, without encryption. Both host and provider firewalls must allow IP protocol 47.'),
    ipv4_ip_in_ip: say('IPv4 IP-in-IP: بسته IPv4 در بسته IPv4 قرار می‌گیرد. پروتکل IP شماره 4 باید در هر دو سمت باز باشد.', 'IPv4 IP-in-IP wraps IPv4 packets in IPv4. Allow IP protocol 4 on both ends.'),
    ipip: say('IPIP در لینوکس از پروتکل IP شماره 4 استفاده می‌کند. دو سمت باید همین حالت را انتخاب کنند.', 'Linux IPIP uses IP protocol 4. Choose the same mode on both ends.'),
    ipv6_encapsulation: say('IPv6 Encapsulation: IPv6 را روی مسیر IPv4 با پروتکل 41 حمل می‌کند. برای آدرس‌های داخل تونل از IPv6 استفاده کنید.', 'IPv6 encapsulation carries IPv6 over an IPv4 path using protocol 41. Use IPv6 tunnel addresses.'),
    etherip: say('EtherIP: اتصال لایه Ethernet با پروتکل 97. پشتیبانی اینترفیس و ماژول کرنل را در هر دو سرور بررسی کنید.', 'EtherIP carries Ethernet using protocol 97. Check kernel and interface support on both servers.'),
    encap: say('IP-in-IP روی GUE/UDP: به قابلیت GUE و تنظیم پورت یکسان در سمت مقابل نیاز دارد. اجازه UDP پورت انتخابی را بررسی کنید.', 'IP-in-IP over GUE/UDP requires GUE support and matching peer ports. Allow the selected UDP port.'),
    gretap: say('GRETAP: تونل Ethernet کرنل با پروتکل GRE شماره ۴۷. مسیر IPv4 یا IPv6 و پشتیبانی ماژول کرنل در هر دو سمت لازم است.', 'GRETAP is a kernel Ethernet tunnel using GRE, IP protocol 47. Both ends need matching IPv4 or IPv6 outer addresses and kernel support.'),
    vxlan: say('VXLAN: تونل Ethernet کرنل روی UDP، پورت پیش‌فرض ۴۷۸۹. VNI و پورت باید در هر دو سمت یکسان باشند.', 'VXLAN carries Ethernet through kernel UDP, default port 4789. Use the same VNI and port on both ends.'),
    geneve: say('GENEVE: تونل Ethernet کرنل روی UDP، پورت پیش‌فرض ۶۰۸۱. VNI و پورت یکسان لازم است. این راه‌اندازی قابل‌حمل از IP مبدأ مسیر سیستم استفاده می‌کند؛ IP محلی و اینترفیس انتخابی باید با آن مسیر یکسان باشند.', 'GENEVE carries Ethernet through kernel UDP, default port 6081. Use matching VNI and port. This portable setup uses the host route’s source IP; configured Local Outer and source interface must match that route.'),
    l2tp: say('L2TPv3: شناسه‌های تونل و نشست در دو سمت باید جفت شوند. UDP برای بیشتر تنظیمات مناسب است؛ این فرم سرور PPP/L2TP VPN ایجاد نمی‌کند.', 'L2TPv3 needs paired tunnel and session IDs. UDP is appropriate for most setups. This does not create a PPP/L2TP VPN server.'),
    esp: say('ESP / XFRM: راه‌اندازی دستی دو سرور با AES-CBC و HMAC-SHA256 و کلیدهای جداگانه HKDF. رمزگذاری، روش کلید و کلید مشترک باید در دو سمت یکسان باشند. پروتکل IP شماره ۵۰ باید باز باشد. برای شروع ساده‌تر، WireGuard پیشنهاد می‌شود.', 'ESP / XFRM sets up manual peers with AES-CBC, HMAC-SHA256, and separate HKDF keys. Both ends need matching cipher, derivation, and shared secret. Allow IP protocol 50. WireGuard is the simpler secure starting point.'),
    tun: say('TUN: حامل TCP، UDP یا ICMP را در دو سمت یکسان انتخاب کنید. TCP و UDP از IP محلی تنظیم‌شده استفاده می‌کنند؛ اینترفیس مبدأ انتخابی باید با مسیر سیستم به سمت مقابل یکسان باشد. در ICMP، IP محلی و اینترفیس مبدأ باید با مسیر سیستم یا قوانین IP مبدأ هماهنگ باشند؛ برنامه مغایرت را گزارش می‌دهد. BIP قدیمی فقط حالت سازگاری UDP است.', 'TUN: choose the same TCP, UDP, or ICMP transport on both ends. TCP and UDP bind the configured local address; a selected source interface must match the host route to the peer. ICMP uses the host route: Local Outer and source interface must match that route or source-IP rules, and mismatches are reported. Legacy BIP uses UDP compatibility.'),
    ssh: say('SSH TUN: به دسترسی SSH و PermitTunnel yes در sshd سمت مقابل نیاز دارد. کلید یا رمز معتبر وارد کنید. اتصال از IP محلی تنظیم‌شده استفاده می‌کند و اینترفیس مبدأ انتخابی باید با مسیر سیستم به سمت مقابل یکسان باشد. حامل TCP ممکن است در مسیرهای پرتأخیر سرعت کمتری داشته باشد.', 'SSH TUN needs SSH access and PermitTunnel yes on the remote sshd. Enter a valid key or password. SSH binds the configured local address; a selected source interface must match the host route to the peer. TCP transport can be slower on high-latency paths.'),
    reverse_ssh: say('Reverse SSH TUN منتظر اتصال آغازشده از سمت مقابل است؛ در سرور مقابل SSH TUN را انتخاب کنید. سرویس SSH این سرور و PermitTunnel yes باید جداگانه فعال شوند. اینترفیس مبدأ انتخابی باید با مسیر برگشت سیستم به سمت مقابل یکسان باشد. آدرس‌ها و اینترفیس‌های TUN دو سمت را بررسی کنید.', 'Reverse SSH TUN receives a connection initiated by the peer; choose SSH TUN on that peer. Configure this server’s SSH service and PermitTunnel yes separately. A selected source interface must match the host return route to the peer. Check the tunnel addresses and interfaces at both ends.'),
    wireguard: say('WireGuard: تونل رمزگذاری‌شده روی UDP. کلید عمومی سمت مقابل لازم است؛ کلید خصوصی هر سرور باید فقط روی همان سرور بماند.', 'WireGuard encrypts traffic over UDP. You need the peer’s public key. Keep each private key only on its own server.')
  };
  function updateProtocol() {
    const protocol = value('tunnel_protocol');
    const creating = value('auto_create_interface') !== '0';
    ['outer_remote', 'inner_local_cidr', 'inner_probe'].forEach(name => {
      const input = field(name);
      if (input) input.required = creating || (name === 'inner_local_cidr' && !!value('speedtest_token'));
    });
    protocolHelp.textContent = explanations[protocol] || '';
    wizard.querySelectorAll('[data-tunnel-protocols]').forEach(container => {
      const show = container.dataset.tunnelProtocols.split(',').includes(protocol);
      container.hidden = !show;
      container.querySelectorAll('input, select, textarea').forEach(control => control.disabled = !show);
    });
    const lanes = wizard.querySelector('[data-tun-lanes]');
    if (lanes) {
      lanes.hidden = protocol !== 'tun' || !['tcp', 'icmp'].includes(value('tun_transport'));
      field('tun_lanes').disabled = lanes.hidden;
    }
    field('mtu').min = value('inner_local_cidr').includes(':') ? '1280' : '576';
    const peerKey = field('wireguard_peer_public_key');
    if (peerKey) peerKey.required = creating && protocol === 'wireguard';
    const username = field('ssh_username');
    if (username) username.required = creating && (protocol === 'ssh' || protocol === 'reverse_ssh');
    const espCipher = field('esp_cipher');
    const espDerivation = field('esp_key_derivation');
    const savedLegacyEsp = !!value('original_check_id') && wizard.dataset.savedEspCipher === 'legacy_aes_gcm';
    espCipher?.setCustomValidity(creating && protocol === 'esp' && value('esp_cipher') !== 'aes_cbc_hmac_sha256' && !savedLegacyEsp
      ? say('AES-GCM با کلید ثابت خودکار ساخته نمی‌شود. هر دو سمت را به AES-CBC/HMAC و HKDF مهاجرت دهید یا حالت بررسی اینترفیس با مدیریت IKE بیرونی را انتخاب کنید.', 'Static-key AES-GCM cannot be created automatically. Migrate both peers to AES-CBC/HMAC with HKDF, or check an externally IKE-managed interface.') : '');
    espDerivation?.setCustomValidity(protocol === 'esp' && value('esp_cipher') === 'aes_cbc_hmac_sha256' && value('esp_key_derivation') !== 'hkdf_sha256'
      ? say('ESP خودکار به HKDF-SHA256 و کلید مشترک امن در هر دو سمت نیاز دارد.', 'Automatic ESP requires HKDF-SHA256 and a secure shared secret on both ends.') : '');
    const key = field('tunnel_key');
    if (key) {
      const secure = creating && protocol === 'esp' && value('esp_key_derivation') === 'hkdf_sha256';
      key.required = secure;
      key.minLength = secure ? 32 : 0;
      key.maxLength = secure ? 128 : 256;
      key.pattern = secure ? '[!-~]{32,128}' : '.*';
      key.placeholder = secure ? say('کلید مشترک امن حداقل ۳۲ نویسه', 'Shared secret with at least 32 characters') : '100 or 0x100';
    }
    const advanced = wizard.querySelector('.tunnel-advanced-panel');
    if (advanced) advanced.hidden = ![...advanced.querySelectorAll('[data-tunnel-protocols]')].some(container => !container.hidden);
    updatePeerGuide();
  }
  function updatePeerGuide() {
    const protocol = value('tunnel_protocol');
    const local = value('inner_local_cidr');
    const [localIp, prefix] = local.split('/');
    const peer = value('inner_probe');
    const missing = say('[راهنما: IP عمومی این سرور را وارد کنید]', '[Enter this server’s public IP]');
    const lines = [
      say('روی سرور B در بخش تونل‌ها وارد کنید:', 'On server B, open Tunnels and enter:'),
      `${say('پروتکل', 'Protocol')}: ${protocol === 'ssh' ? 'reverse_ssh' : protocol === 'reverse_ssh' ? 'ssh' : protocol}`,
      `${say('IP عمومی مقابل', 'Peer public IP')}: ${value('local_outer') || missing}`,
      `${say('IP عمومی محلی', 'Local public IP')}: ${value('outer_remote') || '—'}`,
      `${say('آدرس محلی داخل تونل', 'Local tunnel IP / CIDR')}: ${peer || '—'}${prefix ? '/' + prefix : ''}`,
      `${say('IP مقابل داخل تونل', 'Peer tunnel IP')}: ${localIp || '—'}`
    ];
    const paired = [['tunnel_key','GRE key / ESP secret'], ['tun_transport','TUN transport'], ['transport_port','Transport port'], ['mtu','MTU'], ['ttl','TTL / Hop limit'], ['traffic_class','Traffic class'], ['vni','VNI'], ['tun_lanes','Parallel TUN streams']];
    paired.forEach(([name, label]) => { const input = field(name); if (input && !input.disabled && value(name)) lines.push(`${label}: ${value(name)}`); });
    if (protocol === 'l2tp') {
      lines.push(`Tunnel ID: ${value('l2tp_peer_tunnel_id') || say('خودکار', 'automatic')}`,
        `Peer tunnel ID: ${value('l2tp_tunnel_id') || say('خودکار', 'automatic')}`,
        `Session ID: ${value('l2tp_peer_session_id') || say('خودکار', 'automatic')}`,
        `Peer session ID: ${value('l2tp_session_id') || say('خودکار', 'automatic')}`,
        `Encapsulation: ${value('l2tp_encapsulation') || 'udp'}`);
    }
    if (protocol === 'wireguard') {
      lines.push(say('کلید عمومی سرور A را در Peer Public Key سرور B وارد کنید. کلید خصوصی A را کپی نکنید.', 'Put server A’s public key into Peer Public Key on B. Do not copy A’s private key.'),
        say('کلیدهای هر دو سرور را از راهنمای WireGuard در بخش آموزش بسازید.', 'Generate both servers’ key pairs using the WireGuard guide in Getting Started.'),
        `Allowed IPs: ${localIp ? localIp + (localIp.includes(':') ? '/128' : '/32') : '—'}`);
      if (value('wireguard_preshared_key')) lines.push(`Preshared key: ${value('wireguard_preshared_key')}`);
    }
    if (protocol === 'ssh' || protocol === 'reverse_ssh') lines.push(say('SSH TUN در سمت آغازکننده و Reverse SSH TUN در سمت دریافت‌کننده انتخاب شود. سرویس SSH و PermitTunnel yes را در سمت دریافت‌کننده فعال کنید.', 'Choose SSH TUN on the initiating server and Reverse SSH TUN on the receiving server. Enable the receiving server’s SSH service and PermitTunnel yes.'));
    if (protocol === 'esp') lines.push(`ESP cipher: ${value('esp_cipher') || 'aes_cbc_hmac_sha256'}`, `ESP key derivation: ${value('esp_key_derivation') || 'hkdf_sha256'}`);
    if (['vxlan', 'geneve'].includes(protocol)) {
      if (!value('vni')) lines.push('VNI: 42');
      if (!value('transport_port')) lines.push(`Transport port: ${protocol === 'vxlan' ? '4789' : '6081'}`);
    }
    if (value('speedtest_token')) lines.push(`Speed-test key: ${value('speedtest_token')}`, `Speed-test port: ${value('speedtest_port') || '5201'}`);
    lines.push('', say('پروتکل یا پورت انتخابی را در فایروال هر دو سرور اجازه دهید؛ سپس هر دو سمت را ذخیره کنید.', 'Allow the chosen protocol or port in both firewalls, then save both ends.'));
    document.getElementById('tunnelPeerGuide').textContent = lines.join('\n');
  }
  function setPreset(name, apply = false) {
    preset = name;
    wizard.querySelectorAll('[data-tunnel-preset]').forEach(button => {
      button.classList.toggle('is-selected', button.dataset.tunnelPreset === name);
      button.setAttribute('aria-pressed', String(button.dataset.tunnelPreset === name));
    });
    wizard.querySelector('[data-secure-preset]').hidden = name !== 'secure';
    const messages = {
      gaming: say('حامل UDP/GUE در کرنل، MTU ۱۴۰۰ و TTL ۶۴. مسیر بیرونی و داخل تونل IPv4 است. رمزگذاری ندارد؛ باز بودن پورت و MTU مناسب مسیر را بررسی کنید. تأخیر واقعی به مسیر شما بستگی دارد.', 'Kernel UDP/GUE with MTU 1400 and TTL 64. Outer and tunnel addresses must be IPv4. This is unencrypted; check firewall ports and path MTU. Actual latency depends on your route.'),
      secure: say('شروع پیشنهادی WireGuard روی UDP است. گزینه ESP شماره ۵۰ از AES-CBC/HMAC و کلیدهای HKDF استفاده می‌کند. کلیدهای سمت مقابل و تنظیمات فایروال قبل از اتصال لازم‌اند.', 'Start with WireGuard over UDP. The ESP protocol 50 alternative uses AES-CBC/HMAC with HKDF keys. Exchange peer keys and check both firewalls before connecting.'),
      custom: say('پروتکل و تنظیمات را خودتان انتخاب کنید. تغییر این گزینه به‌تنهایی تنظیمات فعلی را پاک نمی‌کند.', 'Choose the protocol and settings yourself. Selecting Custom keeps your current values.')
    };
    presetHelp.textContent = messages[name];
    if (apply && name === 'gaming') {
      field('tunnel_protocol').value = 'encap';
      field('mtu').value = '1400'; field('ttl').value = '64'; field('traffic_class').value = '0';
    } else if (apply && name === 'secure') {
      field('tunnel_protocol').value = secureChoice.value;
      if (secureChoice.value === 'esp') {
        field('esp_key_derivation').value = 'hkdf_sha256';
        field('esp_cipher').value = 'aes_cbc_hmac_sha256';
      }
    }
    if (apply) {
      field('tunnel_protocol').dispatchEvent(new Event('change', { bubbles: true }));
      updateProtocol();
    }
  }
  wizard.querySelectorAll('[data-tunnel-preset]').forEach(button => button.addEventListener('click', () => setPreset(button.dataset.tunnelPreset, true)));
  secureChoice.addEventListener('change', () => setPreset('secure', true));
  field('tunnel_protocol').addEventListener('change', event => { if (event.isTrusted) setPreset('custom'); });
  function showStep(index, focus = true) {
    step = Math.max(0, Math.min(steps.length - 1, index));
    steps.forEach((panel, i) => panel.hidden = i !== step);
    markers.forEach((marker, i) => {
      marker.classList.toggle('is-complete', i < step);
      if (i === step) marker.setAttribute('aria-current', 'step'); else marker.removeAttribute('aria-current');
    });
    back.disabled = step === 0;
    next.hidden = step === steps.length - 1;
    save.hidden = step !== steps.length - 1;
    error.hidden = true;
    updatePeerGuide();
    if (focus) steps[step].querySelector('input:not([type="hidden"]), select, button, summary')?.focus();
  }
  function validateStep(index) {
    const invalid = [...steps[index].querySelectorAll('input, select, textarea')].find(control => !control.disabled && !control.checkValidity());
    if (invalid) { showStep(index); invalid.reportValidity(); return false; }
    if (index === 1) {
      const local = value('inner_local_cidr').split('/')[0];
      if (local && local === value('inner_probe')) {
        error.textContent = say('آدرس دو سمت داخل تونل باید متفاوت باشند.', 'The two ends need different tunnel IP addresses.');
        error.hidden = false; return false;
      }
    }
    return true;
  }
  next.addEventListener('click', () => { if (validateStep(step)) showStep(step + 1); });
  back.addEventListener('click', () => showStep(step - 1));
  // Prevent Enter from saving early; final validation visits the relevant step.
  wizard.noValidate = true;
  wizard.addEventListener('submit', event => {
    if (step < steps.length - 1) { event.preventDefault(); if (validateStep(step)) showStep(step + 1); return; }
    for (let i = 0; i < steps.length; i++) if (!validateStep(i)) { event.preventDefault(); return; }
    save.disabled = true;
    save.textContent = say('در حال ذخیره…', 'Saving…');
  });
  wizard.addEventListener('input', updatePeerGuide);
  wizard.addEventListener('change', updateProtocol);
  wizard.addEventListener('reset', () => {
    delete wizard.dataset.savedEspCipher;
    window.setTimeout(() => { setPreset('custom'); updateProtocol(); showStep(0); }, 0);
  });
  wizard.addEventListener('imonitor:edit', () => { setPreset('custom'); updateProtocol(); showStep(0); });
  function generateSecret(target) {
    if (!window.crypto?.getRandomValues) {
      error.textContent = say('مرورگر تولید کلید امن را پشتیبانی نمی‌کند. یک کلید تصادفی حداقل ۳۲ نویسه‌ای وارد کنید.', 'This browser cannot generate a secure key. Enter a random key with at least 32 characters.');
      error.hidden = false; return;
    }
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    field(target).value = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
    updateProtocol();
  }
  wizard.querySelector('[data-generate-speedtest-token]').addEventListener('click', () => generateSecret('speedtest_token'));
  wizard.querySelector('[data-generate-esp-key]').addEventListener('click', () => generateSecret('tunnel_key'));
  wizard.querySelector('[data-copy-peer-guide]').addEventListener('click', async () => {
    const text = document.getElementById('tunnelPeerGuide').textContent;
    const status = document.getElementById('tunnelPeerCopyStatus');
    try {
      await navigator.clipboard.writeText(text);
      status.textContent = say('راهنما کپی شد. آن را خصوصی به سمت مقابل منتقل کنید.', 'Guide copied. Share it privately with the other server’s administrator.');
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents(document.getElementById('tunnelPeerGuide'));
      window.getSelection()?.removeAllRanges(); window.getSelection()?.addRange(range);
      status.textContent = say('متن انتخاب شد؛ از گزینه کپی مرورگر استفاده کنید.', 'Guide selected. Use your browser’s Copy command.');
    }
  });
  setPreset('custom');
  updateProtocol();
  showStep(0, false);
})();
