(() => {
  const monitorForm = document.getElementById('monitorBuilder');
  const kindSelect = document.getElementById('monitorKind');
  const labelInput = document.getElementById('monitorLabel');
  const idInput = document.getElementById('monitorCheckId');
  const originalCheckIdInput = document.getElementById('monitorOriginalCheckId');
  const simpleV2rayTypeSelect = document.getElementById('simpleV2rayProtocolType');
  const v2rayTypeSelect = document.getElementById('v2rayProtocolType');
  const v2rayEntrySelect = document.getElementById('v2rayLocalEntryType');
  const v2rayImportInput = document.getElementById('v2rayProfileImport');
  const builderModeLabel = document.getElementById('monitorBuilderModeLabel');
  const resetBuilderButton = document.getElementById('monitorFormReset');
  const monitorBuilderView = document.getElementById('monitorBuilderView');
  const monitorBuilderPanels = document.getElementById('monitorBuilderPanels');
  const monitorBuilderViewButtons = Array.from(document.querySelectorAll('[data-builder-view-trigger]'));
  const brandingForm = document.getElementById('brandingSettingsForm');
  const brandingLogoUpload = document.getElementById('brandingLogoUpload');
  const brandingLogoUploadData = document.getElementById('brandingLogoUploadData');
  const brandingLogoUploadName = document.getElementById('brandingLogoUploadName');
  const brandingFaviconUpload = document.getElementById('brandingFaviconUpload');
  const brandingFaviconUploadData = document.getElementById('brandingFaviconUploadData');
  const brandingFaviconUploadName = document.getElementById('brandingFaviconUploadName');
  const simpleTunnelProtocolSelect = document.getElementById('simpleTunnelProtocolSelect');
  const tunnelProtocolSelect = document.getElementById('tunnelProtocolSelect');
  const tunnelInterfaceInput = document.getElementById('tunnelInterfaceInput');
  const tunnelLocalOuterSelect = document.getElementById('tunnelLocalOuter');
  const tunnelSourceInterfaceSelect = document.getElementById('tunnelSourceInterface');
  const forwardProtocolSelect = document.getElementById('forwardProtocolSelect');
  const themePresetSelect = document.querySelector('select[name="theme_preset"]');
  const livePanel = document.getElementById('systemMetricsPanel');
  const analyticsModal = document.getElementById('monitorAnalyticsModal');
  const analyticsTitle = document.getElementById('analyticsTitle');
  const analyticsSubtitle = document.getElementById('analyticsSubtitle');
  const analyticsFrom = document.getElementById('analyticsFrom');
  const analyticsTo = document.getElementById('analyticsTo');
  const analyticsApply = document.getElementById('analyticsApply');
  const analyticsStats = document.getElementById('analyticsStats');
  const analyticsRows = document.getElementById('analyticsRows');
  const analyticsChart = document.getElementById('analyticsChart');
  const analyticsChartEmpty = document.getElementById('analyticsChartEmpty');
  const analyticsExportCsv = document.getElementById('analyticsExportCsv');
  const analyticsExportPdf = document.getElementById('analyticsExportPdf');
  const analyticsExportXlsx = document.getElementById('analyticsExportXlsx');
  const tunnelDiagModal = document.getElementById('tunnelDiagnosticsModal');
  const tunnelDiagTitle = document.getElementById('tunnelDiagTitle');
  const tunnelDiagSubtitle = document.getElementById('tunnelDiagSubtitle');
  const tunnelDiagRun = document.getElementById('tunnelDiagRun');
  const tunnelDiagMeta = document.getElementById('tunnelDiagMeta');
  const tunnelDiagPingGauge = document.getElementById('tunnelDiagPingGauge');
  const tunnelDiagPingText = document.getElementById('tunnelDiagPingText');
  const tunnelDiagPingRaw = document.getElementById('tunnelDiagPingRaw');
  const tunnelDiagUploadGauge = document.getElementById('tunnelDiagUploadGauge');
  const tunnelDiagUploadText = document.getElementById('tunnelDiagUploadText');
  const tunnelDiagUploadRaw = document.getElementById('tunnelDiagUploadRaw');
  const tunnelDiagDownloadGauge = document.getElementById('tunnelDiagDownloadGauge');
  const tunnelDiagDownloadText = document.getElementById('tunnelDiagDownloadText');
  const tunnelDiagDownloadRaw = document.getElementById('tunnelDiagDownloadRaw');
  // Fixed dialogs must escape cards with transforms/backdrop filters that form containing blocks.
  const dialogState = new WeakMap();
  let activeDialog = null;
  document.querySelectorAll('.dialog-shell').forEach(modal => {
    document.body.append(modal);
    const card = modal.querySelector('.dialog-card');
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    card.tabIndex = -1;
    const title = card.querySelector('h3[id]');
    if (title) card.setAttribute('aria-labelledby', title.id);
  });
  const dialogControls = modal => [...modal.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]')]
    .filter(control => control.getClientRects().length);
  const showDialog = (modal, trigger) => {
    const previous = dialogState.get(modal);
    if (previous?.timer) window.clearTimeout(previous.timer);
    const frame = document.querySelector('.frame');
    dialogState.set(modal, { trigger, frame, wasInert: frame?.inert || false, timer: null });
    if (frame) frame.inert = true;
    activeDialog = modal;
    modal.classList.remove('is-closing');
    modal.hidden = false;
    document.body.classList.add('dialog-open');
    requestAnimationFrame(() => {
      modal.classList.add('is-visible');
      (dialogControls(modal)[0] || modal.querySelector('.dialog-card')).focus({ preventScroll: true });
    });
  };
  const hideDialog = modal => {
    if (modal.hidden || modal.classList.contains('is-closing')) return;
    modal.classList.remove('is-visible');
    modal.classList.add('is-closing');
    const state = dialogState.get(modal);
    const timer = window.setTimeout(() => {
      modal.hidden = true;
      modal.classList.remove('is-closing');
      if (activeDialog === modal) {
        activeDialog = null;
        document.body.classList.remove('dialog-open');
        if (state?.frame) state.frame.inert = state.wasInert;
        state?.trigger?.focus({ preventScroll: true });
      }
    }, 220);
    if (state) state.timer = timer;
  };
  document.addEventListener('keydown', event => {
    if (event.key !== 'Tab' || !activeDialog) return;
    const controls = dialogControls(activeDialog);
    if (!controls.length) { event.preventDefault(); return; }
    if (event.shiftKey && document.activeElement === controls[0]) {
      event.preventDefault(); controls.at(-1).focus();
    } else if (!event.shiftKey && document.activeElement === controls.at(-1)) {
      event.preventDefault(); controls[0].focus();
    }
  });
  let idManuallyEdited = false;
  const analyticsState = {
    checkId: '',
    label: '',
    fromUnix: 0,
    toUnix: 0,
    minUnix: 0,
    maxUnix: 0
  };
  const tunnelDiagState = {
    checkId: '',
    label: '',
    jobId: '',
    pollHandle: null,
    pollInFlight: false
  };
  let livePanelInFlight = false;

  const slugify = (value) => value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  const detectV2rayImportType = (value) => {
    const text = (value || '').trim().toLowerCase();
    if (!text) return null;
    if (text.startsWith('vmess://')) return { protocol: 'vmess', entry: 'direct' };
    if (text.startsWith('vless://')) return { protocol: 'vless', entry: 'direct' };
    if (text.startsWith('trojan://')) return { protocol: 'trojan', entry: 'direct' };
    if (text.startsWith('ss://')) return { protocol: 'shadowsocks', entry: 'direct' };
    if (text.startsWith('socks://') || text.startsWith('socks5://')) {
      return { protocol: 'socks5', entry: 'socks5' };
    }
    if (text.startsWith('http://')) return { protocol: 'http', entry: 'http' };
    if (text.startsWith('https://')) return { protocol: 'https', entry: 'https' };
    if (text.includes('[interface]') && text.includes('[peer]')) {
      return { protocol: 'wireguard', entry: 'direct' };
    }
    return null;
  };

  const defaultTunnelInterfaceName = (protocol, monitorId) => {
    if (protocol === 'ssh' || protocol === 'reverse_ssh') {
      let hash = 2166136261 >>> 0;
      const seed = String(monitorId || 'monitor');
      for (const character of seed) {
        hash ^= character.charCodeAt(0);
        hash = Math.imul(hash, 16777619) >>> 0;
      }
      const unit = Math.max(10, hash % 4000);
      return `tun${unit}`;
    }
    const prefixes = {
      gre: 'gre',
      ipv4_ip_in_ip: 'ipip',
      ipip: 'ipip',
      ipv6_encapsulation: 'sit',
      etherip: 'ethr',
      encap: 'encp',
      l2tp: 'l2tp',
      esp: 'xfrm',
      tun: 'tun',
      ssh: 'tun',
      reverse_ssh: 'tun',
      wireguard: 'wg'
    };
    const prefix = prefixes[protocol];
    if (!prefix) return '';
    let hash = 2166136261 >>> 0;
    const seed = String(monitorId || 'monitor');
    for (const character of seed) {
      hash ^= character.charCodeAt(0);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    return `${prefix}${(hash & 0x00ffffff).toString(16).padStart(6, '0')}`;
  };

  const setFieldsDisabled = (container, disabled) => {
    container.querySelectorAll('input, select, textarea').forEach((field) => {
      if (field.name === 'return_to' || field.name === 'original_check_id') return;
      field.disabled = disabled;
    });
  };

  const updateV2raySections = () => {
    if (!v2rayTypeSelect) return;
    const protocol = v2rayTypeSelect.value || 'vless';
    const nativeProxy = ['socks5', 'http', 'https'].includes(protocol);
    const wireguard = protocol === 'wireguard';
    const xrayFamily = !nativeProxy && !wireguard;

    document.querySelectorAll('[data-v2ray-section]').forEach((section) => {
      const sectionName = section.getAttribute('data-v2ray-section');
      const visible =
        (sectionName === 'proxy' && !wireguard) ||
        (sectionName === 'xray' && xrayFamily) ||
        (sectionName === 'wireguard' && wireguard);
      section.hidden = !visible;
      setFieldsDisabled(section, !visible);
    });

    if (v2rayEntrySelect) {
      if (nativeProxy) {
        v2rayEntrySelect.value = protocol;
      } else if (wireguard) {
        v2rayEntrySelect.value = 'direct';
      }
    }
  };

  const setMonitorBuilderView = (mode) => {
    const nextMode = mode === 'advanced' ? 'advanced' : 'simple';
    if (monitorBuilderView) {
      monitorBuilderView.dataset.mode = nextMode;
    }
    if (monitorBuilderPanels) {
      monitorBuilderPanels.dataset.mode = nextMode;
    }
    monitorBuilderViewButtons.forEach((button) => {
      const active = button.getAttribute('data-builder-view-trigger') === nextMode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
  };

  const updateTunnelProtocolFields = () => {
    const protocol = ((tunnelProtocolSelect && tunnelProtocolSelect.value)
      || (simpleTunnelProtocolSelect && simpleTunnelProtocolSelect.value)
      || 'gre').toLowerCase();
    document.querySelectorAll('[data-tunnel-protocols]').forEach((field) => {
      const protocols = (field.getAttribute('data-tunnel-protocols') || '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean);
      const visible = protocols.includes(protocol);
      field.hidden = !visible;
      setFieldsDisabled(field, !visible);
    });
  };

  const updateBuilder = () => {
    if (!kindSelect) return;
    const kind = kindSelect.value || 'https';
    document.querySelectorAll('[data-simple-kinds]').forEach((panel) => {
      const kinds = (panel.getAttribute('data-simple-kinds') || '').split(',');
      const visible = kinds.includes(kind);
      panel.hidden = !visible;
      setFieldsDisabled(panel, !visible);
    });
    document.querySelectorAll('[data-kinds]').forEach((panel) => {
      const kinds = (panel.getAttribute('data-kinds') || '').split(',');
      const visible = kinds.includes(kind);
      panel.hidden = !visible;
      setFieldsDisabled(panel, !visible);
    });
    updateV2raySections();
    syncTunnelInterfaceSuggestion();
    updateTunnelProtocolFields();
  };

  const updateForwardProtocolFields = () => {
    if (!forwardProtocolSelect) return;
    const protocol = (forwardProtocolSelect.value || 'tcp').toLowerCase();
    const hidePorts = protocol === 'icmp';
    document.querySelectorAll('[data-forward-fields]').forEach((field) => {
      field.hidden = false;
      setFieldsDisabled(field, false);
    });
    document.querySelectorAll('[data-forward-port-fields]').forEach((field) => {
      field.hidden = hidePorts;
      setFieldsDisabled(field, hidePorts);
    });
  };

  const setInputValue = (name, value) => {
    document.querySelectorAll(`[name="${name}"]`).forEach((field) => {
      if (field.disabled) return;
      field.value = value == null ? '' : String(value);
    });
  };

  const setBooleanValue = (name, value) => {
    setInputValue(name, value ? '1' : '0');
  };

  const syncSimpleMirrorField = (simpleName, targetName, afterSync) => {
    const simpleField = document.querySelector(`[name="${simpleName}"]`);
    if (!simpleField) return;
    const copyValue = () => {
      setInputValue(targetName, simpleField.value);
      if (typeof afterSync === 'function') {
        afterSync();
      }
    };
    simpleField.addEventListener('input', copyValue);
    simpleField.addEventListener('change', copyValue);
  };

  const headersToTextarea = (headers) => {
    if (!headers || typeof headers !== 'object') return '';
    return Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\n');
  };

  const joinNumberList = (value) => Array.isArray(value) ? value.join(',') : '';
  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  const resetMonitorEditor = () => {
    if (monitorForm) {
      monitorForm.reset();
    }
    if (originalCheckIdInput) {
      originalCheckIdInput.value = '';
    }
    if (builderModeLabel) {
      builderModeLabel.textContent = monitorForm?.hasAttribute('data-tunnel-wizard') ? (document.documentElement.lang === 'fa' ? 'یک تونل جدید بسازید' : 'Create a new connection') : '@@builder_create@@';
    }
    idManuallyEdited = false;
    if (kindSelect) {
      kindSelect.value = monitorForm?.hasAttribute('data-tunnel-wizard') ? 'tunnel' : 'https';
    }
    if (tunnelSourceInterfaceSelect) {
      tunnelSourceInterfaceSelect.dataset.userLocked = '';
    }
    if (tunnelInterfaceInput) {
      tunnelInterfaceInput.dataset.userLocked = '';
    }
    setMonitorBuilderView('simple');
    updateBuilder();
    updateForwardProtocolFields();
    syncTunnelSourceInterfaceFromOuter();
  };

  const applyThemePreset = () => {
    if (!themePresetSelect) return;
    const option = themePresetSelect.options[themePresetSelect.selectedIndex];
    if (!option || option.value === 'custom') return;
    const palette = {
      primary_color: option.dataset.primary || '',
      secondary_color: option.dataset.secondary || '',
      background_color: option.dataset.background || ''
    };
    Object.entries(palette).forEach(([name, value]) => {
      const textInput = document.querySelector(`input[name="${name}"]`);
      const colorInput = document.querySelector(`[data-sync-color="${name}"]`);
      if (textInput) textInput.value = value;
      if (colorInput) colorInput.value = value;
    });
  };

  const syncColorInputs = () => {
    document.querySelectorAll('[data-sync-color]').forEach((picker) => {
      const targetName = picker.getAttribute('data-sync-color');
      const textInput = targetName ? document.querySelector(`input[name="${targetName}"]`) : null;
      if (!textInput) return;
      picker.addEventListener('input', () => {
        textInput.value = picker.value;
        if (themePresetSelect) themePresetSelect.value = 'custom';
      });
      textInput.addEventListener('input', () => {
        if (/^#[0-9a-fA-F]{6}$/.test(textInput.value.trim())) {
          picker.value = textInput.value.trim();
        }
        if (themePresetSelect) themePresetSelect.value = 'custom';
      });
    });
  };

  const ensureSelectOption = (select, value, label) => {
    if (!select || value == null || value === '') return;
    let option = Array.from(select.options).find((candidate) => candidate.value === String(value));
    if (!option) {
      option = document.createElement('option');
      option.value = String(value);
      option.textContent = label || String(value);
      option.dataset.injected = '1';
      select.appendChild(option);
    }
    select.value = String(value);
  };

  const syncTunnelSourceInterfaceFromOuter = () => {
    if (!tunnelLocalOuterSelect || !tunnelSourceInterfaceSelect) return;
    if (tunnelSourceInterfaceSelect.dataset.userLocked === '1' && tunnelSourceInterfaceSelect.value) {
      return;
    }
    const selectedOption = tunnelLocalOuterSelect.options[tunnelLocalOuterSelect.selectedIndex];
    const inferredInterface = selectedOption ? (selectedOption.getAttribute('data-interface') || '') : '';
    if (!inferredInterface) {
      if (tunnelSourceInterfaceSelect.dataset.userLocked !== '1') {
        tunnelSourceInterfaceSelect.value = '';
      }
      return;
    }
    ensureSelectOption(tunnelSourceInterfaceSelect, inferredInterface, inferredInterface);
    tunnelSourceInterfaceSelect.value = inferredInterface;
  };

  const syncTunnelInterfaceSuggestion = () => {
    if (!tunnelInterfaceInput || !tunnelProtocolSelect) return;
    const generated = defaultTunnelInterfaceName(
      tunnelProtocolSelect.value || 'gre',
      idInput ? idInput.value : ''
    );
    tunnelInterfaceInput.placeholder = generated || 'auto';
    tunnelInterfaceInput.dataset.autoValue = generated;
    if (!generated) {
      if (tunnelInterfaceInput.dataset.userLocked !== '1') {
        tunnelInterfaceInput.value = '';
      }
      return;
    }
    if (tunnelInterfaceInput.dataset.userLocked !== '1' || !tunnelInterfaceInput.value.trim()) {
      tunnelInterfaceInput.value = generated;
      tunnelInterfaceInput.dataset.userLocked = '';
    }
  };

  const readFileAsDataUrl = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(new Error('@@branding_upload_decode_error@@'));
    reader.readAsDataURL(file);
  });

  const loadImageElement = (dataUrl) => new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error('@@branding_upload_canvas_error@@'));
    image.src = dataUrl;
  });

  const normalizeBrandingUpload = async (file, kind) => {
    const mime = (file.type || '').toLowerCase();
    const lowerName = (file.name || '').toLowerCase();
    if (!mime.startsWith('image/') && !/\.(png|jpe?g|gif|webp|bmp|svg|ico)$/i.test(lowerName)) {
      throw new Error('@@branding_upload_image_only@@');
    }
    if (file.size > 8 * 1024 * 1024) {
      throw new Error('@@branding_upload_too_large@@');
    }

    const rawDataUrl = await readFileAsDataUrl(file);
    if (kind === 'favicon' && (lowerName.endsWith('.ico') || mime.includes('icon'))) {
      return rawDataUrl;
    }

    const image = await loadImageElement(rawDataUrl);
    const naturalWidth = image.naturalWidth || image.width || 1;
    const naturalHeight = image.naturalHeight || image.height || 1;
    const maxSide = kind === 'favicon' ? 256 : 1024;
    const ratio = Math.min(1, maxSide / Math.max(naturalWidth, naturalHeight));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(naturalWidth * ratio));
    canvas.height = Math.max(1, Math.round(naturalHeight * ratio));
    const context = canvas.getContext('2d');
    if (!context) {
      throw new Error('@@branding_upload_canvas_error@@');
    }
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/png');
  };

  const prepareBrandingUpload = async (fileInput, dataInput, nameInput, kind) => {
    if (!dataInput || !nameInput) return;
    dataInput.value = '';
    nameInput.value = '';
    const file = fileInput && fileInput.files ? fileInput.files[0] : null;
    if (!file) return;
    dataInput.value = await normalizeBrandingUpload(file, kind);
    nameInput.value = file.name || `${kind}.png`;
  };

  const loadMonitorIntoEditor = (button) => {
    if (!monitorForm) return;
    let definition = null;
    try {
      definition = JSON.parse(button.dataset.editCheck || '{}');
    } catch (_error) {
      return;
    }

    resetMonitorEditor();
    const kind = (definition.kind || 'https').toLowerCase() === 'v2ray_simulation'
      ? 'v2ray'
      : (definition.kind || 'https').toLowerCase();

    if (builderModeLabel) {
      builderModeLabel.textContent = '@@builder_edit_prefix@@: ' + (button.dataset.editLabel || definition.id || '');
    }
    if (labelInput) {
      labelInput.value = button.dataset.editLabel || '';
    }
    if (idInput) {
      idInput.value = definition.id || '';
    }
    if (originalCheckIdInput) {
      originalCheckIdInput.value = definition.id || '';
    }
    setBooleanValue('enabled', button.dataset.editEnabled === '1');
    setBooleanValue('public_visible', button.dataset.editPublic === '1');
    setInputValue('ip_version', definition.ip_version || 'any');
    setInputValue('timeout_ms', definition.timeout_ms || 3000);
    setInputValue('interval_secs', definition.interval_secs || 60);

    if (kindSelect) {
      kindSelect.value = kind;
    }
    updateBuilder();
    setMonitorBuilderView('advanced');

    switch (kind) {
      case 'icmp':
        setInputValue('target', definition.target);
        setInputValue('simple_target', definition.target);
        break;
      case 'tcp':
      case 'ssh':
      case 'sftp':
      case 'rdp':
      case 'ftp':
        setInputValue('target', definition.target);
        setInputValue('simple_target', definition.target);
        setInputValue('port', definition.port);
        setInputValue('simple_port', definition.port);
        setInputValue('expect_banner_prefix', definition.expect_banner_prefix || '');
        setInputValue('username', definition.username || '');
        setInputValue('password', definition.password || '');
        break;
      case 'udp':
        setInputValue('target', definition.target);
        setInputValue('simple_target', definition.target);
        setInputValue('port', definition.port);
        setInputValue('simple_port', definition.port);
        setInputValue('udp_payload', definition.payload || '');
        setBooleanValue('expect_response', Boolean(definition.expect_response));
        setInputValue('response_contains', definition.response_contains || '');
        break;
      case 'http':
      case 'https':
        setInputValue('host', definition.host || '');
        setInputValue('simple_host', definition.host || '');
        setInputValue('connect_host', definition.connect_host || '');
        setInputValue('host_header', definition.host_header || '');
        setInputValue('tls_server_name', definition.tls_server_name || '');
        setInputValue('port', definition.port || '');
        setInputValue('method', definition.method || 'GET');
        setInputValue('path', definition.path || '/');
        setInputValue('expected_status', joinNumberList(definition.expected_status));
        setInputValue('body_contains', definition.body_contains || '');
        setInputValue('headers', headersToTextarea(definition.headers));
        break;
      case 'dns':
        setInputValue('simple_record_name', definition.record_name || '');
        setInputValue('dns_server', definition.server || '');
        setInputValue('dns_port', definition.port || 53);
        setInputValue('record_name', definition.record_name || '');
        setInputValue('record_type', definition.record_type || 'A');
        setInputValue('expect_answers_min', definition.expect_answers_min || 1);
        break;
      case 'tunnel':
        setInputValue('simple_tunnel_protocol', definition.protocol || 'gre');
        setInputValue('tunnel_protocol', definition.protocol || 'gre');
        updateTunnelProtocolFields();
        setInputValue('interface', definition.interface || '');
        if (tunnelInterfaceInput) {
          tunnelInterfaceInput.dataset.userLocked = definition.interface ? '1' : '';
        }
        setInputValue(
          'auto_create_interface',
          definition.auto_create_interface === false ? '0' : '1'
        );
        setInputValue('simple_outer_remote', definition.outer_remote || '');
        setInputValue('outer_remote', definition.outer_remote || '');
        ensureSelectOption(
          tunnelLocalOuterSelect,
          definition.local_outer || '',
          definition.local_outer ? `@@tunnel_saved_outer@@ - ${definition.local_outer}` : ''
        );
        setInputValue('simple_inner_local_cidr', definition.inner_local_cidr || '');
        setInputValue('simple_inner_probe', definition.inner_probe || '');
        setInputValue('inner_probe', definition.inner_probe || '');
        setInputValue('inner_local_cidr', definition.inner_local_cidr || '');
        setInputValue('tunnel_key', definition.tunnel_key || '');
        setInputValue('esp_key_derivation', definition.esp_key_derivation || 'legacy');
        setInputValue('esp_cipher', definition.esp_cipher || 'legacy_aes_gcm');
        if (monitorForm) monitorForm.dataset.savedEspCipher = definition.protocol === 'esp' ? (definition.esp_cipher || 'legacy_aes_gcm') : '';
        setInputValue('speedtest_token', definition.speedtest_token || '');
        setInputValue('speedtest_port', definition.speedtest_port || 5201);
        for (const name of ['mtu', 'ttl', 'traffic_class', 'vni', 'tun_lanes']) setInputValue(name, definition[name] ?? '');
        ensureSelectOption(document.querySelector('[name="tun_transport"]'), definition.tun_transport || 'udp', definition.tun_transport === 'bip' ? 'BIP · legacy UDP compatibility' : undefined);
        setInputValue('tun_transport', definition.tun_transport || 'udp');
        setInputValue('transport_port', definition.transport_port || '');
        setInputValue('listen_port', definition.listen_port || '');
        setInputValue('l2tp_tunnel_id', definition.l2tp_tunnel_id || '');
        setInputValue('l2tp_peer_tunnel_id', definition.l2tp_peer_tunnel_id || '');
        setInputValue('l2tp_session_id', definition.l2tp_session_id || '');
        setInputValue('l2tp_peer_session_id', definition.l2tp_peer_session_id || '');
        setInputValue('l2tp_encapsulation', definition.l2tp_encapsulation || 'udp');
        setInputValue('wireguard_private_key', definition.wireguard_private_key || '');
        setInputValue('wireguard_peer_public_key', definition.wireguard_peer_public_key || '');
        setInputValue('wireguard_preshared_key', definition.wireguard_preshared_key || '');
        setInputValue('wireguard_allowed_ips', definition.wireguard_allowed_ips || '');
        setInputValue('ssh_username', definition.ssh_username || '');
        setInputValue('ssh_password', definition.ssh_password || '');
        setInputValue('ssh_private_key', definition.ssh_private_key || '');
        if (tunnelSourceInterfaceSelect) {
          tunnelSourceInterfaceSelect.dataset.userLocked = definition.source_interface ? '1' : '';
        }
        ensureSelectOption(
          tunnelSourceInterfaceSelect,
          definition.source_interface || '',
          definition.source_interface ? `@@tunnel_saved_source@@ - ${definition.source_interface}` : ''
        );
        setInputValue('expected_operstate', definition.expected_operstate || 'up');
        setInputValue('min_rx_packets_delta', definition.min_rx_packets_delta || 1);
        setInputValue('min_tx_packets_delta', definition.min_tx_packets_delta || 1);
        if (!definition.source_interface) {
          syncTunnelSourceInterfaceFromOuter();
        }
        if (!definition.interface) {
          syncTunnelInterfaceSuggestion();
        }
        break;
      case 'v2ray':
        setInputValue('simple_profile_import', definition.profile_import || '');
        setInputValue('simple_proxy_type', definition.proxy_type || 'vless');
        setInputValue('profile_import', definition.profile_import || '');
        setInputValue('proxy_type', definition.proxy_type || 'vless');
        setInputValue('local_entry_type', definition.local_entry_type || 'direct');
        updateV2raySections();
        setInputValue('proxy_host', definition.proxy_host || '');
        setInputValue('proxy_port', definition.proxy_port || '');
        setInputValue('test_url', definition.test_url || '');
        setInputValue('username', definition.username || '');
        setInputValue('password', definition.password || '');
        setInputValue('expected_status', joinNumberList(definition.expected_status));
        setInputValue('body_contains', definition.body_contains || '');
        setInputValue('server_host', definition.server_host || '');
        setInputValue('server_port', definition.server_port || '');
        setInputValue('server_name', definition.server_name || '');
        setInputValue('transport', definition.transport || '');
        setInputValue('wireguard_interface', definition.wireguard_interface || '');
        setInputValue('wireguard_peer', definition.wireguard_peer || '');
        setInputValue('inner_probe', definition.inner_probe || '');
        setInputValue('source_interface', definition.source_interface || '');
        setInputValue('max_handshake_age_secs', definition.max_handshake_age_secs || '');
        break;
      default:
        break;
    }

    monitorForm.dispatchEvent(new Event('imonitor:edit'));
    monitorForm.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const toLocalDateTime = (unix) => {
    if (!unix) return '';
    const date = new Date(unix * 1000);
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  };

  const fromLocalDateTime = (value) => {
    if (!value) return 0;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 0;
    return Math.floor(date.getTime() / 1000);
  };

  const statusColor = (status) => {
    if (status === 'down') return '#f43f5e';
    if (status === 'degraded') return '#f59e0b';
    return '#22c55e';
  };

  const formatMaybeMs = (value, digits = 1) => value != null && value !== ''
    ? `${Number(value).toFixed(digits)} ms`
    : '-';

  const formatMaybePercent = (value) => value != null && value !== ''
    ? `${Number(value).toFixed(1)}%`
    : '-';

  const formatMaybeMbps = (value) => value != null && value !== ''
    ? `${Number(value).toFixed(1)}`
    : '-';

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

  const speedGaugeCeiling = (value) => {
    const numeric = Number(value || 0);
    if (!Number.isFinite(numeric) || numeric <= 0) return 100;
    if (numeric <= 100) return 100;
    if (numeric <= 250) return 250;
    if (numeric <= 500) return 500;
    if (numeric <= 1000) return 1000;
    return Math.ceil(numeric / 250) * 250;
  };

  const setTunnelGauge = (element, ratio, tone) => {
    if (!element) return;
    element.style.setProperty('--ratio', String(clamp(Number(ratio || 0), 0, 1)));
    element.dataset.tone = tone || 'idle';
  };

  const renderTunnelDiagMeta = (payload) => {
    if (!tunnelDiagMeta) return;
    const cards = [
      ['Interface', payload.interface || '-'],
      ['Inner Probe', payload.inner_probe || '-'],
      ['Bind IP', payload.bind_ip || '-'],
      ['Progress', `${payload.elapsed_seconds || 0} / ${payload.total_seconds || 10} s`]
    ];
    tunnelDiagMeta.innerHTML = cards.map(([label, value]) => `
      <article class="analytics-stat-card">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </article>
    `).join('');
  };

  const renderTunnelDiagResult = (elements, result, options) => {
    if (!elements) return;
    const summary = result || {};
    if (summary.loading || summary.phase === 'pending') {
      if (elements.text) elements.text.textContent = '...';
      if (elements.raw) elements.raw.textContent = '-';
      setTunnelGauge(elements.gauge, 0.08, 'loading');
      return;
    }
    if (summary.error) {
      if (elements.text) elements.text.textContent = '-';
      if (elements.raw) elements.raw.textContent = summary.raw_output || '-';
      setTunnelGauge(elements.gauge, 0, 'error');
      return;
    }

    if (options.kind === 'ping') {
      if (elements.text) {
        elements.text.textContent = summary.avg_latency_ms != null
          ? Number(summary.avg_latency_ms).toFixed(1)
          : '-';
      }
      const pingValue = Number(summary.avg_latency_ms || 0);
      const tone = summary.phase === 'running'
        ? 'loading'
        : (Number(summary.packet_loss_percent || 0) > 0 ? 'warn' : 'success');
      setTunnelGauge(elements.gauge, pingValue / 250, tone);
    } else {
      const displayMbps = summary.phase === 'completed'
        ? (summary.avg_mbps ?? summary.current_mbps)
        : (summary.current_mbps ?? summary.avg_mbps);
      if (elements.text) {
        elements.text.textContent = formatMaybeMbps(displayMbps);
      }
      const ceiling = speedGaugeCeiling(displayMbps);
      const tone = summary.phase === 'running' ? 'loading' : 'success';
      setTunnelGauge(elements.gauge, Number(displayMbps || 0) / ceiling, tone);
    }
    if (elements.raw) elements.raw.textContent = summary.raw_output || '-';
  };

  const stopTunnelDiagPolling = () => {
    if (tunnelDiagState.pollHandle) {
      window.clearTimeout(tunnelDiagState.pollHandle);
      tunnelDiagState.pollHandle = null;
    }
    tunnelDiagState.pollInFlight = false;
  };

  const scheduleTunnelDiagPoll = (delayMs = 1000) => {
    if (!tunnelDiagState.jobId) return;
    if (tunnelDiagState.pollHandle) {
      window.clearTimeout(tunnelDiagState.pollHandle);
    }
    tunnelDiagState.pollHandle = window.setTimeout(() => {
      tunnelDiagState.pollHandle = null;
      fetchTunnelDiagnosticsProgress();
    }, delayMs);
  };

  const applyTunnelDiagPayload = (payload) => {
    if (tunnelDiagTitle) tunnelDiagTitle.textContent = payload.label || tunnelDiagState.label || tunnelDiagState.checkId;
    if (tunnelDiagSubtitle) {
      const subtitleBits = [payload.check_id || tunnelDiagState.checkId];
      if (payload.inner_probe) subtitleBits.push(payload.inner_probe);
      subtitleBits.push(`${payload.elapsed_seconds || 0} / ${payload.total_seconds || 10} s`);
      tunnelDiagSubtitle.textContent = subtitleBits.join(' • ');
    }
    renderTunnelDiagMeta(payload);
    renderTunnelDiagResult(
      { text: tunnelDiagPingText, raw: tunnelDiagPingRaw, gauge: tunnelDiagPingGauge },
      payload.ping,
      { kind: 'ping' }
    );
    renderTunnelDiagResult(
      { text: tunnelDiagUploadText, raw: tunnelDiagUploadRaw, gauge: tunnelDiagUploadGauge },
      payload.upload,
      { kind: 'native' }
    );
    renderTunnelDiagResult(
      { text: tunnelDiagDownloadText, raw: tunnelDiagDownloadRaw, gauge: tunnelDiagDownloadGauge },
      payload.download,
      { kind: 'native' }
    );
  };

  const fetchTunnelDiagnosticsProgress = async () => {
    if (!tunnelDiagState.jobId || tunnelDiagState.pollInFlight) return;
    tunnelDiagState.pollInFlight = true;
    try {
      const params = new URLSearchParams({ job_id: tunnelDiagState.jobId });
      const response = await fetch(`/admin/monitors/tunnel-diagnostics.json?${params.toString()}`, {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch' }
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload && payload.error ? payload.error : String(response.status));
      }
      applyTunnelDiagPayload(payload);
      const finished = payload.status && payload.status !== 'running';
      if (finished) {
        stopTunnelDiagPolling();
        if (tunnelDiagRun) tunnelDiagRun.disabled = false;
      } else {
        scheduleTunnelDiagPoll(1000);
      }
    } catch (error) {
      stopTunnelDiagPolling();
      const message = error && error.message ? error.message : '@@tunnel_diag_error@@';
      if (tunnelDiagMeta) tunnelDiagMeta.innerHTML = '';
      renderTunnelDiagResult(
        { text: tunnelDiagPingText, raw: tunnelDiagPingRaw, gauge: tunnelDiagPingGauge },
        { error: message, raw_output: '-' },
        { kind: 'ping' }
      );
      renderTunnelDiagResult(
        { text: tunnelDiagUploadText, raw: tunnelDiagUploadRaw, gauge: tunnelDiagUploadGauge },
        { error: message, raw_output: '-' },
        { kind: 'native' }
      );
      renderTunnelDiagResult(
        { text: tunnelDiagDownloadText, raw: tunnelDiagDownloadRaw, gauge: tunnelDiagDownloadGauge },
        { error: message, raw_output: '-' },
        { kind: 'native' }
      );
      if (tunnelDiagRun) tunnelDiagRun.disabled = false;
    } finally {
      tunnelDiagState.pollInFlight = false;
    }
  };

  const startTunnelDiagnostics = async () => {
    if (!tunnelDiagState.checkId) return;
    stopTunnelDiagPolling();
    tunnelDiagState.jobId = '';
    if (tunnelDiagRun) tunnelDiagRun.disabled = true;
    renderTunnelDiagResult(
      { text: tunnelDiagPingText, raw: tunnelDiagPingRaw, gauge: tunnelDiagPingGauge },
      { loading: true },
      { kind: 'ping' }
    );
    renderTunnelDiagResult(
      { text: tunnelDiagUploadText, raw: tunnelDiagUploadRaw, gauge: tunnelDiagUploadGauge },
      { loading: true },
      { kind: 'native' }
    );
    renderTunnelDiagResult(
      { text: tunnelDiagDownloadText, raw: tunnelDiagDownloadRaw, gauge: tunnelDiagDownloadGauge },
      { loading: true },
      { kind: 'native' }
    );
    try {
      const body = new URLSearchParams({ check_id: tunnelDiagState.checkId });
      const response = await fetch('/admin/monitors/tunnel-diagnostics/start', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          'X-Requested-With': 'fetch'
        },
        body: body.toString()
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload && payload.error ? payload.error : String(response.status));
      }
      tunnelDiagState.jobId = payload.job_id || '';
      applyTunnelDiagPayload(payload);
      scheduleTunnelDiagPoll(150);
    } catch (error) {
      const message = error && error.message ? error.message : '@@tunnel_diag_error@@';
      if (tunnelDiagMeta) tunnelDiagMeta.innerHTML = '';
      renderTunnelDiagResult(
        { text: tunnelDiagPingText, raw: tunnelDiagPingRaw, gauge: tunnelDiagPingGauge },
        { error: message, raw_output: '-' },
        { kind: 'ping' }
      );
      renderTunnelDiagResult(
        { text: tunnelDiagUploadText, raw: tunnelDiagUploadRaw, gauge: tunnelDiagUploadGauge },
        { error: message, raw_output: '-' },
        { kind: 'native' }
      );
      renderTunnelDiagResult(
        { text: tunnelDiagDownloadText, raw: tunnelDiagDownloadRaw, gauge: tunnelDiagDownloadGauge },
        { error: message, raw_output: '-' },
        { kind: 'native' }
      );
      if (tunnelDiagRun) tunnelDiagRun.disabled = false;
    }
  };

  const openTunnelDiagnosticsModal = (button) => {
    if (!tunnelDiagModal) return;
    tunnelDiagState.checkId = button.dataset.checkId || '';
    tunnelDiagState.label = button.dataset.checkLabel || tunnelDiagState.checkId;
    showDialog(tunnelDiagModal, button);
    startTunnelDiagnostics();
  };

  const closeTunnelDiagnosticsModal = () => {
    if (!tunnelDiagModal) return;
    stopTunnelDiagPolling();
    tunnelDiagState.jobId = '';
    hideDialog(tunnelDiagModal);
  };

  const updateAnalyticsExports = () => {
    if (!analyticsState.checkId) return;
    const params = new URLSearchParams({
      check_id: analyticsState.checkId,
      from_unix: String(analyticsState.fromUnix || 0),
      to_unix: String(analyticsState.toUnix || 0)
    });
    if (analyticsExportCsv) analyticsExportCsv.href = `/admin/monitors/export.csv?${params.toString()}`;
    if (analyticsExportPdf) analyticsExportPdf.href = `/admin/monitors/export.pdf?${params.toString()}`;
    if (analyticsExportXlsx) analyticsExportXlsx.href = `/admin/monitors/export.xlsx?${params.toString()}`;
  };

  const renderAnalyticsStats = (payload) => {
    if (!analyticsStats) return;
    const summary = payload.summary || {};
    const cards = [
      ['Points', String(summary.total_points ?? 0)],
      ['Availability', `${Number(summary.availability_percent || 0).toFixed(2)}%`],
      ['Up / Degraded / Down', `${summary.up_points ?? 0} / ${summary.degraded_points ?? 0} / ${summary.down_points ?? 0}`],
      ['Avg / Max Latency', `${summary.avg_latency_ms ? Number(summary.avg_latency_ms).toFixed(1) + ' ms' : '-'} / ${summary.max_latency_ms ? summary.max_latency_ms + ' ms' : '-'}`]
    ];
    analyticsStats.innerHTML = cards.map(([label, value]) => `
      <article class="analytics-stat-card">
        <span>${label}</span>
        <strong>${value}</strong>
      </article>
    `).join('');
  };

  const renderAnalyticsRows = (points) => {
    if (!analyticsRows) return;
    if (!points.length) {
      analyticsRows.innerHTML = `<tr><td colspan="6" class="empty-cell">@@analytics_no_rows@@</td></tr>`;
      return;
    }
    const formatter = new Intl.DateTimeFormat(document.documentElement.lang === 'fa' ? 'fa-IR-u-ca-gregory' : 'en-CA', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
    analyticsRows.innerHTML = points.map((point) => `
      <tr>
        <td>${formatter.format(new Date((point.observed_at_unix || 0) * 1000))}</td>
        <td><span class="status-chip ${point.status || 'pending'}">${escapeHtml(point.status || 'pending')}</span></td>
        <td>${point.latency_ms != null ? point.latency_ms + ' ms' : '-'}</td>
        <td>${point.duration_ms != null ? point.duration_ms + ' ms' : '-'}</td>
        <td>${escapeHtml(point.endpoint || '-')}</td>
        <td>${escapeHtml(point.message || '')}</td>
      </tr>
    `).join('');
  };

  const renderAnalyticsChart = (points) => {
    if (!analyticsChart || !analyticsChartEmpty) return;
    if (!points.length) {
      analyticsChart.innerHTML = '';
      analyticsChartEmpty.hidden = false;
      return;
    }

    analyticsChartEmpty.hidden = true;
    const width = 960;
    const height = 320;
    const padding = { left: 56, right: 24, top: 22, bottom: 36 };
    const minX = points[0].observed_at_unix || 0;
    const maxX = points[points.length - 1].observed_at_unix || minX + 1;
    const latencyValues = points
      .map((point) => point.latency_ms)
      .filter((value) => value != null)
      .map(Number);
    const maxLatency = Math.max(...latencyValues, 100);
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;
    const xAt = (value) => {
      if (maxX <= minX) return padding.left + chartWidth / 2;
      return padding.left + ((value - minX) / (maxX - minX)) * chartWidth;
    };
    const yAt = (value) => padding.top + chartHeight - ((value / maxLatency) * chartHeight);

    const grid = [0, 0.25, 0.5, 0.75, 1].map((fraction) => {
      const value = Math.round(maxLatency * fraction);
      const y = yAt(value);
      return `
        <line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="rgba(148,163,184,0.18)" stroke-width="1" />
        <text x="${padding.left - 10}" y="${y + 4}" text-anchor="end" fill="rgba(148,163,184,0.72)" font-size="11">${value}ms</text>
      `;
    }).join('');

    const linePoints = points
      .filter((point) => point.latency_ms != null)
      .map((point) => `${xAt(point.observed_at_unix || 0)},${yAt(point.latency_ms)}`)
      .join(' ');
    const polyline = linePoints
      ? `<polyline fill="none" stroke="url(#analyticsLineGradient)" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" points="${linePoints}" />`
      : '';
    const markers = points.map((point) => {
      const x = xAt(point.observed_at_unix || 0);
      const y = point.latency_ms != null ? yAt(point.latency_ms) : height - padding.bottom + 6;
      return `
        <g>
          <rect x="${x - 3.5}" y="${height - padding.bottom + 12}" width="7" height="12" rx="3.5" fill="${statusColor(point.status)}" fill-opacity="0.82"></rect>
          <circle cx="${x}" cy="${y}" r="4.5" fill="${statusColor(point.status)}" />
        </g>
      `;
    }).join('');

    analyticsChart.innerHTML = `
      <defs>
        <linearGradient id="analyticsLineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="var(--primary)"></stop>
          <stop offset="100%" stop-color="var(--secondary)"></stop>
        </linearGradient>
      </defs>
      <rect x="0" y="0" width="${width}" height="${height}" rx="24" fill="transparent"></rect>
      ${grid}
      <line x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" stroke="rgba(148,163,184,0.24)" stroke-width="1"></line>
      ${polyline}
      ${markers}
    `;
  };

  const fetchAnalytics = async () => {
    if (!analyticsState.checkId) return;
    if (analyticsRows) {
      analyticsRows.innerHTML = `<tr><td colspan="6" class="empty-cell">@@analytics_loading@@</td></tr>`;
    }
    try {
      const params = new URLSearchParams({
        check_id: analyticsState.checkId,
        from_unix: String(analyticsState.fromUnix || 0),
        to_unix: String(analyticsState.toUnix || 0)
      });
      const response = await fetch(`/admin/monitors/history.json?${params.toString()}`, {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch' }
      });
      if (!response.ok) {
        throw new Error(String(response.status));
      }
      const payload = await response.json();
      const points = Array.isArray(payload.points) ? payload.points : [];
      analyticsState.fromUnix = payload.from_unix || analyticsState.fromUnix;
      analyticsState.toUnix = payload.to_unix || analyticsState.toUnix;
      analyticsState.minUnix = points.length ? points[0].observed_at_unix : analyticsState.fromUnix;
      analyticsState.maxUnix = points.length ? points[points.length - 1].observed_at_unix : analyticsState.toUnix;
      if (analyticsFrom) analyticsFrom.value = toLocalDateTime(analyticsState.fromUnix);
      if (analyticsTo) analyticsTo.value = toLocalDateTime(analyticsState.toUnix);
      if (analyticsTitle) analyticsTitle.textContent = payload.label || analyticsState.label || analyticsState.checkId;
      if (analyticsSubtitle) analyticsSubtitle.textContent = `${payload.check_id || analyticsState.checkId} • ${payload.kind || ''}`;
      renderAnalyticsStats(payload);
      renderAnalyticsRows(points);
      renderAnalyticsChart(points);
      updateAnalyticsExports();
    } catch (_error) {
      if (analyticsRows) {
        analyticsRows.innerHTML = `<tr><td colspan="6" class="empty-cell">@@analytics_error@@</td></tr>`;
      }
      renderAnalyticsChart([]);
    }
  };

  const openAnalyticsModal = (button) => {
    if (!analyticsModal) return;
    const now = Math.floor(Date.now() / 1000);
    analyticsState.checkId = button.dataset.checkId || '';
    analyticsState.label = button.dataset.checkLabel || analyticsState.checkId;
    analyticsState.fromUnix = now - 86400;
    analyticsState.toUnix = now;
    showDialog(analyticsModal, button);
    fetchAnalytics();
  };

  const closeAnalyticsModal = () => {
    if (!analyticsModal) return;
    hideDialog(analyticsModal);
  };

  const applyPresetRange = (preset) => {
    const now = Math.floor(Date.now() / 1000);
    if (preset === 'all') {
      analyticsState.fromUnix = analyticsState.minUnix || 0;
      analyticsState.toUnix = analyticsState.maxUnix || now;
    } else if (preset === '6h') {
      analyticsState.fromUnix = now - 21600;
      analyticsState.toUnix = now;
    } else if (preset === '24h') {
      analyticsState.fromUnix = now - 86400;
      analyticsState.toUnix = now;
    } else if (preset === '7d') {
      analyticsState.fromUnix = now - 604800;
      analyticsState.toUnix = now;
    } else if (preset === '30d') {
      analyticsState.fromUnix = now - 2592000;
      analyticsState.toUnix = now;
    }
    fetchAnalytics();
  };

  const zoomAnalyticsRange = (direction) => {
    const hardMin = analyticsState.minUnix || 0;
    const hardMax = analyticsState.maxUnix || Math.floor(Date.now() / 1000);
    const span = Math.max(3600, (analyticsState.toUnix || hardMax) - (analyticsState.fromUnix || hardMin));
    const center = (analyticsState.fromUnix || hardMin) + span / 2;
    const nextSpan = direction === 'in'
      ? Math.max(3600, Math.floor(span / 2))
      : Math.min(Math.max(hardMax - hardMin, span * 2), span * 2);
    analyticsState.fromUnix = Math.max(hardMin, Math.floor(center - nextSpan / 2));
    analyticsState.toUnix = Math.min(hardMax, Math.ceil(center + nextSpan / 2));
    fetchAnalytics();
  };

  if (idInput) {
    idInput.addEventListener('input', () => {
      idManuallyEdited = idInput.value.trim().length > 0;
      syncTunnelInterfaceSuggestion();
      updateTunnelProtocolFields();
    });
  }

  if (labelInput && idInput) {
    labelInput.addEventListener('input', () => {
      if (!idManuallyEdited || !idInput.value.trim()) {
        idInput.value = slugify(labelInput.value);
      }
      syncTunnelInterfaceSuggestion();
      updateTunnelProtocolFields();
    });
  }

  if (kindSelect) {
    kindSelect.addEventListener('change', updateBuilder);
    updateBuilder();
  }

  monitorBuilderViewButtons.forEach((button) => {
    button.addEventListener('click', () => {
      setMonitorBuilderView(button.getAttribute('data-builder-view-trigger'));
    });
  });

  setMonitorBuilderView('simple');

  if (resetBuilderButton) {
    resetBuilderButton.addEventListener('click', resetMonitorEditor);
  }

  if (v2rayTypeSelect) {
    v2rayTypeSelect.addEventListener('change', updateV2raySections);
    updateV2raySections();
  }
  if (simpleV2rayTypeSelect) {
    simpleV2rayTypeSelect.addEventListener('change', () => {
      if (v2rayTypeSelect) {
        v2rayTypeSelect.value = simpleV2rayTypeSelect.value;
      }
      updateV2raySections();
    });
  }

  if (v2rayImportInput && v2rayTypeSelect) {
    v2rayImportInput.addEventListener('input', () => {
      const detected = detectV2rayImportType(v2rayImportInput.value);
      if (!detected) return;
      v2rayTypeSelect.value = detected.protocol;
      if (v2rayEntrySelect && detected.entry) {
        v2rayEntrySelect.value = detected.entry;
      }
      updateV2raySections();
    });
  }

  if (simpleTunnelProtocolSelect) {
    simpleTunnelProtocolSelect.addEventListener('change', () => {
      if (tunnelProtocolSelect) {
        tunnelProtocolSelect.value = simpleTunnelProtocolSelect.value;
      }
      syncTunnelInterfaceSuggestion();
    });
  }

  syncSimpleMirrorField('simple_target', 'target');
  syncSimpleMirrorField('simple_port', 'port');
  syncSimpleMirrorField('simple_host', 'host');
  syncSimpleMirrorField('simple_record_name', 'record_name');
  syncSimpleMirrorField('simple_outer_remote', 'outer_remote');
  syncSimpleMirrorField('simple_inner_local_cidr', 'inner_local_cidr');
  syncSimpleMirrorField('simple_inner_probe', 'inner_probe');
  syncSimpleMirrorField('simple_profile_import', 'profile_import', () => {
    if (!v2rayImportInput || !v2rayTypeSelect) return;
    const detected = detectV2rayImportType(v2rayImportInput.value);
    if (!detected) return;
    v2rayTypeSelect.value = detected.protocol;
    if (simpleV2rayTypeSelect) {
      simpleV2rayTypeSelect.value = detected.protocol;
    }
    if (v2rayEntrySelect && detected.entry) {
      v2rayEntrySelect.value = detected.entry;
    }
    updateV2raySections();
  });
  syncSimpleMirrorField('simple_proxy_type', 'proxy_type', updateV2raySections);
  syncSimpleMirrorField('simple_tunnel_protocol', 'tunnel_protocol', syncTunnelInterfaceSuggestion);

  if (tunnelLocalOuterSelect) {
    tunnelLocalOuterSelect.addEventListener('change', () => {
      if (tunnelSourceInterfaceSelect && !tunnelSourceInterfaceSelect.value) {
        tunnelSourceInterfaceSelect.dataset.userLocked = '';
      }
      syncTunnelSourceInterfaceFromOuter();
    });
  }

  if (tunnelProtocolSelect) {
    tunnelProtocolSelect.addEventListener('change', () => {
      syncTunnelInterfaceSuggestion();
      updateTunnelProtocolFields();
    });
    updateTunnelProtocolFields();
  }

  if (tunnelInterfaceInput) {
    tunnelInterfaceInput.addEventListener('input', () => {
      const current = tunnelInterfaceInput.value.trim();
      const autoValue = tunnelInterfaceInput.dataset.autoValue || '';
      tunnelInterfaceInput.dataset.userLocked =
        current && current !== autoValue ? '1' : '';
    });
  }

  if (tunnelSourceInterfaceSelect) {
    tunnelSourceInterfaceSelect.addEventListener('change', () => {
      tunnelSourceInterfaceSelect.dataset.userLocked = tunnelSourceInterfaceSelect.value ? '1' : '';
      if (!tunnelSourceInterfaceSelect.value) {
        syncTunnelSourceInterfaceFromOuter();
      }
    });
  }

  document.querySelectorAll('[data-edit-check]').forEach((button) => {
    button.addEventListener('click', () => loadMonitorIntoEditor(button));
  });

  if (themePresetSelect) {
    themePresetSelect.addEventListener('change', applyThemePreset);
  }
  if (forwardProtocolSelect) {
    forwardProtocolSelect.addEventListener('change', updateForwardProtocolFields);
    updateForwardProtocolFields();
  }
  syncColorInputs();

  if (brandingForm) {
    brandingForm.addEventListener('submit', async (event) => {
      if (brandingLogoUploadData) brandingLogoUploadData.value = '';
      if (brandingLogoUploadName) brandingLogoUploadName.value = '';
      if (brandingFaviconUploadData) brandingFaviconUploadData.value = '';
      if (brandingFaviconUploadName) brandingFaviconUploadName.value = '';
      const hasLogoUpload = Boolean(brandingLogoUpload && brandingLogoUpload.files && brandingLogoUpload.files.length);
      const hasFaviconUpload = Boolean(brandingFaviconUpload && brandingFaviconUpload.files && brandingFaviconUpload.files.length);
      if (!hasLogoUpload && !hasFaviconUpload) {
        return;
      }
      if (brandingForm.dataset.processingUpload === '1') {
        return;
      }
      event.preventDefault();
      brandingForm.dataset.processingUpload = '1';
      const submitter = event.submitter || null;
      if (submitter) {
        submitter.disabled = true;
      }
      try {
        await prepareBrandingUpload(brandingLogoUpload, brandingLogoUploadData, brandingLogoUploadName, 'logo');
        await prepareBrandingUpload(brandingFaviconUpload, brandingFaviconUploadData, brandingFaviconUploadName, 'favicon');
        brandingForm.submit();
      } catch (error) {
        brandingForm.dataset.processingUpload = '';
        if (submitter) {
          submitter.disabled = false;
        }
        const detail = error && error.message ? ` ${error.message}` : '';
        window.alert(`@@branding_upload_failed@@${detail}`);
      }
    });
  }

  document.querySelectorAll('[data-open-analytics]').forEach((button) => {
    button.addEventListener('click', () => openAnalyticsModal(button));
  });

  document.querySelectorAll('[data-open-tunnel-diagnostics]').forEach((button) => {
    button.addEventListener('click', () => openTunnelDiagnosticsModal(button));
  });

  document.querySelectorAll('[data-close-analytics]').forEach((button) => {
    button.addEventListener('click', closeAnalyticsModal);
  });

  document.querySelectorAll('[data-close-tunnel-diagnostics]').forEach((button) => {
    button.addEventListener('click', closeTunnelDiagnosticsModal);
  });

  document.querySelectorAll('[data-range-preset]').forEach((button) => {
    button.addEventListener('click', () => applyPresetRange(button.getAttribute('data-range-preset')));
  });

  document.querySelectorAll('[data-zoom-range]').forEach((button) => {
    button.addEventListener('click', () => zoomAnalyticsRange(button.getAttribute('data-zoom-range')));
  });

  if (analyticsApply) {
    analyticsApply.addEventListener('click', () => {
      analyticsState.fromUnix = fromLocalDateTime(analyticsFrom ? analyticsFrom.value : '') || analyticsState.fromUnix;
      analyticsState.toUnix = fromLocalDateTime(analyticsTo ? analyticsTo.value : '') || analyticsState.toUnix;
      fetchAnalytics();
    });
  }

  if (tunnelDiagRun) {
    tunnelDiagRun.addEventListener('click', () => {
      startTunnelDiagnostics();
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && analyticsModal && !analyticsModal.hidden) {
      closeAnalyticsModal();
    }
    if (event.key === 'Escape' && tunnelDiagModal && !tunnelDiagModal.hidden) {
      closeTunnelDiagnosticsModal();
    }
  });

  const refreshLivePanel = async () => {
    if (!livePanel || document.hidden || livePanelInFlight) return;
    livePanelInFlight = true;
    try {
      const response = await fetch('/admin/live/system', {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch' }
      });
      if (!response.ok) {
        throw new Error(String(response.status));
      }
      const html = await response.text();
      livePanel.classList.add('is-refreshing');
      livePanel.innerHTML = html;
      window.setTimeout(() => livePanel.classList.remove('is-refreshing'), 450);
    } catch (_error) {
      if (livePanel && !livePanel.querySelector('.inline-alert')) {
        livePanel.insertAdjacentHTML(
          'beforeend',
          `<div class="inline-alert inline-alert--danger">@@fetch_failed@@</div>`
        );
      }
    } finally {
      livePanelInFlight = false;
    }
  };

  if (livePanel) {
    refreshLivePanel();
    window.setInterval(refreshLivePanel, 5000);
  }
})();
