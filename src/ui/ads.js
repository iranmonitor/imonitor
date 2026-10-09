(() => {
  const slot = document.querySelector('[data-ad-placement]:not([data-ad-initialized])');
  if (!slot) return;
  slot.dataset.adInitialized = 'true';
  let attempts = 0;
  const show = async () => {
    attempts += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      const response = await fetch('/ads.json?placement=' + slot.dataset.adPlacement + '&lang=' + slot.dataset.adLang,
        { signal: controller.signal, credentials: 'same-origin' });
      if (!response.ok) return;
      const { creative } = await response.json();
      if (!creative) {
        if (attempts < 3) setTimeout(show, 6000);
        return;
      }
      const image = slot.querySelector('img');
      const link = slot.querySelector('a');
      image.onload = () => { slot.hidden = false; };
      image.onerror = () => { slot.hidden = true; };
      image.alt = creative.alt || slot.getAttribute('aria-label');
      link.href = creative.click_url;
      // A hidden slot cannot trigger a lazy image request; reveal it only after decoding.
      image.loading = 'eager';
      image.src = creative.image_url;
    } catch (_) { /* An absent advertising API leaves the page fully usable. */ }
    finally { clearTimeout(timer); }
  };
  if ('requestIdleCallback' in window) requestIdleCallback(show, { timeout: 2500 });
  else setTimeout(show, 800);
})();
