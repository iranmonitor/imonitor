# Sponsor placement API

iMonitor requests `https://iranmonitor.net/api/imonitor/ads` with two public
query parameters: `placement=admin|public` and `lang=fa|en`. The server API
will be implemented separately. No license key, account data, monitor
configuration, tunnel credentials, or device fingerprint is sent.

Return a JSON object:

```json
{
  "image_url": "https://iranmonitor.net/api/ads/monitoring.png",
  "click_url": "https://iranmonitor.net/services/monitoring/",
  "alt": "Sponsor description"
}
```

Return HTTP 204 when no creative is available. Serve different creatives
for `admin` and `public`. PNG images must be hosted over HTTPS on
`iranmonitor.net`, `www.iranmonitor.net`, or `irnmo.ir`; destination links
must use HTTPS. Images should be responsive, below 250 KiB, and use an
approximately 6:1 aspect ratio. Include short localized alt text.

The panel returns sanitized creative metadata from its own `/ads.json`
route. Admin metadata requires a logged-in session. Fetches run in background
workers with a five-second deadline and 64 KiB response limit, cached for
15 minutes. An unavailable API leaves a new placement hidden; a previously valid creative
is retained for up to 24 hours. Invalid images stay hidden.
The browser loads the PNG lazily after the page is usable. The browser retries an initially empty response twice at six-second intervals
to allow the background fetch to finish. Advertising never delays monitor
checks or page rendering.

There are no executable remote scripts or HTML creatives. Clicking an ad
opens a new tab with `noopener`, `noreferrer`, and `sponsored` link relations.
