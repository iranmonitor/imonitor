<?php

declare(strict_types=1);

require_once __DIR__ . '/../../configs/config.php';

function imonitor_free_escape(mixed $value): string
{
    return iranmonitor_escape((string) $value);
}

$iranmonitorSeo = [
    'title' => 'iMonitor رایگان؛ کد، نصب و راهنما | IranMonitor',
    'favicon' => '/assets/logo.png',
    'meta_tags' => [
        'description' => 'iMonitor رایگان برای مانیتورینگ و تونل؛ مخزن رسمی GitHub، نصب و ارتقا، راهنمای فارسی و آینه محلی کد، بدون خرید لایسنس.',
        'robots' => 'index,follow',
        'canonical' => iranmonitor_url('/services/monitoring'),
    ],
];
$repository = 'https://github.com/iranmonitor/imonitor';
$installer = 'https://github.com/iranmonitor/imonitor/releases/latest/download/install.sh';
$mirrorBrowse = '/git/imonitor/';
$mirrorClone = iranmonitor_url('/git/imonitor.git');
$features = [
    ['title' => 'مانیتورینگ و عیب‌یابی', 'copy' => 'بررسی دسترس‌پذیری سرویس‌ها، وضعیت سرور و مسیر شبکه، همراه با تاریخچه و صفحه وضعیت عمومی.'],
    ['title' => 'تونل و تست سرعت', 'copy' => 'راه‌اندازی تونل با راهنمای مرحله‌ای و اندازه‌گیری سرعت داخلی بین دو سرور برای بررسی مسیر واقعی شما.'],
    ['title' => 'پنل فارسی و انگلیسی', 'copy' => 'شروع کار، مدیریت مانیتورها و تنظیمات شبکه در یک پنل با راهنمای فارسی و انگلیسی.'],
];
require_once __DIR__ . '/../../includes/header/index.php';
?>
<style>
.imonitor-free{display:flex;flex-direction:column;gap:1.5rem;width:100%;margin:2rem auto 1rem;color:#e2e8f0;direction:rtl}
.imonitor-free *{box-sizing:border-box}
.imonitor-free .if-panel,.imonitor-free .if-feature{padding:1.5rem;border:1px solid rgba(255,255,255,.12);border-radius:1.75rem;background:rgba(255,255,255,.04)}
.imonitor-free .if-hero{border-color:rgba(110,231,183,.25);background:linear-gradient(135deg,#0d2e1e,#0b1420);box-shadow:0 20px 48px rgba(8,10,14,.24)}
.imonitor-free .if-eyebrow{margin:0;color:#a7f3d0;font-size:.75rem;letter-spacing:.12em}
.imonitor-free .if-title{margin:1rem 0 0;color:#fff;font-size:1.85rem;font-weight:740;line-height:1.65}
.imonitor-free .if-subtitle{margin:0;color:#fff;font-size:1.25rem;font-weight:700;line-height:1.7}
.imonitor-free .if-copy{max-width:54rem;margin:.75rem 0 0;color:#cbd5e1;font-size:.9rem;line-height:2.2}
.imonitor-free .if-badges,.imonitor-free .if-actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}
.imonitor-free .if-chip{padding:.5rem 1rem;border:1px solid rgba(255,255,255,.16);border-radius:999px;font-size:.75rem}
.imonitor-free .if-button{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:.75rem 1.25rem;border:1px solid rgba(255,255,255,.2);border-radius:.85rem;color:#fff;background:rgba(255,255,255,.025);font-size:.9rem;text-decoration:none;transition:background .2s}
.imonitor-free .if-button:hover{background:rgba(255,255,255,.1)}
.imonitor-free .if-button:focus-visible,.imonitor-free .if-link:focus-visible{outline:2px solid #a7f3d0;outline-offset:4px}
.imonitor-free .if-primary{border-color:#6ee7b7;background:#6ee7b7;color:#0f172a;font-weight:700}
.imonitor-free .if-primary:hover{background:#a7f3d0}
.imonitor-free .if-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:1rem}
.imonitor-free .if-feature .if-subtitle{font-size:1.05rem}
.imonitor-free .if-code{overflow-x:auto;margin-top:1.1rem;padding:1.1rem;border-radius:1rem;background:rgba(0,0,0,.3);color:#a7f3d0;text-align:left;direction:ltr}
.imonitor-free .if-code code{white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.87rem}
.imonitor-free .if-code-label{margin:1.5rem 0 0;color:#fff;font-size:.9rem;font-weight:700}
.imonitor-free .if-note{margin:1.5rem 0 0;color:#cbd5e1;font-size:.8rem;line-height:2}
.imonitor-free .if-link{color:#a7f3d0;text-decoration:underline}
@media(min-width:768px){.imonitor-free .if-panel{padding:2rem}.imonitor-free .if-hero{padding:2.5rem}.imonitor-free .if-title{font-size:2.45rem}.imonitor-free .if-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
</style>
<div class="imonitor-free" dir="rtl">
    <section class="if-panel if-hero">
        <p class="if-eyebrow" dir="ltr">iMONITOR · FREE FOR EVERYONE</p>
        <h1 class="if-title">مانیتورینگ و تونل، ساده و رایگان.</h1>
        <p class="if-copy">iMonitor برای پایش سرویس‌ها، ساخت تونل و عیب‌یابی شبکه روی سرور شما ساخته شده است. همه امکانات نسخه رسمی بدون کلید لایسنس و محدودیت تعداد مانیتور در دسترس‌اند؛ برای شروع، مخزن پروژه و راهنمای نصب را ببینید.</p>
        <div class="if-badges">
            <span class="if-chip">مصرف شخصی و تجاری رایگان</span>
            <span class="if-chip">بدون خرید لایسنس یا اسلات</span>
            <span class="if-chip">کد و راهنمای پروژه در GitHub</span>
        </div>
        <div class="if-actions">
            <a class="if-button if-primary" href="<?= imonitor_free_escape($repository) ?>">مخزن رسمی در GitHub</a>
            <a class="if-button" href="<?= imonitor_free_escape($repository . '#readme') ?>">راهنمای نصب و شروع کار</a>
            <a class="if-button" href="<?= imonitor_free_escape($mirrorBrowse) ?>">مرور آینه محلی کد</a>
        </div>
    </section>

    <section class="if-grid" aria-label="امکانات iMonitor">
        <?php foreach ($features as $feature): ?>
            <article class="if-feature">
                <h2 class="if-subtitle"><?= imonitor_free_escape($feature['title']) ?></h2>
                <p class="if-copy"><?= imonitor_free_escape($feature['copy']) ?></p>
            </article>
        <?php endforeach; ?>
    </section>

    <section class="if-panel">
        <h2 class="if-subtitle">نصب یا ارتقا روی لینوکس</h2>
        <p class="if-copy">دستور زیر نصب‌کننده رسمی را از مخزن پروژه اجرا می‌کند. برای نصب جدید و ارتقای نسخه قبلی از همین مسیر استفاده کنید؛ راهنمای پیش‌نیازها و نسخه‌های منتشرشده در مخزن قرار دارد.</p>
        <div class="if-code" dir="ltr"><code><?= imonitor_free_escape('curl -fsSL ' . $installer . ' | sudo bash') ?></code></div>
        <div class="if-actions">
            <a class="if-button" href="<?= imonitor_free_escape($installer) ?>">مشاهده نصب‌کننده</a>
            <a class="if-button" href="<?= imonitor_free_escape($repository . '/releases') ?>">نسخه‌ها و بسته‌های رسمی</a>
        </div>
    </section>

    <section class="if-panel">
        <h2 class="if-subtitle">دریافت کد از GitHub یا آینه محلی</h2>
        <p class="if-copy">مخزن GitHub مرجع اصلی کد، راهنما و نسخه‌های پروژه است. آینه محلی هم برای مرور فایل‌ها و دریافت کد با Git در دسترس است.</p>
        <p class="if-code-label">مخزن اصلی</p>
        <div class="if-code" dir="ltr"><code>git clone https://github.com/iranmonitor/imonitor.git</code></div>
        <p class="if-code-label">آینه محلی</p>
        <div class="if-code" dir="ltr"><code><?= imonitor_free_escape('git clone ' . $mirrorClone) ?></code></div>
        <div class="if-actions"><a class="if-button" href="<?= imonitor_free_escape($mirrorBrowse) ?>">مرور فایل‌ها در آینه محلی</a></div>
        <p class="if-note">استفاده شخصی و تجاری از نسخه رسمی بدون تغییر رایگان است. شرایط مطالعه کد، تغییر و بازتوزیع را در <a class="if-link" href="<?= imonitor_free_escape($repository . '/blob/main/LICENSE') ?>">مجوز پروژه</a> بخوانید.</p>
    </section>

    <section class="if-panel">
        <h2 class="if-subtitle">قبلاً لایسنس خریده‌اید؟</h2>
        <p class="if-copy">نسخه جدید iMonitor نیازی به خرید، تمدید، ارتقای پلن یا افزودن اسلات ندارد. سوابق پرداخت و سرویس‌های قبلی در حساب شما حفظ می‌شوند و از داشبورد قابل مشاهده‌اند.</p>
        <div class="if-actions"><a class="if-button" href="/dashboard/services/monitoring/">مشاهده سوابق در داشبورد</a></div>
    </section>
</div>
<?php require_once __DIR__ . '/../../includes/footer/index.php'; ?>
