# نقل الـ Relay إلى سيرفر الشركة (Windows PC)

## 1) على لابتوبك (تصدير البيانات)
```powershell
cd C:\Users\PC\Desktop\blockwebsite
powershell -ExecutionPolicy Bypass -File relay\export-laptop.ps1
```
هيقفل الـ Relay مؤقتًا وينسخ إلى `relay\migrate\`:
- `relay.db` (الأجهزة المسجّلة والمجموعات والسياسات)
- `admin-key.txt` (نفس مفتاح المدير)
- ملفات WAL إن وُجدت

> مهم: بعد التصدير، لابتوبك توقف عن العمل كـ Relay. لا تشغّل المهمة القديمة مرة أخرى إلا لو هترجع.

## 2) على سيرفر الشركة
1. ثبّت **Node.js LTS** (https://nodejs.org).
2. انسخ مجلد `relay` كامل (بما فيه `migrate\` و`server.js` و`run-relay.cmd` و`install-server.ps1`) إلى مثلاً:
```
C:\IT-ELKHAWGA\relay
```
3. افتح PowerShell **كمسؤول** وشغّل:
```powershell
cd C:\IT-ELKHAWGA\relay
powershell -ExecutionPolicy Bypass -File install-server.ps1
```
هيعمل:
- نسخ قاعدة البيانات والمفتاح إلى `C:\ProgramData\IT-ELKHAWGA-Relay`
- مهمة `IT ELKHAWGA Relay` تعمل عند بدء التشغيل بحساب SYSTEM
- فتح المنفذ 8790 في جدار الحماية
- اختبار `/healthz` وطباعة الرابط المحلي + `ADMIN_KEY`

## 3) تعريض السيرفر على الإنترنت (HTTPS)

### الخيار A: Tailscale Funnel (مجاني، سريع)
```powershell
# على سيرفر الشركة
# نزّل Tailscale وثبّته، ثم:
tailscale up
# فعّل HTTPS: https://login.tailscale.com/admin/dns  (Enable HTTPS)
# فعّل Funnel: https://login.tailscale.com/f/funnel?node=<node-id> (يظهر بالرابط عند تشغيل الأمر)
tailscale funnel --bg 8790
tailscale funnel status
```
هيديك رابطًا مثل:
```
https://اسم-السيرفر.<tailnet>.ts.net
```
> الرابط يعتمد على اسم الجهاز؛ لتثبيته استخدم الخيار B.

### الخيار B: دومين ثابت (الأفضل)
لو تملك دومينًا على Cloudflare (مثل `elkhawaga.com`):
```powershell
cloudflared tunnel login
cloudflared tunnel create it-elkhawga
cloudflared tunnel route dns it-elkhawga relay.elkhawaga.com
# ملف إعداد بـ ingress إلى http://localhost:8790 ثم:
cloudflared tunnel run it-elkhawga
```
النتيجة رابط ثابت: `https://relay.elkhawaga.com` لا يتغير مهما غيّرت السيرفر.

## 4) ربط برنامج المدير
- في Admin → «الربط السحابي»: ضع الرابط الجديد + نفس `ADMIN_KEY`.
- اضغط «حفظ الإعدادات» ثم «مزامنة السياسة».

## 5) إعادة توجيه الأجهزة (مرة واحدة عند تغيير الرابط)
الأجهزة تحفظ رابط الـ Relay. عند تغييره:
- على كل جهاز: Client → «الربط السحابي» → اكتب **الرابط الجديد** + **رمز ربط جديد** من المدير → «ربط الجهاز».

> لتجنّب هذه الخطوة مستقبلاً: استخدم **دومين ثابت** (الخيار B) بدل رابط Tailscale المتغيّر.

## 6) التحقق النهائي
| الاختبار | الأمر |
|---|---|
| الـ Relay يعمل | `http://127.0.0.1:8790/healthz` |
| من شبكة الشركة | `http://IP-السيرفر:8790/healthz` |
| من الإنترنت | `https://الرابط/healthz` |
| المهمة | `schtasks /Query /TN "IT ELKHAWGA Relay"` |

## ملاحظات
- برنامج **Admin** لا يحتاج أن يكون شغّالًا دائمًا؛ الأجهزة تستمر على آخر سياسة.
- **Client** يجب أن يكون 03:28 أو أحدث (بروكسي/تحديد سرعة + حالة الحجب).
- لا توزّع نسخة Admin (تحتوي `ADMIN_KEY`).
- احتفظ بنسخة احتياطية من `relay\migrate\relay.db` و`admin-key.txt`.
