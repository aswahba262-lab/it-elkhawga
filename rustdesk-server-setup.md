# RustDesk Self-Hosted Server — دليل الإعداد

> **السبب:** RustDesk (الإصدار 1.2+) يتطلب تسجيل دخول على السيرفر العام (rs-ny.rustdesk.com) بسبب إساءة الاستخدام.
> **الحل:** استضافة سيرفر RustDesk (hbbs + hbbr) داخل الشركة — مجاني، open-source، تحكم كامل بدون موافقة.

---

## 1. تثبيت سيرفر RustDesk (على سيرفر الشركة)

### 1.1 تحميل
نزّل أحدث إصدار من: https://github.com/rustdesk/rustdesk-server/releases
(ملف `rustdesk-server-windows-x86_64.zip` أو `rustdesk-server-linux-amd64.zip`)

### 1.2 تشغيل (Windows)
```powershell
# استخرج الملفات إلى C:\RustDesk-Server
cd C:\RustDesk-Server

# hbbs = rendezvous server (port 21115/21116)
# hbbr = relay server (port 21117)
Start-Process -FilePath .\hbbs.exe -ArgumentList "-r 127.0.0.1" -WindowStyle Hidden
Start-Process -FilePath .\hbbr.exe -WindowStyle Hidden
```

### 1.3 المنافذ (Firewall)
```powershell
New-NetFirewallRule -DisplayName "RustDesk hbbs" -Direction Inbound -Protocol TCP -LocalPort 21115,21116 -Action Allow
New-NetFirewallRule -DisplayName "RustDesk hbbr" -Direction Inbound -Protocol TCP -LocalPort 21117 -Action Allow
New-NetFirewallRule -DisplayName "RustDesk hbbs UDP" -Direction Inbound -Protocol UDP -LocalPort 21116 -Action Allow
```

### 1.4 المفتاح العام (Public Key)
بعد تشغيل hbbs، سيُنشأ ملف `id_ed25519.pub` في نفس المجلد. اقرأه:
```powershell
Get-Content C:\RustDesk-Server\id_ed25519.pub
```
انسخ محتواه (سلسلة base64) — ستحتاجه في program المدير.

### 1.5 تشغيل دائم (Scheduled Task)
```powershell
$cmd = 'C:\RustDesk-Server\hbbs.exe -r 127.0.0.1'
schtasks /Create /TN "RustDesk hbbs" /TR "`"$cmd`"" /SC ONSTART /RU SYSTEM /RL HIGHEST /F
schtasks /Create /TN "RustDesk hbbr" /TR "C:\RustDesk-Server\hbbr.exe" /SC ONSTART /RU SYSTEM /RL HIGHEST /F
```

---

## 2. ربط IT ELKHAWGA بسيرفر RustDesk

### 2.1 في برنامج المدير
1. «الربط السحابي» → حقل **RustDesk Server (host:port)**: `IP-السيرفر:21116` (أو دومين: `relay.company.com:21116`).
2. **RustDesk Public Key**: الصق محتوى `id_ed25519.pub`.
3. **RustDesk كلمة السر (Unattended)**: اكتب كلمة سر قوية (للوصول بدون موافقة).
4. «حفظ الإعدادات» → «مزامنة السياسة».

### 2.2 ما يحدث تلقائيًا
- الإعدادات تُرسل للعملاء (عبر policy sync).
- Capture Agent (جلسة المستخدم) يكتب `RustDesk2.toml`:
```
rendezvous_server = 'IP-السيرفر:21116'
key = '<public key>'
```
- Capture Agent يضبط كلمة السر الدائمة: `rustdesk --password <pw>` (بدون نافذة موافقة).
- RustDesk ID يُبلَّغ للمدير → زر «🛠 دعم» يفتح جلسة فورًا.

---

## 3. التحقق
```powershell
# على سيرفر الشركة
Test-NetConnection -ComputerName 127.0.0.1 -Port 21116
Test-NetConnection -ComputerName 127.0.0.1 -Port 21117

# على جهاز العميل (بعد تثبيت + logon)
Get-Content "$env:APPDATA\RustDesk\config\RustDesk2.toml"
& 'C:\Program Files\RustDesk\rustdesk.exe' --get-id
```

في المدير: «الربط السحابي» → RustDesk ID يظهر → «🛠 دعم» → RustDesk يفتح ويتصل **بدون نافذة موافقة**.

---

## 4. ملاحظات
- **لا حاجة لـ VS Code/Rust** — RustDesk binaries جاهزة.
- **الوصول بدون موافقة**: كلمة السر الدائمة تُضبط تلقائيًا من Admin. **لا تشاركها** مع الموظفين.
- **الأمان**: self-hosted server = بياناتك remain within company network (أو VPS الخاص بك).
- **بدائل**: AnyDesk / Quick Assist / TeamViewer (إذا فضّلت SaaS).
- **الترخيص**: RustDesk open-source (AGPL) — free for self-hosting.

---

**ال作者:** Ahmed Wahba
**Idea by:** Zakee Tahawi
**التاريخ:** 2026-11-15
