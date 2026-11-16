# Phase 3 — السرقة/الاختلاس (Theft/Embezzlement)

> **المشروع:** IT ELKHAWGA (Ahmed Wahba) — Tauri v2 Admin/Client + Relay
> **المرحلة:** 3 — كشف ومنع سرقة/اختلاس البيانات، التلاعب، والوصول غير المصرح
> **اللغة:** العربية
> **الحالة:** تأسيس (Foundation) — جاهز للتوسعة

---

## 1. الهدف (Objective)

السرقة/الاختلاس في سياق نظام حماية أجهزة الشركة تشمل:

1. **سرقة البيانات (Data Exfiltration)** — نقل ملفات/بيانات حساسة خارج الشركة (USB، سحابة، بريد، تحميل كبير).
2. **التحايل على الحماية (Bypass)** — تعطيل الـ Agent، تعديل hosts/proxy، إيقاف المهمة (Task)، إزالة سياسات المتصفح.
3. **الوصول غير المصرح** — استخدام جهاز دون إذن، تغيير كلمة السر، فصل الربط.
4. **عدم وجود أثر (No Audit)** — عمليات حساسة بدون سجل.

**Goal of Phase 3:** كشف + منع + تدقيق (Detect, Prevent, Audit).

---

## 2. النطاق (Scope)

### 2.1 داخل النطاق (In Scope)
- كشف التلاعب (Tamper Detection) في Agent.
- كشف تسرب البيانات (Data Exfiltration) عبر البروكسي (حجم، hosts مشبوهة).
- مراقبة أجهزة USB (إدراج/إزالة) + حظر اختياري.
- سجل تدقيق (Audit Log) على Relay (أوامر، تغييرات، محاولات فاشلة).
- لوحة تنبيهات (Alerts) في Admin + إقرار (Acknowledge).
- إعدادات حساسية (Thresholds) قابلة للتكوين.
- حماية Agent (anti-kill, self-repair).

### 2.2 خارج النطاق (Out of Scope — مراحل لاحقة)
- DLP (Data Loss Prevention) على مستوى الملفات (تشفير/تصنيف).
- EDR (Endpoint Detection & Response) كامل.
- SIEM integration.
- Zero-Trust network.

---

## 3. التصميم (Architecture)

```
┌──────────────┐  poll/alerts  ┌──────────────┐  poll/alerts  ┌──────────────┐
│ Client Agent │ ─────────────►│  Relay v3+   │◄───────────── │ Admin App    │
│ (SYSTEM)     │  (tamper,     │  (alerts,    │  (view, ack)  │ (UI)         │
│ + Capture    │   usb, exfil) │   audit)     │               │              │
└──────────────┘               └──────────────┘               └──────────────┘
       │                              │
       │ local proxy :8080            │ SQLite (alerts/audit)
       ▼                              ▼
   site logging + size tracking
```

### 3.1 مكونات جديدة
| المكوّن | الملف | الوظيفة |
|---|---|---|
| Alerts table | `relay/server.js` | تخزين تنبيهات الأجهزة |
| Audit table | `relay/server.js` | سجل تدقيق |
| Tamper detector | `src-tauri/src/agent.rs` | كشف hosts/proxy/task tampering |
| Exfil detector | `src-tauri/src/proxy.rs` | كشف رفع كبير/hosts مشبوهة |
| USB monitor | `src-tauri/src/agent.rs` (thread) | كشف إدراج USB |
| Admin alerts UI | `web/index.html` | badge + list + ack |
| Settings | `web/index.html` + relay | thresholds, enable/disable |

---

## 4. نموذج البيانات (Data Model)

### 4.1 alerts
```sql
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  type TEXT NOT NULL,        -- tamper | exfil | usb | auth_fail | bypass
  severity TEXT NOT NULL,    -- low | medium | high | critical
  message TEXT NOT NULL,
  meta TEXT DEFAULT '{}',    -- JSON
  created_at INTEGER NOT NULL,
  acked_at INTEGER,
  acked_by TEXT
);
```

### 4.2 audit_log
```sql
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,       -- admin | device:<id> | system
  action TEXT NOT NULL,      -- block | unblock | enroll | password_change | ...
  target TEXT,               -- device_id or group_id
  result TEXT,               -- ok | fail
  meta TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL
);
```

---

## 5. API (Relay)

| Method | Path | Auth | الوصف |
|---|---|---|---|
| POST | `/api/v1/device/alert` | device token | جهاز يرسل تنبيه |
| GET | `/api/v1/admin/alerts` | admin key | list (filter: type, severity, acked) |
| POST | `/api/v1/admin/alerts/:id/ack` | admin key | إقرار تنبيه |
| GET | `/api/v1/admin/audit` | admin key | سجل تدقيق (paginated) |

---

## 6. خوارزميات الكشف (Detection)

### 6.1 Tamper Detection (Agent)
كل poll (~3s):
1. تحقق من `hosts` marker (`# === BLOCKED SITES START/END ===`) — لو الحجب فعال ولا marker ⇒ tamper.
2. تحقق من `ProxyEnable` في HKLM/HKCU — لو الحجب فعال والـ proxy disabled ⇒ tamper.
3. تحقق من Chrome/Edge policy keys — لو الحجب فعال والـ policy missing ⇒ tamper.
4. تحقق من Scheduled Task `IT ELKHAWGA Agent` — لو غير موجود ⇒ tamper.
5. لو tamper ⇒ اضبط `pending_alert = {type:'tamper', severity:'high', message:'...'}` وأرسله في poll.

### 6.2 Data Exfiltration (Proxy)
- تتبع حجم الرفع لكل host.
- لو `uploaded_bytes(host) > threshold (default 50 MB)` في 10 min ⇒ alert `exfil`.
- hosts مشبوهة (مثلاً `mega.nz`, `dropbox.com`, `drive.google.com`, `wetransfer.com`) ⇒ alert `exfil` فورًا (severity medium).
- إعداد thresholds من Admin (قابل للتعديل).

### 6.3 USB Monitoring (Agent thread)
- WMI query: `SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2` (insertion).
- أو polling `Get-WmiObject Win32_DiskDrive` (InterfaceType=USB) every 10s.
- عند إدراج ⇒ alert `usb` (severity medium/high حسب policy).
- حظر (optional): تعطيل USB storage عبر registry (`HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start = 4`).

### 6.4 Auth Failures
- كل محاولة كلمة سر فاشلة ⇒ alert `auth_fail` (low)؛ بعد N محاولات ⇒ `high` + قفل (lockout).

---

## 7. التدقيق (Audit Log)

كل إجراء حساس يُسجَّل:
- block / unblock (admin + agent)
- password change
- device enroll / disconnect
- relay config change
- alert acknowledge
- group create/update/delete
- speed throttle set/clear

ال actor: `admin`, `device:<id>`, `system`.

---

## 8. التحديات والحلول (Challenges & Resolutions)

### C1. Agent يعمل كـ SYSTEM (Session 0) — cannot capture user session
**التحدي:** USB events، screen capture، user activity.
**الحل:** thread منفصل داخل `--agent` (SYSTEM) لـ USB via WMI (يعمل من Session 0). For screen capture استخدم `--capture-agent` (user session) — نمط Phase 2.

### C2. Proxy لا يرى HTTPS payload (مشفر)
**التحدي:** لا يمكن فحص محتوى HTTPS.
**الحل:** سجّل **hostname** (من CONNECT) + **حجم** + **مدة**. كشف exfil بالحجم/الـ hosts، ليس المحتوى. لفحص المحتوى لازم MITM (خارج النطاق).

### C3. False positives (تنبيهات كاذبة)
**التحدي:** legitimately large uploads (backup، Windows Update).
**الحل:** allowlist للـ hosts (backup servers، update servers)، thresholds قابلة للتعديل، severity levels، admin ack.

### C4. Agent tampering (تعطيل الخدمة)
**التحدي:** موظف يوقف الـ Agent أو المهمة.
**الحل:** 
- Watchdog (موجود Phase 2) يعيد تشغيله.
- Self-repair: عند كل poll يتحقق من Task/registry/hosts ويُصلح (re-apply) + يرسل alert.
- Hidden file attributes / ACL (Phase 2) لمنع التعديل.
- إعداد policy: "alert if offline > 5 min".

### C5. USB حظر (قد يكسر أجهزة الإدخال)
**التحدي:** تعطيل USBSTOR يعطّل كل USB storage (بما فيها USB drives مشبوهة).
**الحل:** اختياري (enable/disable per device/group)، افتراضيًا **monitor only** (تنبيه فقط).

### C6. Performance (Proxy logging)
**التحدي:** تسجيل كل host يبطئ.
**الحل:** in-memory ring buffer (40 hosts)، flush إلى Relay كل poll (3s). Dedup by host.

### C7. Privacy / Compliance
**التحدي:** تسجيل المواقع قد يخالف سياسات الخصوصية.
**الحل:** عرض "privacy notice" للموظف، retention policy (auto-delete after N days)، admin-only access، audit of who viewed.

### C8. Relay schema migration
**التحدي:** إضافة tables/columns لقواعد بيانات موجودة.
**الحل:** `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN` مع try/catch (نمط Phase 2).

---

## 9. خطة التنفيذ (Implementation Plan)

### Sprint 1 — Tamper + Audit (أسبوع 1)
- [ ] Relay: `alerts` + `audit_log` tables + endpoints.
- [ ] Agent: tamper detection (hosts/proxy/task) → alert.
- [ ] Admin: alerts badge + list + ack.
- [ ] Audit logging for all sensitive actions (block/unblock/password/config).

### Sprint 2 — Exfiltration + USB (أسبوع 2)
- [ ] Proxy: size tracking + threshold alerts + suspicious host list.
- [ ] Agent: USB monitor thread + optional block.
- [ ] Admin: settings page (thresholds, enable/disable, USB policy).
- [ ] Admin: alert filters (type/severity/acked).

### Sprint 3 — Hardening + Polish (أسبوع 3)
- [ ] Self-repair / anti-kill.
- [ ] Alert retention + auto-cleanup.
- [ ] Export audit log (CSV).
- [ ] Privacy notice + consent dialog.
- [ ] Performance tuning + tests.

---

## 10. معايير القبول (Acceptance Criteria)

- [ ] Agent يكتشف تعطيل proxy ويرسل alert خلال ≤ 6s.
- [ ] Admin يعرض alert مع severity وack.
- [ ] Proxy يُسجّل host + حجم، ويرسل alert عند تجاوز threshold.
- [ ] USB insertion يُسجَّل كـ alert within 10s.
- [ ] Audit log يحتوي كل block/unblock/password change مع actor + timestamp.
- [ ] لا false positive على Windows Update (allowlist).
- [ ] Agent self-repairs within 1 poll after tampering.
- [ ] Performance: proxy overhead < 5% CPU on idle.

---

## 11. المخاطر والافتراضات (Risks & Assumptions)

| المخاطر | الاحتمال | التأثير | التخفيف |
|---|---|---|---|
| False positives (exfil) | متوسط | متوسط | allowlist + thresholds قابلة للتعديل |
| Privacy complaints | منخفض | عالي | consent + retention + admin-only |
| Agent kill by admin user | منخفض | عالي | watchdog + self-repair + ACL |
| Performance degradation | منخفض | متوسط | ring buffer + batched reporting |
| Schema migration fail | منخفض | متوسط | try/catch + IF NOT EXISTS |

**الافتراضات:**
- الأجهزة على Windows 10/11.
- Agent يعمل كـ SYSTEM (موجود).
- Relay v3 (long-poll) deployed.
- Admin has a configured password (Phase 2 security).

---

## 12. الملفات المتأثرة (Affected Files)

| ملف | التغيير |
|---|---|
| `relay/server.js` | alerts + audit tables + endpoints |
| `src-tauri/src/agent.rs` | tamper detection, USB thread, alert reporting |
| `src-tauri/src/proxy.rs` | size tracking, exfil detection, denied list (موجود) |
| `src-tauri/src/commands.rs` | audit logging (extend existing) |
| `src-tauri/src/common.rs` | alert helpers, thresholds config |
| `web/index.html` | alerts badge + panel + settings |
| `web/styles/theme.css` | alert severity colors (موجود جزئيًا) |
| `throttle.ps1` | (لا تغيير) |

---

## 13. ملاحظة تنفيذ (Implementation Note)

هذه الوثيقة هي **خريطة طريق (roadmap)**. Sprint 1 (Tamper + Audit) هو **الخطوة التالية** بعد Phase 2 (التي ما زالت قيد التحقق). recommend completing Phase 2 verification before starting Phase 3.

---

**ال作者:** Ahmed Wahba
**المطور (Idea):** Zakee Tahawi
**الإصدار:** 1.0 (Foundation)
**التاريخ:** 2026-11-15
