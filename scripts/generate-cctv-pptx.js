import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import os from 'node:os';

function xmlEscape(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Builds a rich RTL Arabic shape (card, banner, badge, or text block) in OpenXML PresentationML
function makeShape({
  id,
  name,
  x,
  y,
  w,
  h,
  fillHex = null,
  borderHex = null,
  borderPt = 1,
  radius = false,
  paragraphs = [],
  valign = 't',
}) {
  const geom = radius ? 'roundRect' : 'rect';
  const fillXml = fillHex
    ? `<a:solidFill><a:srgbClr val="${fillHex}"/></a:solidFill>`
    : '<a:noFill/>';
  const lnXml = borderHex
    ? `<a:ln w="${Math.round(borderPt * 12700)}"><a:solidFill><a:srgbClr val="${borderHex}"/></a:solidFill></a:ln>`
    : '<a:ln><a:noFill/></a:ln>';

  const parasXml = paragraphs
    .map((p) => {
      const align = p.align || 'r';
      const rtl = p.ltr ? '0' : '1';
      const spaceBefore = p.spaceBeforePt ? `<a:spcBef><a:spcPts val="${p.spaceBeforePt * 100}"/></a:spcBef>` : '';
      const spaceAfter = p.spaceAfterPt ? `<a:spcAft><a:spcPts val="${p.spaceAfterPt * 100}"/></a:spcAft>` : '';
      const runs = (p.runs || [{ text: p.text || '', sizePt: p.sizePt || 18, bold: p.bold, colorHex: p.colorHex || 'F8FAFC', font: p.font || 'Cairo' }])
        .map((r) => {
          const sz = Math.round((r.sizePt || p.sizePt || 18) * 100);
          const b = r.bold !== undefined ? (r.bold ? '1' : '0') : (p.bold ? '1' : '0');
          const clr = r.colorHex || p.colorHex || 'F8FAFC';
          const font = r.font || p.font || 'Tahoma';
          return `<a:r>
            <a:rPr lang="ar-EG" altLang="en-US" sz="${sz}" b="${b}" dirty="0">
              <a:solidFill><a:srgbClr val="${clr}"/></a:solidFill>
              <a:latin typeface="${font}"/>
              <a:cs typeface="${font}"/>
            </a:rPr>
            <a:t>${xmlEscape(r.text)}</a:t>
          </a:r>`;
        })
        .join('');
      return `<a:p>
        <a:pPr algn="${align}" rtl="${rtl}">${spaceBefore}${spaceAfter}</a:pPr>
        ${runs}
      </a:p>`;
    })
    .join('');

  return `<p:sp>
    <p:nvSpPr>
      <p:cNvPr id="${id}" name="${xmlEscape(name)}"/>
      <p:cNvSpPr/>
      <p:nvPr/>
    </p:nvSpPr>
    <p:spPr>
      <a:xfrm>
        <a:off x="${x}" y="${y}"/>
        <a:ext cx="${w}" cy="${h}"/>
      </a:xfrm>
      <a:prstGeom prst="${geom}"><a:avLst/></a:prstGeom>
      ${fillXml}
      ${lnXml}
    </p:spPr>
    <p:txBody>
      <a:bodyPr wrap="square" lIns="180000" tIns="140000" rIns="180000" bIns="140000" anchor="${valign}"/>
      <a:lstStyle/>
      ${parasXml || '<a:p><a:endParaRPr lang="ar-EG"/></a:p>'}
    </p:txBody>
  </p:sp>`;
}

// 16:9 Widescreen dimensions in EMUs: 12192000 x 6858000
const SLIDE_W = 12192000;
const SLIDE_H = 6858000;

function wrapSlideXml(shapesXml, slideNum, totalSlides) {
  const bgShape = makeShape({
    id: 2,
    name: 'BackgroundPlate',
    x: 0,
    y: 0,
    w: SLIDE_W,
    h: SLIDE_H,
    fillHex: '0B1120',
  });
  const topAccent = makeShape({
    id: 3,
    name: 'TopAccentBar',
    x: 0,
    y: 0,
    w: SLIDE_W,
    h: 85000,
    fillHex: '10B981',
  });
  const footerShape = makeShape({
    id: 99,
    name: 'FooterBar',
    x: 500000,
    y: 6380000,
    w: SLIDE_W - 1000000,
    h: 360000,
    valign: 'ctr',
    paragraphs: [
      {
        align: 'l',
        runs: [
          { text: `IT ELKHAWGA Enterprise CCTV  |  شريحة ${slideNum} من ${totalSlides}  |  الربط المباشر عبر الراوتر 100% (0% حمل على أجهزة الموظفين)`, sizePt: 11, bold: true, colorHex: '64748B' },
        ],
      },
    ],
  });

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm>
          <a:off x="0" y="0"/>
          <a:ext cx="0" cy="0"/>
          <a:chOff x="0" y="0"/>
          <a:chExt cx="0" cy="0"/>
        </a:xfrm>
      </p:grpSpPr>
      ${bgShape}
      ${topAccent}
      ${shapesXml}
      ${footerShape}
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>`;
}

function slideHeader({ badgeText, title, subtitle }) {
  return [
    makeShape({
      id: 4,
      name: 'SlideBadge',
      x: 9200000,
      y: 260000,
      w: 2490000,
      h: 420000,
      fillHex: '064E3B',
      borderHex: '10B981',
      borderPt: 1.5,
      radius: true,
      valign: 'ctr',
      paragraphs: [{ text: badgeText, sizePt: 13, bold: true, colorHex: '34D399', align: 'ctr' }],
    }),
    makeShape({
      id: 5,
      name: 'SlideTitle',
      x: 500000,
      y: 230000,
      w: 8550000,
      h: 550000,
      valign: 'ctr',
      paragraphs: [{ text: title, sizePt: 26, bold: true, colorHex: 'F8FAFC', align: 'r' }],
    }),
    makeShape({
      id: 6,
      name: 'SlideSubtitle',
      x: 500000,
      y: 780000,
      w: 11190000,
      h: 420000,
      valign: 'ctr',
      paragraphs: [{ text: subtitle, sizePt: 15, bold: false, colorHex: '94A3B8', align: 'r' }],
    }),
  ].join('');
}

const slides = [];

// ================= SLIDE 1: COVER =================
slides.push(
  [
    makeShape({
      id: 10,
      name: 'CoverCard',
      x: 700000,
      y: 700000,
      w: 10792000,
      h: 5300000,
      fillHex: '111C33',
      borderHex: '1E3A8A',
      borderPt: 2,
      radius: true,
      valign: 'ctr',
      paragraphs: [
        { text: 'منظومة IT ELKHAWGA Enterprise', sizePt: 18, bold: true, colorHex: '38BDF8', align: 'ctr', spaceAfterPt: 12 },
        { text: 'دليل ربط كاميرات الفروع والمخازن (Dahua DVR / XVR)', sizePt: 34, bold: true, colorHex: 'FFFFFF', align: 'ctr', spaceAfterPt: 14 },
        { text: 'الربط المباشر عبر راوتر الفرع 100% (Router Port Forwarding)', sizePt: 24, bold: true, colorHex: '34D399', align: 'ctr', spaceAfterPt: 22 },
        { text: '✔ صفر ضغط أو استهلاك من أجهزة الموظفين (0% CPU & Bandwidth)', sizePt: 17, bold: true, colorHex: 'E2E8F0', align: 'ctr', spaceAfterPt: 8 },
        { text: '✔ يعمل 24 ساعة طوال الأسبوع حتى أثناء إغلاق جميع كمبيوترات الفرع', sizePt: 17, bold: true, colorHex: 'E2E8F0', align: 'ctr', spaceAfterPt: 8 },
        { text: '✔ يدعم البث الحي السريع RTSP + التكبير HD + الصوت المباشر + استرجاع التسجيلات', sizePt: 17, bold: true, colorHex: 'E2E8F0', align: 'ctr', spaceAfterPt: 24 },
        { text: 'Developer: Ahmed Wahba  |  Idea by: Zakee Tahawi', sizePt: 13, bold: true, colorHex: '94A3B8', align: 'ctr' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 2: ARCHITECTURE & BENEFITS =================
slides.push(
  slideHeader({
    badgeText: 'نظرة عامة',
    title: 'كيف يعمل الربط المباشر عبر راوتر الفرع 100%؟',
    subtitle: 'اتصال مباشر بين السيرفر الرئيسي وراوتر الفرع وجهاز الـ DVR دون المرور بأي جهاز كمبيوتر للموظفين',
  }) +
  [
    // Flow boxes (Right to Left: Main Server -> Branch Router -> Branch DVR)
    makeShape({
      id: 11,
      name: 'FlowBox1',
      x: 8300000,
      y: 1400000,
      w: 3390000,
      h: 1750000,
      fillHex: '1E293B',
      borderHex: '38BDF8',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '1️⃣ السيرفر الرئيسي (لوحة الأدمن)', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: 'يتصل مباشرةً بالـ Public IP الخاص براوتر الفرع على البورت 8085 (HTTP) والبورت 554 (RTSP) عند فتح شاشة الكاميرات فقط.', sizePt: 14, colorHex: 'E2E8F0' },
      ],
    }),
    makeShape({
      id: 12,
      name: 'FlowBox2',
      x: 4400000,
      y: 1400000,
      w: 3390000,
      h: 1750000,
      fillHex: '1E293B',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '2️⃣ راوتر الفرع (Port Forwarding)', sizePt: 18, bold: true, colorHex: '34D399', spaceAfterPt: 8 },
        { text: 'يستقبل الطلب من السيرفر على بورت 8085 و 554 ويوجّهه فوراً داخل الشبكة المحلية إلى جهاز الـ DVR (10.10.1.108).', sizePt: 14, colorHex: 'E2E8F0' },
      ],
    }),
    makeShape({
      id: 13,
      name: 'FlowBox3',
      x: 500000,
      y: 1400000,
      w: 3390000,
      h: 1750000,
      fillHex: '1E293B',
      borderHex: 'F59E0B',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '3️⃣ جهاز Dahua DVR بالفرع', sizePt: 18, bold: true, colorHex: 'FBBF24', spaceAfterPt: 8 },
        { text: 'يرسل البث المرئي والصوت المباشر وأسماء الكاميرات والتسجيلات مباشرةً للراوتر ومنه للسيرفر بسرعة فائقة.', sizePt: 14, colorHex: 'E2E8F0' },
      ],
    }),
    makeShape({
      id: 14,
      name: 'BenefitsCard',
      x: 500000,
      y: 3450000,
      w: 11190000,
      h: 2700000,
      fillHex: '0F172A',
      borderHex: '334155',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: 'أهم مزايا هذه الطريقة:', sizePt: 19, bold: true, colorHex: '34D399', spaceAfterPt: 10 },
        { text: '• حماية أجهزة الموظفين 100%: لا يتم إرسال أي مهام كاميرات (cctv_tasks) لأجهزة السيلز أو الفرع نهائياً.', sizePt: 15, bold: true, colorHex: 'F8FAFC', spaceAfterPt: 6 },
        { text: '• استقلالية تامة 24/7: يمكنك متابعة الكاميرات وسماع الصوت وسحب التسجيلات حتى لو كانت كل أجهزة الكمبيوتر في الفرع مطفأة.', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• توفير سرعة الإنترنت في الفرع: البث يعمل فقط لحظة فتح شاشة الكاميرات ويتوقف تلقائياً (0 KB/s) عند إغلاقها.', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• إعداد لمرة واحدة فقط: يتم ضبطه في 3 دقائق لكل فرع جديد من خلال 4 خطوات بسيطة موضحة في الشرائح التالية.', sizePt: 15, colorHex: 'E2E8F0' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 3: STEP 1 - DVR STATIC IP =================
slides.push(
  slideHeader({
    badgeText: 'الخطوة 1 من 4',
    title: 'الخطوة الأولى: تثبيت الـ IP الداخلي لجهاز الـ DVR',
    subtitle: 'من شاشة جهاز الـ Dahua DVR أو من صفحة الويب الخاصة بالـ DVR على الشبكة الداخلية للفرع',
  }) +
  [
    makeShape({
      id: 21,
      name: 'Step1Right',
      x: 6300000,
      y: 1400000,
      w: 5390000,
      h: 4750000,
      fillHex: '1E293B',
      borderHex: '38BDF8',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: 'خطوات الضبط داخل جهاز الـ DVR:', sizePt: 20, bold: true, colorHex: '38BDF8', spaceAfterPt: 12 },
        { text: '1. افتح القائمة الرئيسية للـ DVR (Main Menu).', sizePt: 16, bold: true, colorHex: 'F8FAFC', spaceAfterPt: 8 },
        { text: '2. ادخل على قسم الشبكة (NETWORK) ثم اختر (TCP/IP).', sizePt: 16, bold: true, colorHex: 'F8FAFC', spaceAfterPt: 8 },
        { text: '3. غيّر وضع الشبكة من DHCP إلى Static (ثابت)؛ حتى لا يتغير رقم الـ IP الخاص بالـ DVR عند انقطاع الكهرباء أو إعادة تشغيل الراوتر.', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 12 },
        { text: '4. اضغط Apply / Save لحفظ الإعدادات.', sizePt: 16, bold: true, colorHex: '34D399' },
      ],
    }),
    makeShape({
      id: 22,
      name: 'Step1Left',
      x: 500000,
      y: 1400000,
      w: 5500000,
      h: 4750000,
      fillHex: '0F172A',
      borderHex: '10B981',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: 'القيم القياسية الموصى بها في فروع الشركة:', sizePt: 19, bold: true, colorHex: '34D399', spaceAfterPt: 14 },
        { text: '• وضع العنوان (Mode):  Static', sizePt: 16, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 10 },
        { text: '• عنوان الـ DVR (IPv4 Address):  10.10.1.108', sizePt: 16, bold: true, colorHex: '38BDF8', spaceAfterPt: 4 },
        { text: '   (أو 192.168.1.108 إذا كان راوتر الفرع يوزع 192.168.1.x)', sizePt: 13, colorHex: '94A3B8', spaceAfterPt: 10 },
        { text: '• قناع الشبكة (Subnet Mask):  255.255.255.0', sizePt: 16, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 10 },
        { text: '• البوابة الافتراضية (Default Gateway):  10.10.1.1', sizePt: 16, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 4 },
        { text: '   (يجب أن يكون نفس رقم IP راوتر الفرع الداخلي)', sizePt: 13, colorHex: '94A3B8', spaceAfterPt: 10 },
        { text: '• خادم DNS المفضل:  8.8.8.8  |  البديل:  1.1.1.1', sizePt: 15, colorHex: 'E2E8F0' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 4: STEP 2 - DVR INTERNAL PORTS =================
slides.push(
  slideHeader({
    badgeText: 'الخطوة 2 من 4',
    title: 'الخطوة الثانية: التأكد من أرقام البورتات داخل الـ DVR',
    subtitle: 'من داخل جهاز الـ DVR: الدخول إلى NETWORK ⬅ Connection (أو Port)',
  }) +
  [
    makeShape({
      id: 31,
      name: 'PortCard1',
      x: 8300000,
      y: 1450000,
      w: 3390000,
      h: 2450000,
      fillHex: '1E293B',
      borderHex: '38BDF8',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🌐 HTTP Port', sizePt: 22, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: 'القيمة الافتراضية: 80', sizePt: 20, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 10 },
        { text: 'يُستخدم لجلب الصور الفورية، أسماء الكاميرات، الصوت المباشر، فحص حالة الهارد، واسترجاع مقاطع الفيديو المسجلة.', sizePt: 14, colorHex: 'CBD5E1' },
      ],
    }),
    makeShape({
      id: 32,
      name: 'PortCard2',
      x: 4400000,
      y: 1450000,
      w: 3390000,
      h: 2450000,
      fillHex: '1E293B',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🎥 RTSP Port', sizePt: 22, bold: true, colorHex: '34D399', spaceAfterPt: 8 },
        { text: 'القيمة الافتراضية: 554', sizePt: 20, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 10 },
        { text: 'يُستخدم للبث المرئي المباشر السريع (8-10 إطارات/ثانية) وجودة الـ HD بدون تقطيع.', sizePt: 14, colorHex: 'CBD5E1' },
      ],
    }),
    makeShape({
      id: 33,
      name: 'PortCard3',
      x: 500000,
      y: 1450000,
      w: 3390000,
      h: 2450000,
      fillHex: '1E293B',
      borderHex: 'F59E0B',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🔌 TCP Command Port', sizePt: 22, bold: true, colorHex: 'FBBF24', spaceAfterPt: 8 },
        { text: 'القيمة الافتراضية: 37777', sizePt: 20, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 10 },
        { text: 'البورت القياسي لأجهزة Dahua على الشبكة المحلية.', sizePt: 14, colorHex: 'CBD5E1' },
      ],
    }),
    makeShape({
      id: 34,
      name: 'AudioTipBox',
      x: 500000,
      y: 4150000,
      w: 11190000,
      h: 1950000,
      fillHex: '0F172A',
      borderHex: '10B981',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: '🎙️ تفعيل المايكروفون والصوت على القنوات المزودة بمايك (اختياري):', sizePt: 18, bold: true, colorHex: '34D399', spaceAfterPt: 8 },
        { text: '• من داخل الـ DVR: ادخل إلى CAMERA ⬅ ENCODE (أو Audio/Video).', sizePt: 15, colorHex: 'F8FAFC', spaceAfterPt: 4 },
        { text: '• للقناة الموصّل عليها مايكروفون، اضغط (More Setting) تحت كل من Main Stream و Sub Stream وفعّل خيار (Audio Encode) مع اختيار الصيغة AAC أو G.711A.', sizePt: 15, colorHex: 'E2E8F0' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 5: STEP 3 - ROUTER PORT FORWARDING =================
slides.push(
  slideHeader({
    badgeText: 'الخطوة 3 من 4 (الأهم)',
    title: 'الخطوة الثالثة: فتح البورت في راوتر الفرع (Port Forwarding)',
    subtitle: 'الدخول لصفحة راوتر الفرع (10.10.1.1 أو 192.168.1.1) وتوجيه بورت 8085 وبورت 554 إلى الـ DVR',
  }) +
  [
    makeShape({
      id: 41,
      name: 'RouterSteps',
      x: 500000,
      y: 1380000,
      w: 11190000,
      h: 1850000,
      fillHex: '1E293B',
      borderHex: '38BDF8',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: 'أين تجد إعدادات Port Forwarding داخل راوتر WE / TP-Link / Huawei / ZTE؟', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: '• راوترات WE (Huawei / ZTE): ادخل على Internet ⬅ Security ⬅ Port Forwarding (أو Application ⬅ Port Forwarding).', sizePt: 15, colorHex: 'F8FAFC', spaceAfterPt: 5 },
        { text: '• راوترات TP-Link / D-Link: ادخل على Forwarding (أو NAT Forwarding) ⬅ Virtual Servers.', sizePt: 15, colorHex: 'F8FAFC', spaceAfterPt: 5 },
        { text: '• ملاحظة هامة: إذا وُجد جدار حماية في الراوتر (Firewall Level)، اجعله على الوضع المتوسط/المنخفض أو اسمح بمرور WAN HTTP/RTSP.', sizePt: 14, colorHex: 'FBBF24' },
      ],
    }),
    makeShape({
      id: 42,
      name: 'Rule1Card',
      x: 6250000,
      y: 3420000,
      w: 5440000,
      h: 2730000,
      fillHex: '0F172A',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '✅ القاعدة الأولى (Rule 1): بورت HTTP للكاميرات', sizePt: 18, bold: true, colorHex: '34D399', spaceAfterPt: 10 },
        { text: '• الاسم (Name):  DVR-HTTP', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 6 },
        { text: '• البروتوكول (Protocol):  TCP (أو TCP/UDP)', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 6 },
        { text: '• البورت الخارجي (WAN / External Port):  8085', sizePt: 16, bold: true, colorHex: '38BDF8', spaceAfterPt: 6 },
        { text: '• البورت الداخلي (LAN / Internal Port):  80', sizePt: 16, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• عنوان الجهاز الداخلي (Internal Host IP):  10.10.1.108', sizePt: 16, bold: true, colorHex: 'FBBF24' },
      ],
    }),
    makeShape({
      id: 43,
      name: 'Rule2Card',
      x: 500000,
      y: 3420000,
      w: 5440000,
      h: 2730000,
      fillHex: '0F172A',
      borderHex: '38BDF8',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '✅ القاعدة الثانية (Rule 2): بورت RTSP للبث المباشر', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 10 },
        { text: '• الاسم (Name):  DVR-RTSP', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 6 },
        { text: '• البروتوكول (Protocol):  TCP (أو TCP/UDP)', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 6 },
        { text: '• البورت الخارجي (WAN / External Port):  554', sizePt: 16, bold: true, colorHex: '38BDF8', spaceAfterPt: 6 },
        { text: '• البورت الداخلي (LAN / Internal Port):  554', sizePt: 16, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• عنوان الجهاز الداخلي (Internal Host IP):  10.10.1.108', sizePt: 16, bold: true, colorHex: 'FBBF24' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 6: STEP 4 - ADDING IN IT ELKHAWGA ADMIN =================
slides.push(
  slideHeader({
    badgeText: 'الخطوة 4 من 4',
    title: 'الخطوة الرابعة: إضافة الفرع داخل لوحة IT ELKHAWGA Admin',
    subtitle: 'فتح لوحة الإدارة ⬅ قسم «🎥 كاميرات الفروع (CCTV)» ⬅ زر «➕ إدارة أجهزة DVR»',
  }) +
  [
    makeShape({
      id: 51,
      name: 'AdminFormGuide',
      x: 500000,
      y: 1380000,
      w: 11190000,
      h: 4780000,
      fillHex: '1E293B',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: 'املأ الحقول التالية في نافذة إضافة جهاز DVR جديد:', sizePt: 20, bold: true, colorHex: '34D399', spaceAfterPt: 12 },
        { text: '1️⃣ اسم الفرع أو المخزن: اكتب اسم الفرع بوضوح (مثال: Doki أو maadi أو October أو مخزن العاشر).', sizePt: 16, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 8 },
        { text: '2️⃣ طريقة الاتصال بجهاز الـ DVR: اختر الخيار الأول الافتراضي:', sizePt: 16, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 4 },
        { text: '     «🌐 راوتر الفرع مباشر 100% (Port Forwarding 24/7 بدون أجهزة الموظفين)»', sizePt: 16, bold: true, colorHex: '34D399', spaceAfterPt: 10 },
        { text: '3️⃣ الـ Public IP لراوتر الفرع: اكتب الـ IP الخارجي لراوتر الفرع (تستخرجه من خانة IP بجوار أي جهاز بالفرع في قائمة الأجهزة، مثل 154.182.208.246).', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 8 },
        { text: '4️⃣ منفذ HTTP بالراوتر:  8085    |    منفذ RTSP بالراوتر:  554', sizePt: 16, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: '5️⃣ عنوان IP الداخلي للـ DVR:  10.10.1.108    |    منفذ HTTP الداخلي:  80    |    عدد الكاميرات: 8 أو 16', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 8 },
        { text: '6️⃣ اسم المستخدم وكلمة المرور: اكتب admin وكلمة سر جهاز الـ DVR.', sizePt: 15, colorHex: 'E2E8F0', spaceAfterPt: 10 },
        { text: '7️⃣ اضغط «🔌 فحص الاتصال وسحب أسماء الكاميرات» للتأكد من فتح البورت، ثم اضغط «💾 حفظ جهاز الـ DVR».', sizePt: 16, bold: true, colorHex: 'FBBF24' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 7: LIVE REFERENCE TABLE OF CURRENT BRANCHES =================
slides.push(
  slideHeader({
    badgeText: 'جدول مرجعي',
    title: 'بيانات الربط المباشر الحالية للفروع المسجلة بالنظام',
    subtitle: 'جميع الفروع التالية مضبوطة على وضع الراوتر المباشر 100% (بدون أي تحميل على أجهزة الموظفين)',
  }) +
  [
    makeShape({
      id: 61,
      name: 'Branch1Card',
      x: 8300000,
      y: 1450000,
      w: 3390000,
      h: 4650000,
      fillHex: '111C33',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🏢 فرع المعادي (maadi)', sizePt: 20, bold: true, colorHex: '34D399', spaceAfterPt: 12 },
        { text: '• وضع الربط: راوتر مباشر 100%', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 8 },
        { text: '• Public IP الراوتر:', sizePt: 14, colorHex: '94A3B8', spaceAfterPt: 2 },
        { text: '  156.215.178.244', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: '• بورت HTTP بالراوتر: 8085 (مفتوح ✔)', sizePt: 14, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• بورت RTSP بالراوتر: 554 (مفتوح ✔)', sizePt: 14, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• IP الـ DVR الداخلي: 10.10.1.108:80', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• عدد القنوات: 8 كاميرات', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• استهلاك أجهزة الفرع: 0%', sizePt: 15, bold: true, colorHex: '34D399' },
      ],
    }),
    makeShape({
      id: 62,
      name: 'Branch2Card',
      x: 4400000,
      y: 1450000,
      w: 3390000,
      h: 4650000,
      fillHex: '111C33',
      borderHex: '10B981',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🏢 فرع الدقي (Doki)', sizePt: 20, bold: true, colorHex: '34D399', spaceAfterPt: 12 },
        { text: '• وضع الربط: راوتر مباشر 100%', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 8 },
        { text: '• Public IP الراوتر:', sizePt: 14, colorHex: '94A3B8', spaceAfterPt: 2 },
        { text: '  154.182.208.246', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: '• بورت HTTP بالراوتر: 8085 (مفتوح ✔)', sizePt: 14, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• بورت RTSP بالراوتر: 554 (مفتوح ✔)', sizePt: 14, bold: true, colorHex: '34D399', spaceAfterPt: 6 },
        { text: '• IP الـ DVR الداخلي: 10.10.1.108:80', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• عدد القنوات: 8 كاميرات', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• استهلاك أجهزة الفرع: 0%', sizePt: 15, bold: true, colorHex: '34D399' },
      ],
    }),
    makeShape({
      id: 63,
      name: 'Branch3Card',
      x: 500000,
      y: 1450000,
      w: 3390000,
      h: 4650000,
      fillHex: '111C33',
      borderHex: 'F59E0B',
      borderPt: 2,
      radius: true,
      paragraphs: [
        { text: '🏢 فرع أكتوبر (October)', sizePt: 20, bold: true, colorHex: 'FBBF24', spaceAfterPt: 12 },
        { text: '• وضع الربط: راوتر مباشر 100%', sizePt: 15, bold: true, colorHex: 'FFFFFF', spaceAfterPt: 8 },
        { text: '• Public IP الراوتر:', sizePt: 14, colorHex: '94A3B8', spaceAfterPt: 2 },
        { text: '  197.47.130.110', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 8 },
        { text: '• بورت HTTP المطلوب بالراوتر: 8085 -> 80', sizePt: 14, bold: true, colorHex: 'FBBF24', spaceAfterPt: 6 },
        { text: '• بورت RTSP المطلوب بالراوتر: 554 -> 554', sizePt: 14, bold: true, colorHex: 'FBBF24', spaceAfterPt: 6 },
        { text: '• IP الـ DVR الداخلي: 10.10.1.108:80', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• عدد القنوات: 16 كاميرا', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 6 },
        { text: '• استهلاك أجهزة الفرع: 0%', sizePt: 15, bold: true, colorHex: '34D399' },
      ],
    }),
  ].join('')
);

// ================= SLIDE 8: TROUBLESHOOTING & QUICK CHECKLIST =================
slides.push(
  slideHeader({
    badgeText: 'قائمة المراجعة',
    title: 'قائمة الفحص السريع وحل المشكلات الشائعة',
    subtitle: 'ماذا تفعل إذا لم تفتح الكاميرا بعد إضافة فرع جديد؟',
  }) +
  [
    makeShape({
      id: 71,
      name: 'ChecklistCard',
      x: 500000,
      y: 1380000,
      w: 11190000,
      h: 4780000,
      fillHex: '1E293B',
      borderHex: '38BDF8',
      borderPt: 1.5,
      radius: true,
      paragraphs: [
        { text: '1. إذا ظهرت رسالة «بورت راوتر الفرع (8085) غير مفتوح بعد»:', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 4 },
        { text: '   • تأكد من داخل صفحة راوتر الفرع أن قاعدة Port Forwarding مفعّلة (Enable = On) وموجّهة إلى الـ IP الصحيح للـ DVR (10.10.1.108).', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 4 },
        { text: '   • تأكد أن كابل الشبكة (LAN) موصّل جيداً في الـ DVR وأن الـ DVR يفتح محلياً من داخل الفرع على http://10.10.1.108.', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 12 },
        { text: '2. إذا تغيّر الـ Public IP لراوتر الفرع بعد انقطاع الكهرباء عن الراوتر:', sizePt: 18, bold: true, colorHex: '34D399', spaceAfterPt: 4 },
        { text: '   • إذا لم يكن للفرع Static IP من شركة الإنترنت، انسخ الـ IP الجديد الظاهر بجوار جهاز الفرع في لوحة الأدمن وحدّثه في خانة «الـ Public IP لراوتر الفرع».', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 12 },
        { text: '3. إذا ظهرت رسالة «اسم المستخدم أو كلمة مرور الـ DVR غير صحيحة (HTTP 401)»:', sizePt: 18, bold: true, colorHex: 'FBBF24', spaceAfterPt: 4 },
        { text: '   • هذا يعني أن البورت مفتوح بنجاح ووصل للـ DVR! فقط تأكد من كتابة اسم المستخدم (admin) وكلمة مرور الـ DVR الصحيحة ثم اضغط حفظ.', sizePt: 14, colorHex: 'E2E8F0', spaceAfterPt: 12 },
        { text: '4. لسحب أسماء الكاميرات تلقائياً من الـ DVR:', sizePt: 18, bold: true, colorHex: '38BDF8', spaceAfterPt: 4 },
        { text: '   • اضغط زر «🏷️ سحب الأسماء» بجوار اسم الفرع في قائمة أجهزة الـ DVR المسجلة ليتم تحديث أسماء جميع القنوات بضغطة واحدة.', sizePt: 14, colorHex: 'E2E8F0' },
      ],
    }),
  ].join('')
);

// Build OpenXML package structure in a temporary folder and zip into .pptx
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'itk-pptx-'));

const mkdir = (rel) => fs.mkdirSync(path.join(tmpDir, rel), { recursive: true });
const write = (rel, content) => fs.writeFileSync(path.join(tmpDir, rel), content, 'utf8');

mkdir('_rels');
mkdir('docProps');
mkdir('ppt/_rels');
mkdir('ppt/slides/_rels');
mkdir('ppt/slideLayouts/_rels');
mkdir('ppt/slideMasters/_rels');
mkdir('ppt/theme');

const slideTypesXml = slides
  .map((_, i) => `<Override PartName="/ppt/slides/slide${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>`)
  .join('\n  ');

write(
  '[Content_Types].xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  ${slideTypesXml}
</Types>`
);

write(
  '_rels/.rels',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`
);

write(
  'docProps/core.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>دليل ربط كاميرات الفروع عبر الراوتر 100% - IT ELKHAWGA</dc:title>
  <dc:creator>Ahmed Wahba - IT ELKHAWGA</dc:creator>
  <cp:lastModifiedBy>Ahmed Wahba</cp:lastModifiedBy>
</cp:coreProperties>`
);

write(
  'docProps/app.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Microsoft Office PowerPoint</Application>
  <PresentationFormat>Widescreen</PresentationFormat>
  <Slides>${slides.length}</Slides>
  <Company>ELKHAWAGA Company</Company>
</Properties>`
);

const sldIdLstXml = slides
  .map((_, i) => `<p:sldId id="${256 + i}" r:id="rId${i + 2}"/>`)
  .join('\n    ');

write(
  'ppt/presentation.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
                saveSubsetFonts="1">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>
    ${sldIdLstXml}
  </p:sldIdLst>
  <p:sldSz cx="${SLIDE_W}" cy="${SLIDE_H}"/>
  <p:notesSz cx="${SLIDE_H}" cy="${SLIDE_W}"/>
</p:presentation>`
);

const presRelsXml = slides
  .map((_, i) => `<Relationship Id="rId${i + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${i + 1}.xml"/>`)
  .join('\n  ');

write(
  'ppt/_rels/presentation.xml.rels',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
  ${presRelsXml}
  <Relationship Id="rId${slides.length + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
</Relationships>`
);

write(
  'ppt/slideMasters/slideMaster1.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgPr>
        <a:solidFill><a:srgbClr val="0B1120"/></a:solidFill>
        <a:effectLst/>
      </p:bgPr>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="dk1" tx1="lt1" bg2="dk2" tx2="lt2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
</p:sldMaster>`
);

write(
  'ppt/slideMasters/_rels/slideMaster1.xml.rels',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>`
);

write(
  'ppt/slideLayouts/slideLayout1.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             type="blank" preserve="1">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>`
);

write(
  'ppt/slideLayouts/_rels/slideLayout1.xml.rels',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>`
);

write(
  'ppt/theme/theme1.xml',
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="IT ELKHAWGA Theme">
  <a:themeElements>
    <a:clrScheme name="IT ELKHAWGA">
      <a:dk1><a:srgbClr val="0B1120"/></a:dk1>
      <a:lt1><a:srgbClr val="F8FAFC"/></a:lt1>
      <a:dk2><a:srgbClr val="1E293B"/></a:dk2>
      <a:lt2><a:srgbClr val="E2E8F0"/></a:lt2>
      <a:accent1><a:srgbClr val="38BDF8"/></a:accent1>
      <a:accent2><a:srgbClr val="10B981"/></a:accent2>
      <a:accent3><a:srgbClr val="F59E0B"/></a:accent3>
      <a:accent4><a:srgbClr val="EF4444"/></a:accent4>
      <a:accent5><a:srgbClr val="8B5CF6"/></a:accent5>
      <a:accent6><a:srgbClr val="EC4899"/></a:accent6>
      <a:hlink><a:srgbClr val="38BDF8"/></a:hlink>
      <a:folHlink><a:srgbClr val="94A3B8"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="IT ELKHAWGA Fonts">
      <a:majorFont><a:latin typeface="Tahoma"/><a:ea typeface=""/><a:cs typeface="Tahoma"/></a:majorFont>
      <a:minorFont><a:latin typeface="Tahoma"/><a:ea typeface=""/><a:cs typeface="Tahoma"/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="IT ELKHAWGA">
      <a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
      <a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>
      <a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
      <a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>`
);

slides.forEach((sXml, idx) => {
  const num = idx + 1;
  write(`ppt/slides/slide${num}.xml`, wrapSlideXml(sXml, num, slides.length));
  write(
    `ppt/slides/_rels/slide${num}.xml.rels`,
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>`
  );
});

const outPptx1 = 'C:\\Users\\IT APP\\Desktop\\blockwebsite\\دليل_ربط_كاميرات_الفروع_عبر_الراوتر.pptx';
const outPptx2 = 'C:\\Users\\IT APP\\Desktop\\tools\\دليل_ربط_كاميرات_الفروع_عبر_الراوتر.pptx';

for (const p of [outPptx1, outPptx2]) {
  try {
    if (fs.existsSync(p)) fs.unlinkSync(p);
  } catch (_) {}
}

const psZip = `
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$src = (Get-Item -LiteralPath '${tmpDir.replace(/'/g, "''")}').FullName.TrimEnd('\\')
$dst1 = '${outPptx1.replace(/'/g, "''")}'
$dst2 = '${outPptx2.replace(/'/g, "''")}'
$zip = [System.IO.Compression.ZipFile]::Open($dst1, [System.IO.Compression.ZipArchiveMode]::Create)
Get-ChildItem -LiteralPath $src -Recurse -File | ForEach-Object {
  $rel = $_.FullName.Substring($src.Length + 1).Replace('\\', '/')
  [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
}
$zip.Dispose()
Copy-Item -LiteralPath $dst1 -Destination $dst2 -Force
Remove-Item -LiteralPath $src -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PPTX_CREATED_OK: $dst1 ($(Get-Item -LiteralPath $dst1 | Select-Object -ExpandProperty Length) bytes)"
`;

execFileSync('powershell.exe', ['-NoProfile', '-Command', psZip], { stdio: 'inherit' });
