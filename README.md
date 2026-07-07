# الدرع الموزع AlDir AlMozza

الدرع الموزع شبكة دفاع تشاركية محلية: تستقبل إشارات تهديد من عدة مصادر، تطبعها إلى fingerprints، تجمعها، وتصدر blocklist حسب الشدة والإجماع.

## آلية العمل

1. `convert-nvd` يحول CVE إلى إشارات تهديد.
2. `aggregate` يجمع الإشارات ويصدر blocklist.
3. `batch/stress` يقيسان التجميع والانهيار.

## تشغيل سريع

```powershell
python -m aldir_almozza.cli convert-nvd
python -m aldir_almozza.cli batch
```

## بيانات الاختبار

المصدر: NVD CVE API 2.0 المحفوظ في `C:\Projects\kashif` بعدد 12,000 سجل.

## آخر نتائج

- الاختبارات الذاتية: 2/2 ناجحة.
- بيانات الإنترنت: 12,000 CVE تحولت إلى 12,000 إشارة، منها 5,375 HIGH/CRITICAL.
- Benchmark: 12,000 إشارة، blocklist=5,375، errors=0، aggregation latency=207.93ms.
- Stress: 36,000 إشارة عبر 3 تجميعات، errors=0، p99=230.44ms، peak memory=10.30MB.

## تحسينات إنتاجية 2026-07-04

- كل إشارة تُطبع إلى fingerprint لا يكشف تفاصيل زائدة.
- blocklist يعتمد على الشدة وعدد المصادر، تمهيداً لإجماع CrowdSec-like.
- batch/stress يقيسان التجميع الكامل لا فحص صف مفرد.

## التشغيل المؤسسي (Enterprise) — v1.0.0

- **خدمة تجميع إشارات HTTP**: `python -m aldir_almozza.cli serve` → `POST /api/aggregate {"signals": [...]}` يعيد blocklist إجماعياً بالبصمات.
- **نقاط فحص**: `/api/health` (مفتوح) · `/api/version` · `/api/metrics`.
- **تهيئة عبر البيئة**: متغيرات `ALDIR_*` — انظر `docs/OPERATIONS.md`.
- **مصادقة**: `ALDIR_API_KEY` → ترويسة `X-API-Key`. **سجلات JSON**: `logs\aldir-almozza.service.jsonl`.
