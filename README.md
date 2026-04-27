# webTracker

SSL domain takip ve indirilebilir sertifika dosyaları. Linux üzerinde çalışır. **Domain’ler başka sunucuda** olduğu için doğrulama **dosya yükleme (HTTP-01 manuel)** ile yapılır: sayfada çıkan dosyayı domain’in yayınlandığı sunucuya yüklersiniz.

## Ne yapar?

- Domain ekleyip listelersiniz; SSL bitiş süresi gösterilir.
- **Yenile**: Certbot **HTTP-01 (manuel)** ile sertifika başlatır. Sayfada **dosya adı ve içeriği** çıkar. Bu dosyayı domain’in yayınlandığı sunucuda `.well-known/acme-challenge/` altına yükleyip (FTP/SFTP veya hosting paneli) “Dosyayı yükledim, tamamla” butonuna basarsınız. Sertifikalar proje klasöründe `certs/live/DOMAIN/` altında oluşur.
- **İndir**: .crt, fullchain, cabundle, .key dosyalarını indirirsiniz (başka sunucuda kullanmak için).

## Kurulum

```bash
cd webTracker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Çalıştırma

```bash
./run.sh
# veya
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Tarayıcı: http://sunucu:8000

## Ortam değişkenleri (isteğe bağlı)

| Değişken | Varsayılan |
|----------|------------|
| `WEBTRACKER_DATA` | `./data` |
| `CERTBOT_EMAIL` | `info@harunbulbul.com` |
| `CERTBOT_USER_DIR` | `./certs` (proje içi) |
| `APP_TIMEZONE` | `Europe/Istanbul` |
| `SMTP_HOST` | (boş) |
| `SMTP_PORT` | `587` |
| `SMTP_USERNAME` | (boş) |
| `SMTP_PASSWORD` | (boş) |
| `SMTP_USE_TLS` | `true` |
| `SMTP_USE_SSL` | `false` |
| `SMTP_FROM_EMAIL` | `SMTP_USERNAME` |
| `SMTP_TO_EMAILS` | (boş, virgülle çoklu) |
| `SSL_ALERT_THRESHOLD_DAYS` | `2` |
| `SSL_ALERT_CRON_HOUR` | `9` |
| `SSL_ALERT_CRON_MINUTE` | `0` |

Sertifikalar varsayılan olarak `webTracker/certs/live/DOMAIN/` altındadır.

## SMTP cron job (cPanel)

Uygulama her gün `09:00`'da (varsayılan timezone: `Europe/Istanbul`) çalışan bir cron job içerir:

- Önce tüm domainlerin SSL bilgisini yeniler.
- Süresi `2 günden az` kalan (`0 <= gün < 2`) domainleri bulur.
- `SMTP_TO_EMAILS` içindeki adreslere SMTP ile özet e-posta gönderir.

Örnek cPanel SMTP değişkenleri:

```bash
SMTP_HOST=mail.ornekdomain.com
SMTP_PORT=587
SMTP_USERNAME=uyari@ornekdomain.com
SMTP_PASSWORD=super-secret
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SMTP_FROM_EMAIL=uyari@ornekdomain.com
SMTP_TO_EMAILS=admin@ornekdomain.com,devops@ornekdomain.com
```

## Doğrulama dosyası nereye yüklenir?

Domain’in **yayınlandığı sunucuda** (harunbulbul.com’un işaret ettiği sunucu) şu dosyayı oluşturun:

- **Yol:** `.well-known/acme-challenge/DOSYA_ADI` (DOSYA_ADI sayfada yazıyor)
- **İçerik:** Sayfada gösterilen metin (tek satır, aynen kopyalayın)

Örnek: web root’unuz `/var/www/html` ise dosya `/var/www/html/.well-known/acme-challenge/xyz123` olmalı. Nginx/Apache’de `/.well-known/acme-challenge/` path’inin bu dizine yönlendiğinden emin olun. Dosyayı yükledikten sonra “Dosyayı yükledim, sertifika üretimini tamamla” butonuna basın.
