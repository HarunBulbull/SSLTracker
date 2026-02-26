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

Sertifikalar varsayılan olarak `webTracker/certs/live/DOMAIN/` altındadır.

## Doğrulama dosyası nereye yüklenir?

Domain’in **yayınlandığı sunucuda** (harunbulbul.com’un işaret ettiği sunucu) şu dosyayı oluşturun:

- **Yol:** `.well-known/acme-challenge/DOSYA_ADI` (DOSYA_ADI sayfada yazıyor)
- **İçerik:** Sayfada gösterilen metin (tek satır, aynen kopyalayın)

Örnek: web root’unuz `/var/www/html` ise dosya `/var/www/html/.well-known/acme-challenge/xyz123` olmalı. Nginx/Apache’de `/.well-known/acme-challenge/` path’inin bu dizine yönlendiğinden emin olun. Dosyayı yükledikten sonra “Dosyayı yükledim, sertifika üretimini tamamla” butonuna basın.
