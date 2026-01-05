# Email Analyzer

`.eml` formatındaki şüpheli e-postaları analiz eden ve analistler için kullanışlı **HTML raporları** üreten bir Python aracıdır.

<img src="https://raw.githubusercontent.com/wolkansec/email-analyzer/refs/heads/main/1.PNG" widh="800" height="200">
<img src="https://raw.githubusercontent.com/wolkansec/email-analyzer/refs/heads/main/2.PNG">
<img src="https://raw.githubusercontent.com/wolkansec/email-analyzer/refs/heads/main/3.PNG">


## Özellikler

* **Header Analizi:** SPF, DKIM, DMARC kontrolleri ve e-postanın izlediği yolu (Hop Analysis) gösteren `Received` satırı incelemesi.
* **Akıllı Skorlama Sistemi:** Gönderen tutarsızlıkları, kimlik doğrulama hataları ve şüpheli içeriklere göre otomatik risk puanlaması.
* **Hızlı Kontroller:** IP, Domain ve Dosya Hash değerleri için **VirusTotal**, **AbuseIPDB** ve **URLScan.io** üzerinden hızlı sorgulama imkanı.
* **Otomatik IoC Çıkarımı:** E-posta içindeki tüm IP adreslerini, URL'leri ve ek dosya hashlerini otomatik olarak toplar ve "defang" uygular.
* **Modern HTML Raporu:** Analistler için aksiyon alınabilir butonlar (VT, Whois, AbuseIPDB linkleri) içeren rapor çıktısı.

## Kurulum

1.  **Depoyu Klonlayın:**
    ```bash
    git clone https://github.com/wolkansec/email-analyzer.git
    cd email-analyzer
    ```

## Kullanım

Analizi başlatmak için terminal üzerinden şüpheli `.eml` dosyasını parametre olarak vermeniz yeterlidir:

```bash
python analyzer.py -f suspicious_email.eml
