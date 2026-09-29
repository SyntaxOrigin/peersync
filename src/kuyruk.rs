//! Aktarım kuyruğu, bant genişliği sınırı ve duraklat/devam denetimi.
//!
//! Bu modülün sorumluluğu aktarımın **hızını ve sırasını** denetlemektir.
//! Bu modülün sorumluluğu *değil*: neyin aktarılacağına karar vermek (bkz.
//! `crate::senkron`) ve baytların taşınması (bkz. `crate::tasma`).
//!
//! # Hız sınırı
//!
//! Kova (token bucket) tabanlıdır: kova `kapasite` bayta kadar dolar, saniyede
//! `hiz` bayt yenilenir. Bu, kısa bir tepeyi (ör. küçük bir dosyanın tamamı) izin
//! verilen sınırın çok üstüne çıkarmadan geçirir; sabit bir `sleep` yerine kova
//! kullanılmasının nedeni budur.
//!
//! `HizSinirlayici::doldur` yalnızca testlerde çağrılır: gerçek bir `sleep`
//! yapmadan kova zamanını ileri alır, böylece testler saniyeler sürmez ve
//! yine de ölçülebilir sonuç verir.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::hata::{Hata, Sonuc};

/// Aktarım önceliği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Oncelik {
    /// Kullanıcı beklemesin: en yüksek öncelik (0).
    Yuksek,
    /// Varsayılan öncelik.
    Normal,
    /// Arka plan bakımı.
    Dusuk,
}

impl Oncelik {
    /// Tamsayı sıralama anahtarı (küçükten büyüğe öncelik).
    pub fn sira(&self) -> u8 {
        match self {
            Oncelik::Yuksek => 0,
            Oncelik::Normal => 1,
            Oncelik::Dusuk => 2,
        }
    }
}

/// Kuyruğa eklenmiş tek bir aktarım görevi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gorev {
    /// Görevin kimliği (dosya yolu veya parça karmasının metni).
    pub kimlik: String,
    /// Öncelik.
    pub oncelik: Oncelik,
    /// Kaç kez yeniden denendi.
    pub deneme: u32,
    /// Kuyruğa giriş zamanı (sıralama ve geri çekilme hesabı için).
    pub giris: Instant,
}

/// Öncelik sıralı, kapasiteli aktarım kuyruğu.
#[derive(Debug)]
pub struct Kuyruk {
    ogeler: VecDeque<Gorev>,
    kapasite: usize,
    toplam_giris: u64,
}

impl Kuyruk {
    /// Verilen kapasiteyle boş kuyruk oluşturur.
    ///
    /// # Hatalar
    ///
    /// Kapasite sıfırsa [`Hata::AyarGecersiz`] döner: sıfır kapasiteli kuyruk
    /// hiçbir işi kabul edemez ve bu bir yapılandırma hatasıdır.
    pub fn yeni(kapasite: usize) -> Sonuc<Kuyruk> {
        if kapasite == 0 {
            return Err(Hata::AyarGecersiz {
                ad: "kuyruk.kapasite",
                deger: "0".to_string(),
            });
        }
        Ok(Kuyruk {
            ogeler: VecDeque::new(),
            kapasite,
            toplam_giris: 0,
        })
    }

    /// Kuyruğa görev ekler.
    ///
    /// Aynı kimlik iki kez eklenirse yalnızca bir kez sayılır: yinelenen bir
    /// senkron turu aynı dosyayı iki kez indirtmemelidir.
    ///
    /// # Hatalar
    ///
    /// Kuyruk doluysa [`Hata::KuyrukDolu`] döner.
    pub fn ekle(&mut self, kimlik: &str, oncelik: Oncelik, simdi: Instant) -> Sonuc<Gorev> {
        if self.ogeler.iter().any(|g| g.kimlik == kimlik) {
            return Err(Hata::GecersizArguman(format!(
                "görev zaten kuyrukta: {kimlik}"
            )));
        }
        if self.ogeler.len() >= self.kapasite {
            return Err(Hata::KuyrukDolu {
                kapasite: self.kapasite,
            });
        }
        let gorev = Gorev {
            kimlik: kimlik.to_string(),
            oncelik,
            deneme: 0,
            giris: simdi,
        };
        self.ogeler.push_back(gorev.clone());
        self.toplam_giris += 1;
        Ok(gorev)
    }

    /// Önceliği en yüksek, aynı öncelikte en eski görevi çıkarır.
    pub fn sonraki(&mut self) -> Option<Gorev> {
        if self.ogeler.is_empty() {
            return None;
        }
        let en_iyi = self
            .ogeler
            .iter()
            .enumerate()
            .min_by_key(|(i, g)| (g.oncelik.sira(), *i))
            .map(|(i, _)| i)?;
        self.ogeler.remove(en_iyi)
    }

    /// Yeniden denenecek görevi kuyruğun sonuna ekler ve deneme sayısını artırır.
    ///
    /// Geri çekilme süresi çağıran tarafın sorumluluğundadır; kuyruk yalnızca
    /// sırayı korur.
    pub fn yeniden_zamanla(&mut self, gorev: &mut Gorev) -> Sonuc<()> {
        if self.ogeler.len() >= self.kapasite {
            return Err(Hata::KuyrukDolu {
                kapasite: self.kapasite,
            });
        }
        gorev.deneme += 1;
        self.ogeler.push_back(gorev.clone());
        Ok(())
    }

    /// Kuyrukta bekleyen görev sayısı.
    pub fn uzunluk(&self) -> usize {
        self.ogeler.len()
    }

    /// Kuyruk boş mu?
    pub fn bos(&self) -> bool {
        self.ogeler.is_empty()
    }

    /// Kuyruğun azami uzunluğu.
    pub fn kapasite(&self) -> usize {
        self.kapasite
    }

    /// Sıradaki görevleri (öncelik sırasıyla) listeler; kuyruğu boşaltmaz.
    pub fn onizleme(&self) -> Vec<&Gorev> {
        let mut sirali: Vec<(usize, &Gorev)> = self.ogeler.iter().enumerate().collect();
        sirali.sort_by_key(|(i, g)| (g.oncelik.sira(), *i));
        sirali.into_iter().map(|(_, g)| g).collect()
    }

    /// Kuyruğa bugün giren toplam görev sayısı (ölçüm için).
    pub fn toplam_giris(&self) -> u64 {
        self.toplam_giris
    }
}

/// Kova tabanlı bant genişliği sınırı.
#[derive(Debug)]
pub struct HizSinirlayici {
    kova: f64,
    kapasite: f64,
    hiz: f64,
    son: Instant,
    gecmis_harcanan: u64,
}

impl HizSinirlayici {
    /// Saniyede `hiz` bayta sınırlar.
    ///
    /// `hiz` sıfırsa sınır yoktur (`HizSinirlayici::sinirsiz`).
    pub fn yeni(hiz: u64) -> HizSinirlayici {
        if hiz == 0 {
            return HizSinirlayici::sinirsiz();
        }
        let kapasite = hiz as f64;
        HizSinirlayici {
            kova: kapasite,
            kapasite,
            hiz: hiz as f64,
            son: Instant::now(),
            gecmis_harcanan: 0,
        }
    }

    /// Sınırsız (hız kısıtı olmayan) sınır.
    pub fn sinirsiz() -> HizSinirlayici {
        HizSinirlayici {
            kova: f64::INFINITY,
            kapasite: f64::INFINITY,
            hiz: f64::INFINITY,
            son: Instant::now(),
            gecmis_harcanan: 0,
        }
    }

    /// Kova yetmiyorsa gereken bekleme süresini hesaplar (bloklamadan).
    pub fn beklenen_bekleme(&mut self, bayt: u64) -> Duration {
        self.yenile();
        if !self.hiz.is_finite() {
            return Duration::ZERO;
        }
        let istenen = bayt as f64;
        if self.kova >= istenen {
            return Duration::ZERO;
        }
        let eksik = istenen - self.kova;
        Duration::from_secs_f64((eksik / self.hiz).max(0.0))
    }

    /// Bayt harcar; kova yetmiyorsa gereken süre boyunca **bloklar**.
    pub fn harca(&mut self, bayt: u64) -> Duration {
        let bekle = self.beklenen_bekleme(bayt);
        if !bekle.is_zero() {
            std::thread::sleep(bekle);
            self.yenile();
        }
        self.kova -= (bayt as f64).min(self.kova.max(0.0));
        self.gecmis_harcanan += bayt;
        bekle
    }

    /// Verilen süre kadar kovayı doldurur. **Yalnızca testlerde** çağrılır.
    pub fn doldur(&mut self, gecen: Duration) {
        if !self.hiz.is_finite() {
            return;
        }
        self.kova = (self.kova + gecen.as_secs_f64() * self.hiz).min(self.kapasite);
    }

    /// Kova miktarını bayt olarak bildirir.
    pub fn kova_bayt(&self) -> u64 {
        if !self.kova.is_finite() {
            return u64::MAX;
        }
        self.kova.max(0.0) as u64
    }

    /// Sınırlanan hız (bayt/saniye); sınırsızsa sıfır.
    pub fn hiz(&self) -> u64 {
        if self.hiz.is_finite() {
            self.hiz as u64
        } else {
            0
        }
    }

    /// Sınırdan geçen toplam bayt (ölçüm için).
    pub fn harcanan(&self) -> u64 {
        self.gecmis_harcanan
    }

    fn yenile(&mut self) {
        let simdi = Instant::now();
        if simdi > self.son {
            let gecen = simdi.duration_since(self.son);
            if self.hiz.is_finite() {
                self.kova = (self.kova + gecen.as_secs_f64() * self.hiz).min(self.kapasite);
            }
            self.son = simdi;
        }
    }
}

/// İş parçacıkları arasında paylaşılabilen duraklat/devam anahtarı.
///
/// Anahtar `Arc<AtomicBool>` ile paylaşılır: taşıma iş parçacığı her segmentten
/// önce `duraklatildi_mi` değerine bakar, arayüz ise `duraklat`/`devam_et` ile
/// durumu değiştirir. Kilit yoktur, bekleme süresi hesaplanır.
#[derive(Debug, Clone)]
pub struct Duraklatma {
    bayrak: Arc<AtomicBool>,
}

impl Default for Duraklatma {
    fn default() -> Self {
        Duraklatma::yeni()
    }
}

impl Duraklatma {
    /// Devam durumunda yeni anahtar oluşturur.
    pub fn yeni() -> Duraklatma {
        Duraklatma {
            bayrak: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Aktarımı duraklatır.
    pub fn duraklat(&self) {
        self.bayrak.store(true, Ordering::SeqCst);
    }

    /// Aktarımı sürdürür.
    pub fn devam_et(&self) {
        self.bayrak.store(false, Ordering::SeqCst);
    }

    /// Duraklatılmış mı?
    pub fn duraklatildi_mi(&self) -> bool {
        self.bayrak.load(Ordering::SeqCst)
    }

    /// Durum değiştiyse `true` döndürür (arayüzün "duraklatildi/devam ediyor"
    /// satırını yalnızca gerçekten değiştiğinde yazması için).
    pub fn degisti_mi(&self) -> bool {
        let yeni = !self.duraklatildi_mi();
        self.bayrak.store(yeni, Ordering::SeqCst);
        true
    }
}

/// Yeniden deneme için üstel geri çekilme (üst sınırlı).
///
/// `deneme` 0 iken `temel`, her adımda iki katı, en fazla `azami` süredir.
/// Sınırsız büyüme engellenir: sınırsız geri çekilme, kalıcı bir hatada sonsuza
/// kadar beklemek demektir.
pub fn geri_cekilme(deneme: u32, temel: Duration, azami: Duration) -> Duration {
    let carpan = 1u64.checked_shl(deneme.min(16)).unwrap_or(u64::MAX);
    let nanos = temel
        .as_nanos()
        .saturating_mul(u128::from(carpan))
        .min(azami.as_nanos());
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oncelik_sirasi_kucukten_buyuge() {
        assert!(Oncelik::Yuksek < Oncelik::Normal);
        assert!(Oncelik::Normal < Oncelik::Dusuk);
        assert_eq!(Oncelik::Yuksek.sira(), 0);
        assert_eq!(Oncelik::Dusuk.sira(), 2);
    }

    #[test]
    fn sifir_kapasiteli_kuyruk_hata_dondurur() {
        let hata = Kuyruk::yeni(0).unwrap_err();
        assert!(matches!(hata, Hata::AyarGecersiz { .. }));
    }

    #[test]
    fn kuyruk_ekle_ve_çikar_dis_durumu_guncellenir() {
        let mut kuyruk = Kuyruk::yeni(4).unwrap();
        let simdi = Instant::now();
        assert!(kuyruk.bos());
        kuyruk.ekle("a", Oncelik::Normal, simdi).unwrap();
        kuyruk.ekle("b", Oncelik::Normal, simdi).unwrap();
        assert_eq!(kuyruk.uzunluk(), 2);
        assert!(!kuyruk.bos());
        assert_eq!(kuyruk.toplam_giris(), 2);
    }

    #[test]
    fn kuyruk_ayni_gorevi_iki_kez_almaz() {
        let mut kuyruk = Kuyruk::yeni(4).unwrap();
        let simdi = Instant::now();
        kuyruk.ekle("a", Oncelik::Normal, simdi).unwrap();
        let hata = kuyruk.ekle("a", Oncelik::Normal, simdi).unwrap_err();
        assert!(matches!(hata, Hata::GecersizArguman(_)));
        assert_eq!(kuyruk.uzunluk(), 1);
    }

    #[test]
    fn kuyruk_dolu_hata_dondurur() {
        let mut kuyruk = Kuyruk::yeni(2).unwrap();
        let simdi = Instant::now();
        kuyruk.ekle("a", Oncelik::Normal, simdi).unwrap();
        kuyruk.ekle("b", Oncelik::Normal, simdi).unwrap();
        let hata = kuyruk.ekle("c", Oncelik::Normal, simdi).unwrap_err();
        assert!(matches!(hata, Hata::KuyrukDolu { kapasite: 2 }));
    }

    #[test]
    fn kuyruk_once_yuksek_onceligi_seker() {
        let mut kuyruk = Kuyruk::yeni(8).unwrap();
        let simdi = Instant::now();
        kuyruk.ekle("normal-1", Oncelik::Normal, simdi).unwrap();
        kuyruk.ekle("dusuk", Oncelik::Dusuk, simdi).unwrap();
        kuyruk.ekle("yuksek", Oncelik::Yuksek, simdi).unwrap();
        kuyruk.ekle("normal-2", Oncelik::Normal, simdi).unwrap();
        assert_eq!(kuyruk.sonraki().unwrap().kimlik, "yuksek");
        assert_eq!(kuyruk.sonraki().unwrap().kimlik, "normal-1");
        assert_eq!(kuyruk.sonraki().unwrap().kimlik, "normal-2");
        assert_eq!(kuyruk.sonraki().unwrap().kimlik, "dusuk");
        assert!(kuyruk.sonraki().is_none());
    }

    #[test]
    fn kuyruk_geri_zamanlama_denemeyi_artirir() {
        let mut kuyruk = Kuyruk::yeni(4).unwrap();
        let simdi = Instant::now();
        let mut gorev = kuyruk.ekle("a", Oncelik::Normal, simdi).unwrap();
        kuyruk.sonraki().unwrap();
        assert_eq!(gorev.deneme, 0);
        kuyruk.yeniden_zamanla(&mut gorev).unwrap();
        assert_eq!(gorev.deneme, 1);
        assert_eq!(kuyruk.uzunluk(), 1);
    }

    #[test]
    fn kuyruk_onizleme_siralamayi_gosterir() {
        let mut kuyruk = Kuyruk::yeni(8).unwrap();
        let simdi = Instant::now();
        kuyruk.ekle("n1", Oncelik::Normal, simdi).unwrap();
        kuyruk.ekle("d1", Oncelik::Dusuk, simdi).unwrap();
        kuyruk.ekle("y1", Oncelik::Yuksek, simdi).unwrap();
        let sirali: Vec<&str> = kuyruk
            .onizleme()
            .iter()
            .map(|g| g.kimlik.as_str())
            .collect();
        assert_eq!(sirali, vec!["y1", "n1", "d1"]);
        assert_eq!(kuyruk.uzunluk(), 3, "onizleme kuyrugu bosaltmamali");
    }

    #[test]
    fn hiz_sinirlayici_sinirsiz_oldugunda_beklemez() {
        let mut s = HizSinirlayici::sinirsiz();
        assert!(s.beklenen_bekleme(1_000_000).is_zero());
        assert_eq!(s.hiz(), 0);
        assert!(s.kova_bayt() == u64::MAX);
    }

    #[test]
    fn hiz_sinirlayici_kova_bosalınca_bekleme_uretir() {
        let mut s = HizSinirlayici::yeni(1000);
        s.harca(1000);
        assert_eq!(s.kova_bayt(), 0);
        let bekle = s.beklenen_bekleme(500);
        // Kova arasi gecen gercek zaman nedeniyle deger tam 500 ms olmaz;
        // yalnizca "yaklasik yarim saniye" mertebesi dogrulanir.
        assert!(
            bekle >= Duration::from_millis(450) && bekle <= Duration::from_millis(550),
            "bekleme suresi beklenenden farkli: {bekle:?}"
        );
    }

    #[test]
    fn hiz_sinirlayici_zaman_gectikce_kovayi_doldurur() {
        let mut s = HizSinirlayici::yeni(1000);
        s.harca(1000);
        assert_eq!(s.kova_bayt(), 0);
        s.doldur(Duration::from_millis(200));
        assert_eq!(s.kova_bayt(), 200);
        assert!(s.beklenen_bekleme(100).is_zero());
    }

    #[test]
    fn hiz_sinirlayici_kova_kapasiteyi_asmaz() {
        let mut s = HizSinirlayici::yeni(1000);
        s.doldur(Duration::from_secs(10));
        assert_eq!(s.kova_bayt(), 1000);
    }

    #[test]
    fn hiz_sinirlayici_kova_icinde_beklemez() {
        let mut s = HizSinirlayici::yeni(1000);
        assert!(s.beklenen_bekleme(500).is_zero());
        let bekle = s.harca(500);
        assert!(bekle.is_zero());
        assert!(s.harcanan() >= 500);
    }

    #[test]
    fn hiz_sinirlayici_kucuk_paketler_tek_seferde_gecer() {
        // 10 MB/s sinirinda 64 KiB paketler yaklaşık 6.5 ms aralikla gecmeli.
        let mut s = HizSinirlayici::yeni(10_000_000);
        let baslangic = Instant::now();
        for _ in 0..100 {
            s.harca(64 * 1024);
        }
        let gecen = baslangic.elapsed();
        // 100 * 64 KiB = 6.4 MiB; kova 10 MiB oldugu icin bekleme olmamali.
        assert!(
            gecen < Duration::from_millis(200),
            "beklenmedik yavaşlık: {gecen:?}"
        );
    }

    #[test]
    fn duraklama_durum_degistirir_ve_okunur() {
        let d = Duraklatma::yeni();
        assert!(!d.duraklatildi_mi());
        d.duraklat();
        assert!(d.duraklatildi_mi());
        d.devam_et();
        assert!(!d.duraklatildi_mi());
    }

    #[test]
    fn duraklama_kopyasi_ayni_durumu_paylasir() {
        let d = Duraklatma::yeni();
        let kopya = d.clone();
        d.duraklat();
        assert!(kopya.duraklatildi_mi());
    }

    #[test]
    fn geri_cekilme_ustel_ve_sinirli() {
        let temel = Duration::from_millis(100);
        let azami = Duration::from_secs(2);
        assert_eq!(geri_cekilme(0, temel, azami), temel);
        assert_eq!(geri_cekilme(1, temel, azami), Duration::from_millis(200));
        assert_eq!(geri_cekilme(2, temel, azami), Duration::from_millis(400));
        assert_eq!(geri_cekilme(5, temel, azami), azami);
        assert_eq!(geri_cekilme(64, temel, azami), azami);
    }
}
