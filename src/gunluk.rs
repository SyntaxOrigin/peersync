//! Durum makinesi günlüğü (`gecmis.jsonl`).
//!
//! Bu modülün sorumluluğu oturumun her durum geçişini zaman damgalı, satır
//! satırlık JSON olarak diske yazmaktır. Bu modülün sorumluluğu *değil*: ne
//! yazılacağına karar vermek; günlük yalnızca kaydeder.
//!
//! # Neden JSON satırı (JSONL)
//!
//! Her satır bağımsız bir JSON nesnesidir. Böylece (a) yazma sırasında satır
//! satır bozulsa bile **önceki satırlar okunabilir** kalır, (b) akış halinde
//! `serde_json` ile ayrıştırılabilir, (c) bir dosyayı iki kez okuyup birleştirmek
//! gerekmez. Bu, "yarım yazılmış günlük yüzünden teşhis kaybı" riskini ortadan
//! kaldırır.
//!
//! # Sır disiplini
//!
//! Günlüğe yazılan metinler **serbest metindir**. `Hata::Display` çıktıları
//! sır içermediği için doğrudan yazılabilir; parola, anahtar veya şifre metni
//! hiçbir yerde görünmez.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::hata::Sonuc;

/// Günlük dosyasının adı.
pub const GUNLUK_DOSYASI: &str = "gecmis.jsonl";

/// Günlüğe yazılabilecek durumlar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "durum")]
pub enum Durum {
    /// Uygulama başladı.
    Basladi,
    /// Yayın keşfi başladı.
    KesifBasladi,
    /// Bir eş ilan edildi.
    EsBulundu,
    /// El sıkışma başladı.
    SikismaBasladi,
    /// El sıkışma başarıyla tamamlandı.
    SikismaTamam,
    /// El sıkışma başarısız oldu.
    SikismaHata,
    /// Oturum kuruldu.
    OturumAcildi,
    /// Dosya listesi alışverişi tamamlandı.
    ManifestAlindi,
    /// Aktarım başladı.
    AktarimBasladi,
    /// Tek bir parça aktarıldı.
    ParcaAktarildi,
    /// Aktarım duraklatıldı.
    Duraklatildi,
    /// Aktarım sürdürüldü.
    DevamEdildi,
    /// Aktarım tamamlandı.
    AktarimBitti,
    /// Çakışma çözüldü.
    CatismaCozuldu,
    /// İşlem hata ile bitti.
    Hata,
}

/// Tek bir günlük satırı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kayit {
    /// Unix milisaniyesi (çıktı içindir; hiçbir karar buraya bakmaz).
    pub zaman_ms: u64,
    /// Oturum içinde artan sıra numarası.
    pub sira: u64,
    /// Durum.
    pub durum: Durum,
    /// Ayrıntı metni (sır içermez).
    pub ayrinti: String,
}

/// Satır satır JSON günlüğü.
#[derive(Debug)]
pub struct Gunluk {
    dosya: Option<File>,
    yol: PathBuf,
    sira: u64,
    yazilan: u64,
}

impl Gunluk {
    /// Verilen yolda günlük açar; dosya yoksa sonuna ekleyerek oluşturur.
    ///
    /// # Hatalar
    ///
    /// Dizin veya dosya açılamazsa [`crate::hata::Hata::Io`] döner.
    pub fn ac(yol: &Path) -> Sonuc<Gunluk> {
        if let Some(ust) = yol.parent() {
            std::fs::create_dir_all(ust)?;
        }
        let dosya = OpenOptions::new().create(true).append(true).open(yol)?;
        Ok(Gunluk {
            dosya: Some(dosya),
            yol: yol.to_path_buf(),
            sira: 0,
            yazilan: 0,
        })
    }

    /// Yazma hedefi olmayan günlük (yalnız sayaç; testler ve `--gunluk yok`).
    pub fn bos() -> Gunluk {
        Gunluk {
            dosya: None,
            yol: PathBuf::new(),
            sira: 0,
            yazilan: 0,
        }
    }

    /// Günlüğün dosya yolu (yoksa boş).
    pub fn yol(&self) -> &Path {
        &self.yol
    }

    /// Yazılan satır sayısı (ölçüm için).
    pub fn yazilan(&self) -> u64 {
        self.yazilan
    }

    /// Durum geçişini yazar.
    ///
    /// Yazma hatası **sessizce yutulmaz**: günlük, teşhis için tek kaynaktır ve
    /// sessizce kaybolan günlük, olmayan günlükten daha kötüdür. Hata
    /// döndürülür; çağıran taraf bunu kullanıcıya bildirir.
    pub fn yaz(&mut self, durum: Durum, ayrinti: impl Into<String>) -> Sonuc<()> {
        self.sira += 1;
        let kayit = Kayit {
            zaman_ms: simdi_ms(),
            sira: self.sira,
            durum,
            ayrinti: ayrinti.into(),
        };
        self.yazilan += 1;
        let Some(dosya) = self.dosya.as_mut() else {
            return Ok(());
        };
        let satir = serde_json::to_string(&kayit)?;
        dosya.write_all(satir.as_bytes())?;
        dosya.write_all(b"\n")?;
        Ok(())
    }

    /// Günlüğü okur.
    ///
    /// **Bozuk satırlar atlanır**, okuma hatası olarak bildirilmez: teşhis
    /// aracının kendisi çökerse teşhis imkânsız hâle gelir. Kaç satırın
    /// atlandığı dönüş değerinde belirtilir.
    pub fn oku(yol: &Path) -> (Vec<Kayit>, usize) {
        let Ok(metin) = std::fs::read_to_string(yol) else {
            return (Vec::new(), 0);
        };
        let mut kayitlar = Vec::new();
        let mut atlanan = 0usize;
        for satir in metin.lines() {
            if satir.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Kayit>(satir) {
                Ok(k) => kayitlar.push(k),
                Err(_) => atlanan += 1,
            }
        }
        (kayitlar, atlanan)
    }
}

/// Unix milisaniyesini döndürür.
///
/// Bu değer yalnızca **çıktı** içindir; hiçbir karar buna bakmaz, bu yüzden
/// testlerin belirlenimliliğini bozmaz.
pub fn simdi_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GeciciDizin {
        yol: PathBuf,
    }

    impl GeciciDizin {
        fn yeni(etiket: &str) -> GeciciDizin {
            let yol = std::env::temp_dir()
                .join(format!("peersync-gunluk-{etiket}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&yol);
            std::fs::create_dir_all(&yol).unwrap();
            GeciciDizin { yol }
        }
    }

    impl Drop for GeciciDizin {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.yol);
        }
    }

    #[test]
    fn bos_gunluk_yazmaz_ama_sayar() {
        let mut gunluk = Gunluk::bos();
        gunluk.yaz(Durum::Basladi, "kayit yok").unwrap();
        assert_eq!(gunluk.yazilan(), 1);
    }

    #[test]
    fn gunluk_satirlari_jsonl_olarak_yazilir() {
        let gecici = GeciciDizin::yeni("yaz");
        let yol = gecici.yol.join(GUNLUK_DOSYASI);
        let mut gunluk = Gunluk::ac(&yol).unwrap();
        gunluk.yaz(Durum::Basladi, "uygulama basladi").unwrap();
        gunluk
            .yaz(Durum::SikismaBasladi, "el sikisma basliyor")
            .unwrap();
        gunluk.yaz(Durum::SikismaTamam, "tamam").unwrap();
        let metin = std::fs::read_to_string(&yol).unwrap();
        assert_eq!(metin.lines().count(), 3);
        assert!(metin.contains("\"durum\":\"Basladi\""));
    }

    #[test]
    fn gunluk_okuma_kayitlari_sira_numarasiyla_dondurur() {
        let gecici = GeciciDizin::yeni("oku");
        let yol = gecici.yol.join(GUNLUK_DOSYASI);
        let mut gunluk = Gunluk::ac(&yol).unwrap();
        gunluk.yaz(Durum::KesifBasladi, "k").unwrap();
        gunluk.yaz(Durum::EsBulundu, "e").unwrap();
        let (kayitlar, atlanan) = Gunluk::oku(&yol);
        assert_eq!(atlanan, 0);
        assert_eq!(kayitlar.len(), 2);
        assert_eq!(kayitlar[0].sira, 1);
        assert_eq!(kayitlar[1].sira, 2);
        assert_eq!(kayitlar[0].durum, Durum::KesifBasladi);
    }

    #[test]
    fn bozuk_satir_atlanir_digerleri_okunur() {
        let gecici = GeciciDizin::yeni("bozuk");
        let yol = gecici.yol.join(GUNLUK_DOSYASI);
        std::fs::write(
            &yol,
            "{\"zaman_ms\":1,\"sira\":1,\"durum\":{\"durum\":\"Basladi\"},\"ayrinti\":\"a\"}\nBOZUK SATIR\n",
        )
        .unwrap();
        let (kayitlar, atlanan) = Gunluk::oku(&yol);
        assert_eq!(kayitlar.len(), 1);
        assert_eq!(atlanan, 1);
    }

    #[test]
    fn var_olmayan_dosya_okundugunda_bos_doner() {
        let gecici = GeciciDizin::yeni("yok");
        let (kayitlar, atlanan) = Gunluk::oku(&gecici.yol.join("olmayan.jsonl"));
        assert!(kayitlar.is_empty());
        assert_eq!(atlanan, 0);
    }

    #[test]
    fn gunluk_ekleme_kipiyle_acilir() {
        let gecici = GeciciDizin::yeni("ekleme");
        let yol = gecici.yol.join(GUNLUK_DOSYASI);
        {
            let mut g = Gunluk::ac(&yol).unwrap();
            g.yaz(Durum::Basladi, "birinci").unwrap();
        }
        {
            let mut g = Gunluk::ac(&yol).unwrap();
            g.yaz(Durum::Hata, "ikinci").unwrap();
        }
        let (kayitlar, _) = Gunluk::oku(&yol);
        assert_eq!(kayitlar.len(), 2);
    }

    #[test]
    fn gecmis_dosyasi_adi_beklendigi_gibi() {
        assert_eq!(GUNLUK_DOSYASI, "gecmis.jsonl");
    }

    #[test]
    fn kayit_json_gidis_donus_yapar() {
        let kayit = Kayit {
            zaman_ms: 123,
            sira: 4,
            durum: Durum::AktarimBitti,
            ayrinti: "5 dosya".to_string(),
        };
        let metin = serde_json::to_string(&kayit).unwrap();
        let cozulen: Kayit = serde_json::from_str(&metin).unwrap();
        assert_eq!(cozulen, kayit);
    }

    #[test]
    fn simulasyon_zamani_uygun_aralikta() {
        // Yalnizca "makul bir deger" kontrolu; kararda kullanilmaz.
        let ms = simdi_ms();
        assert!(
            ms > 1_600_000_000_000,
            "zaman damgasi beklenenden kucuk: {ms}"
        );
    }
}
