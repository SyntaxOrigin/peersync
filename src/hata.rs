//! Hata tipi ve sonuç takma adı.
//!
//! Bu modülün sorumluluğu tüm katmanlardan dönen hataları **tek** bir tipe
//! indirgemektir. Bu modülün sorumluluğu *değil*: hataları sınıflandırmak yerine
//! ortak bir `Display`/`Error` yüzeyi sağlamak ve sır taşıyan ayrıntıları eler.
//!
//! Güvenlik notu: hiçbir `Hata` türü parolayı, türetilmiş anahtarı veya şifre
//! metnini taşımaz. Kripto hataları yalnızca "beklenen koşul sağlanmadı" bilgisini
//! verir; bu, günlük çıktısının sır sızdırmamasını garanti eder.

use std::fmt;

/// Projenin tamamında kullanılan sonuç takma adı.
pub type Sonuc<T> = Result<T, Hata>;

/// PeerSync'in tüm katmanlarının ortak hata tipi.
///
/// Kapsam genişletilebilir olduğu için `#[non_exhaustive]` işaretlidir; eşleme
/// (`match`) yapan çağıranlar yeni türler için el vermek zorunda kalmaz.
#[derive(Debug)]
#[non_exhaustive]
pub enum Hata {
    /// Dosya sistemi veya soket hatası.
    Io(std::io::Error),
    /// JSON çözümleme veya üretme hatası.
    Json(String),
    /// Yayın paketi veya el sıkışma açılış paketi çözülemedi.
    BozukPaket(String),
    /// Gelen mesaj izin verilen üst sınırdan büyük.
    MesajCokBuyuk {
        /// Alınan bayt sayısı.
        alinan: usize,
        /// İzin verilen azami bayt sayısı.
        azami: usize,
    },
    /// Gelen veri işlenirken bir tampon sınırı aşıldı.
    TamponSinir {
        /// Aşılan sınırın adı.
        sinir: &'static str,
        /// İzin verilen değer.
        azami: usize,
    },
    /// Parça boyutu izin verilen üst sınırdan büyük.
    ParcaBoyutuGecersiz {
        /// Bildirilen parça boyutu.
        bildirilen: u32,
        /// İzin verilen azami parça boyutu.
        azami: u32,
    },
    /// Keşifte bilinen eş sayısı sınırı aşıldı.
    EsSiniriAsildi {
        /// Üretilen eş sayısı.
        alinan: usize,
        /// İzin verilen azami eş sayısı.
        azami: usize,
    },
    /// Yayın paketinde veya el sıkışmada sürüm uyuşmazlığı.
    SurumUyusmadi {
        /// Bu yapının anladığı protokol sürümü.
        beklenen: u16,
        /// Karşı tarafın bildirdiği sürüm.
        alinan: u16,
    },
    /// Kimlik doğrulama başarısız; oturum **derhal** kapatılır.
    KimlikDogrulanmadi {
        /// Güvenli, sır içermeyen açıklama.
        gerekce: &'static str,
    },
    /// Oturum anahtarı üretilmemiş veya oturum henüz kurulmamış.
    OturumAnahtariYok,
    /// AEAD şifreleme/çözme başarısız (Poly1305 etiketi tutmadı ya da biçim bozuk).
    SifrelemeHatasi,
    /// Nonce kaynağı tükendi veya daha önce kullanılmış bir nonce istendi.
    NonceTekrari,
    /// Parola modunda şifrelenmemiş aktarım yapılamaz.
    SifrelemeZorunlu,
    /// Oturum açmak için grup parolası zorunludur.
    ParolaZorunlu,
    /// Belirtilen sürede veri gelmedi.
    ZamanAsimi {
        /// Hangi aşamanın beklediği.
        beklenti: &'static str,
    },
    /// Karşı taraf bağlantıyı kapattı ya da paket akışı bozuldu.
    BaglantiKapandi {
        /// Bağlantının kesilme nedeni (sır içermez).
        gerekce: &'static str,
    },
    /// Kuyruk kapasitesi dolu.
    KuyrukDolu {
        /// Kuyruğun azami uzunluğu.
        kapasite: usize,
    },
    /// Kalıcı depo (`indeks.json`) okunamadı veya bozuk.
    DepoBozuk(String),
    /// Diskte yeterli yer yok ya da yazma başarısız.
    DepoYazmaHatasi(String),
    /// Çakışma çözüldü; hiçbir tarafın verisi kaybolmadı.
    CatismaCozuldu {
        /// Çakışan dosyanın göreli yolu.
        yol: String,
        /// Korunan eski sürümün dosya adı.
        yedek: String,
    },
    /// Argüman veya ayar geçersiz.
    GecersizArguman(String),
    /// Yapılandırma değeri aralık dışında.
    AyarGecersiz {
        /// Ayarın adı.
        ad: &'static str,
        /// Geçersiz değerin metinsel hâli.
        deger: String,
    },
    /// Aktarım, duraklatma isteğiyle yarıda kesildi.
    Duraklatildi,
}

impl fmt::Display for Hata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hata::Io(kaynak) => write!(f, "girdi/çıktı hatası: {kaynak}"),
            Hata::Json(ayrinti) => write!(f, "JSON hatası: {ayrinti}"),
            Hata::BozukPaket(ayrinti) => write!(f, "bozuk paket: {ayrinti}"),
            Hata::MesajCokBuyuk { alinan, azami } => {
                write!(f, "mesaj çok büyük: {alinan} bayt, sınır {azami} bayt")
            }
            Hata::TamponSinir { sinir, azami } => {
                write!(f, "tampon sınırı aşıldı ({sinir}): sınır {azami}")
            }
            Hata::ParcaBoyutuGecersiz { bildirilen, azami } => {
                write!(f, "geçersiz parça boyutu {bildirilen}, azami {azami}")
            }
            Hata::EsSiniriAsildi { alinan, azami } => {
                write!(f, "eş sayısı sınırı aşıldı: {alinan} > {azami}")
            }
            Hata::SurumUyusmadi { beklenen, alinan } => {
                write!(f, "sürüm uyuşmazlığı: beklenen {beklenen}, alınan {alinan}")
            }
            Hata::KimlikDogrulanmadi { gerekce } => {
                write!(f, "kimlik doğrulama başarısız: {gerekce}")
            }
            Hata::OturumAnahtariYok => write!(f, "oturum anahtarı yok"),
            Hata::SifrelemeHatasi => write!(f, "şifreleme/çözme doğrulaması başarısız"),
            Hata::NonceTekrari => write!(f, "nonce tekrarı veya nonce kaynağı tükendi"),
            Hata::SifrelemeZorunlu => write!(
                f,
                "parola modunda şifrelenmemiş aktarım yapılamaz: taşıma şifrelemesi zorunludur"
            ),
            Hata::ParolaZorunlu => write!(f, "grup parolası zorunludur"),
            Hata::ZamanAsimi { beklenti } => write!(f, "zaman aşımı: {beklenti}"),
            Hata::BaglantiKapandi { gerekce } => write!(f, "bağlantı kesildi: {gerekce}"),
            Hata::KuyrukDolu { kapasite } => write!(f, "kuyruk dolu (kapasite {kapasite})"),
            Hata::DepoBozuk(ayrinti) => write!(f, "depo bozuk: {ayrinti}"),
            Hata::DepoYazmaHatasi(ayrinti) => write!(f, "depo yazma hatası: {ayrinti}"),
            Hata::CatismaCozuldu { yol, yedek } => {
                write!(
                    f,
                    "çakışma çözüldü: {yol} -> eski sürüm {yedek} olarak korundu"
                )
            }
            Hata::GecersizArguman(ayrinti) => write!(f, "geçersiz argüman: {ayrinti}"),
            Hata::AyarGecersiz { ad, deger } => write!(f, "ayar geçersiz: {ad} = {deger}"),
            Hata::Duraklatildi => write!(f, "işlem duraklatma isteğiyle yarıda kesildi"),
        }
    }
}

impl std::error::Error for Hata {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Hata::Io(kaynak) => Some(kaynak),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Hata {
    fn from(deger: std::io::Error) -> Self {
        Hata::Io(deger)
    }
}

impl From<serde_json::Error> for Hata {
    fn from(deger: serde_json::Error) -> Self {
        Hata::Json(deger.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_hatasi_kaynak_zinciri_baglidir() {
        let hata = Hata::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "dosya yok",
        ));
        assert!(std::error::Error::source(&hata).is_some());
        assert!(hata.to_string().contains("dosya yok"));
    }

    #[test]
    fn json_hatasi_display_metni_hata_tasiyor() {
        let hata: Hata = "bozuk".parse::<serde_json::Value>().unwrap_err().into();
        assert!(matches!(hata, Hata::Json(_)));
        assert!(hata.to_string().starts_with("JSON hatası:"));
    }

    #[test]
    fn sinir_hatalari_sayi_degerlerini_gosterir() {
        let hata = Hata::MesajCokBuyuk {
            alinan: 10,
            azami: 4,
        };
        assert_eq!(hata.to_string(), "mesaj çok büyük: 10 bayt, sınır 4 bayt");
        let hata = Hata::EsSiniriAsildi {
            alinan: 5,
            azami: 4,
        };
        assert_eq!(hata.to_string(), "eş sayısı sınırı aşıldı: 5 > 4");
    }

    #[test]
    fn sifreleme_zorunlu_hatasi_acik_mesaj_verir() {
        let metin = Hata::SifrelemeZorunlu.to_string();
        assert!(metin.contains("zorunludur"));
    }

    #[test]
    fn kimlik_dogrulanmadi_hatasi_sir_sızdirmaz() {
        let hata = Hata::KimlikDogrulanmadi {
            gerekce: "karsi taraf dogrulama bayisi uretemedi",
        };
        let metin = hata.to_string();
        assert!(metin.contains("kimlik doğrulama başarısız"));
        assert!(!metin.to_lowercase().contains("parola"));
    }

    #[test]
    fn catisma_hatasi_her_iki_yolu_da_gosterir() {
        let hata = Hata::CatismaCozuldu {
            yol: "a/b.txt".to_string(),
            yedek: "b.txt.conflict-aa-1.conflict".to_string(),
        };
        assert!(hata.to_string().contains("a/b.txt"));
        assert!(hata.to_string().contains("b.txt.conflict-aa-1.conflict"));
    }

    #[test]
    fn ayar_hatasi_ayar_adi_ve_degeri_yazar() {
        let hata = Hata::AyarGecersiz {
            ad: "sn",
            deger: "0".to_string(),
        };
        assert_eq!(hata.to_string(), "ayar geçersiz: sn = 0");
    }
}
