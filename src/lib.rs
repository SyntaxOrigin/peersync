//! EşDosya (PeerSync) — sunucusuz P2P dosya senkronizasyonu.
//!
//! # Katmanlar
//!
//! | Modül | Sorumluluk |
//! |---|---|
//! | [`karma`] | SHA-256 içerik tanımlayıcısı, karma kümeleri |
//! | [`parca`] | İçerik tanımlayıcılı parçalama (kayan pencere + 13 bit geçiş) |
//! | [`kimlik`] | Cihaz kimliği, Argon2id parola türetme, HKDF |
//! | [`sifre`] | Oturum anahtarları, nonce disiplini, ChaCha20-Poly1305 |
//! | [`protok`] | İkili çerçeve biçimi, segmentasyon, yeniden birleştirme |
//! | [`kesif`] | UDP yayın eş keşfi |
//! | [`el_sikisma`] | Karşılıklı kimlik doğrulama ve oturum kurulumu |
//! | [`tasma`] | UDP taşıma, şifreli gönderim/alım, zaman aşımı |
//! | [`depo`] | Klasör tarama, parça deposu, atomik kurulum, çakışma yedeği |
//! | [`kuyruk`] | Aktarım kuyruğu, bant genişliği sınırı, duraklat/devam |
//! | [`senkron`] | Delta kararı, çekme/gönderme, çakışma çözümü |
//! | [`gunluk`] | Durum makinesi günlüğü (`gecmis.jsonl`) |
//! | [`hata`] | Ortak hata tipi |
//!
//! # Güvenlik ilkeleri
//!
//! - Grup parolası **hiçbir zaman** ağa taşınmaz; iki taraf da Argon2id
//!   özütünden türetilen anahtarla mühürlenmiş bir kanıt değişir
//!   (bkz. [`sifre::KanitMuhrü`]).
//! - El sıkışma sonrası **her** bayt ChaCha20-Poly1305 ile korunur. Parola modunda
//!   şifrelenmemiş aktarım yapılamaz; bu talep [`sifre::GuvenlikModu::sifresiz_istiyor`]
//!   tarafından açık bir hatayla reddedilir.
//! - Kimlik doğrulama başarısızsa oturum **derhal** kurulmaz.
//! - Nonce asla tekrarlanmaz: yön etiketi + artan sayaç (bkz. [`sifre::NonceSayaci`]).
//! - Kimlikler ve anahtarlar log'a yazılmaz; hata mesajları sır içermez.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod depo;
pub mod el_sikisma;
pub mod gunluk;
pub mod hata;
pub mod karma;
pub mod kesif;
pub mod kimlik;
pub mod kuyruk;
pub mod parca;
pub mod protok;
pub mod senkron;
pub mod sifre;
pub mod tasma;

pub use hata::{Hata, Sonuc};

use std::path::Path;

use crate::kimlik::Kimlik;
use crate::parca::ParcaAyari;

/// Kimlik dosyasının adı (paylaşılan klasörün `.peersync` dizini içinde).
pub const KIMLIK_DOSYASI: &str = "kimlik.json";

/// Günlük dosyasının adı.
pub const GUNLUK_DOSYASI: &str = "gecmis.jsonl";

/// Depo alt dizininin adı.
pub const DEPO_DIZINI: &str = ".peersync";

/// Cihaz kimliğini okur; yoksa üretip diske yazar.
///
/// Kimlik **gizli değildir** ama kimlik doğrulama için kullanılmaz; yalnız
/// çakışmada belirsizliği kırmak ve günlükte okunabilir etiketler üretmek içindir.
/// Kimlik dosyası bozuksa hata verilmez, yeni kimlik üretilir: kimlik kaybı
/// yalnızca çakışma çözümündeki belirsizliği artırır, veri bütünlüğünü etkilemez.
pub fn kimlik_yukle_veya_uret(kok: &Path) -> Sonuc<Kimlik> {
    let dizin = kok.join(DEPO_DIZINI);
    std::fs::create_dir_all(&dizin)?;
    let yol = dizin.join(KIMLIK_DOSYASI);
    if yol.exists() {
        if let Ok(metin) = std::fs::read_to_string(&yol) {
            if let Ok(kimlik) = Kimlik::onaltilikten(metin.trim()) {
                return Ok(kimlik);
            }
        }
    }
    let kimlik = Kimlik::uret()?;
    std::fs::write(&yol, kimlik.onaltilik())?;
    Ok(kimlik)
}

/// Varsayılan parçalama ayarı.
pub fn varsayilan_parca_ayari() -> ParcaAyari {
    ParcaAyari::varsayilan()
}

/// Uygulama sürümü (`Cargo.toml`'daki `version` ile aynı tutulur).
pub const SURUM: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct GeciciDizin {
        yol: PathBuf,
    }

    impl GeciciDizin {
        fn yol(&self) -> &std::path::Path {
            &self.yol
        }

        fn yeni(etiket: &str) -> GeciciDizin {
            let yol =
                std::env::temp_dir().join(format!("peersync-lib-{etiket}-{}", std::process::id()));
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
    fn kimlik_ilk_kez_uretildiginde_dosyaya_yazilir() {
        let gecici = GeciciDizin::yeni("kimlik");
        let kimlik = kimlik_yukle_veya_uret(gecici.yol()).unwrap();
        let yol = gecici.yol().join(DEPO_DIZINI).join(KIMLIK_DOSYASI);
        assert!(yol.exists());
        assert_eq!(
            std::fs::read_to_string(&yol).unwrap().trim(),
            kimlik.onaltilik()
        );
    }

    #[test]
    fn kimlik_ikinci_cagrida_ayni_kalir() {
        let gecici = GeciciDizin::yeni("kimlik2");
        let a = kimlik_yukle_veya_uret(gecici.yol()).unwrap();
        let b = kimlik_yukle_veya_uret(gecici.yol()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bozuk_kimlik_dosyasi_yenisi_uretir() {
        let gecici = GeciciDizin::yeni("bozukkimlik");
        let dizin = gecici.yol().join(DEPO_DIZINI);
        std::fs::create_dir_all(&dizin).unwrap();
        std::fs::write(dizin.join(KIMLIK_DOSYASI), b"bozuk").unwrap();
        let kimlik = kimlik_yukle_veya_uret(gecici.yol()).unwrap();
        assert_eq!(kimlik.onaltilik().len(), 32);
    }

    #[test]
    fn surum_bos_degildir() {
        assert!(!SURUM.is_empty());
        assert!(SURUM.starts_with('0'));
    }

    #[test]
    fn varsayilan_ayar_gecerlidir() {
        assert!(varsayilan_parca_ayari().dogrula().is_ok());
    }
}
