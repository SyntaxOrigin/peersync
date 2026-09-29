//! Test içinde geçici dizin üreten, `Drop` ile temizleyen kapsayıcı.
//!
//! Neden `tempfile` yok: bağımlılık politikası (WORKER_CONTRACT § 3.2)
//! `tempfile`'i hiçbir projede vermez; yardımcı kendi kodumuzla yazılır.
//!
//! Benzersizlik `std::process::id()` ve etiketten gelir; rastgelelik crate'i
//! kullanılmaz. Aynı etiketle ikinci bir dizin açılırsa eski içerik önce silinir
//! (test yeniden çalıştırıldığında temiz başlar).
//!
//! `Drop` içinden hata döndürülemez; temizlik hatası bilinçli olarak yutulur.

use std::path::{Path, PathBuf};

/// Geçici dizin kapsayıcısı.
pub struct GeciciDizin {
    yol: PathBuf,
}

impl GeciciDizin {
    /// `std::env::temp_dir()` altında, etiketten türetilmiş benzersiz dizin oluşturur.
    ///
    /// # Hatalar
    ///
    /// Dizin oluşturulamazsa [`std::io::Error`] döner.
    pub fn yeni(etiket: &str) -> std::io::Result<GeciciDizin> {
        let kok = std::env::temp_dir().join(format!("peersync-{etiket}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&kok);
        std::fs::create_dir_all(&kok)?;
        Ok(GeciciDizin { yol: kok })
    }

    /// Dizin yolu.
    pub fn yol(&self) -> &Path {
        &self.yol
    }

    /// Dizin altına göreli yol oluşturur (üst dizinleri de yaratır).
    pub fn yaz(&self, goreli: &str) -> PathBuf {
        let yol = self.yol.join(goreli);
        if let Some(ust) = yol.parent() {
            let _ = std::fs::create_dir_all(ust);
        }
        yol
    }

    /// Göreli yola bayt yazar.
    ///
    /// # Hatalar
    ///
    /// Yazma başarısızsa [`std::io::Error`] döner.
    pub fn dosya_yaz(&self, goreli: &str, veri: &[u8]) -> std::io::Result<PathBuf> {
        let yol = self.yaz(goreli);
        std::fs::write(&yol, veri)?;
        Ok(yol)
    }
}

impl Drop for GeciciDizin {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.yol);
    }
}

/// Sabit tohumlu xorshift tabanlı test verisi üreticisi.
///
/// Deterministiktir: aynı tohum her zaman aynı bayt dizisini üretir, bu yüzden
/// testler tekrar edilebilir.
pub fn veri_uret(bayt_sayisi: usize, tohum: u64) -> Vec<u8> {
    let mut x = tohum | 1;
    let mut veri = Vec::with_capacity(bayt_sayisi);
    for _ in 0..bayt_sayisi {
        x ^= x >> 12;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        x ^= x >> 25;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        x ^= x >> 27;
        veri.push((x & 0xff) as u8);
    }
    veri
}
