//! UDP taşıma katmanı: çerçeve gönderimi, segmentasyon ve şifreli alma.
//!
//! Bu modülün sorumluluğu el sıkışmadan sonraki taşımanın **akışını** yönetmektir:
//! çerçeveyi şifrelemek, gerekiyorsa segmentlere bölmek, sokete yazmak, gelen
//! datagramları birleştirip çözmek ve zaman aşımına uymaktır.
//! Bu modülün sorumluluğu *değil*: el sıkışma kuralları (bkz. `crate::el_sikisma`)
//! ve senkronizasyon kararları (bkz. `crate::senkron`).
//!
//! # Düz metin / şifreli ayrımı
//!
//! Gelen datagram önce segment olarak birleştirilir. Birleşik yükün ilk baytı
//! taşımanın türünü belirler:
//!
//! - `0x00` → düz metin çerçeve (yalnızca el sıkışmanın ilk üç paketi).
//! - `PS01` / `PS02` → şifreli çerçeve; yön etiketine göre kanal seçilir.
//! - başka bir şey → bozuk paket, hata.
//!
//! Bu ayrım belirsiz değildir: şifreli paketler `SifreliKanal` nonce'inin yön
//! etiketiyle başlar, düz metin paketler ise tek bir ayırt edici baytla. El
//! sıkışma paketlerinin bir segment sanılma olasılığı yoktur (bkz.
//! `crate::protok::SEGMENT_SIHIR`).

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::hata::{Hata, Sonuc};
use crate::kuyruk::{Duraklatma, HizSinirlayici};
use crate::protok::{bol, tur, Birlesim, Cerceve, AZAMI_DATAGRAM};
use crate::sifre::SifreliKanal;

/// Düz metin taşımanın ayırt edici ilk baytı.
pub const DUZ_ISARET: u8 = 0x00;

/// Beklenmeyen çerçevelerin tutulduğu tamponun azami uzunluğu.
pub const TAMPON_SINIRI: usize = 512;

/// UDP alıcı/verici soket tamponu için istenen boyut (2 MiB).
pub const ALICI_TAMPON_BOYUTU: usize = 2 * 1024 * 1024;

/// Gönderimde arka arkaya gönderilebilen segment sayısı (pencere).
///
/// Gerekçe: UDP'de akış denetimi yoktur. Windows'un öntanımlı UDP alma
/// tamponu ~64 KiB'dir; 200 KiB'lık bir çerçeve ~170 segment hâlinde gelir ve
/// hepsi arka arkaya gönderilirse paketler **sessizce** düşer (ölçüldü: 200 KiB
/// gönderiminde 66 KiB ulaştı). 48 segmentlik pencere (~58 KiB) her iki
/// platformun da öntanımlı tamponuna sığar.
pub const SEGMENT_PENCERE: usize = 48;

/// Bir pencere gönderildikten sonra ilerleme bildirimi beklenecek azami süre.
pub const SEGMENT_ACK_ZAMANI: Duration = Duration::from_millis(1000);

/// İlerleme bildirimi (ack) için azami yeniden gönderim sayısı.
pub const SEGMENT_ACK_DENEME: u32 = 4;

/// Alıcının kaç segmentte bir ilerleme bildirimi gönderdiği.
pub const ALICI_ACK_ARALIK: usize = 16;

/// İlerleme bildiriminin ilk baytı.
pub const ACK_ISARETI: u8 = 0xFD;

/// İlerleme bildiriminin bayt cinsinden uzunluğu.
pub const ACK_UZUNLUGU: usize = 7;

/// Bir oturumun taşıma uçları.
#[derive(Debug)]
pub struct Tasima {
    soket: UdpSocket,
    karsi: SocketAddr,
    gonderen: SifreliKanal,
    alan: SifreliKanal,
    birlesim: Birlesim,
    hazir: Vec<Cerceve>,
    hiz: HizSinirlayici,
    duraklatma: Duraklatma,
    gonderilen_bayt: u64,
    alinan_bayt: u64,
    gelen_segment: usize,
    son_okuma: Option<Instant>,
}

impl Tasima {
    /// Soket, karşı adres ve iki yönlü kanaldan taşıma uçları oluşturur.
    pub fn yeni(
        soket: UdpSocket,
        karsi: SocketAddr,
        gonderen: SifreliKanal,
        alan: SifreliKanal,
        hiz: HizSinirlayici,
        duraklatma: Duraklatma,
    ) -> Tasima {
        Tasima {
            soket,
            karsi,
            gonderen,
            alan,
            birlesim: Birlesim::yeni(),
            hazir: Vec::new(),
            hiz,
            duraklatma,
            gonderilen_bayt: 0,
            alinan_bayt: 0,
            gelen_segment: 0,
            son_okuma: None,
        }
    }

    /// Karşı tarafın adresi.
    pub fn karsi(&self) -> SocketAddr {
        self.karsi
    }

    /// Karşı tarafın adresini değiştirir (keşif sonrası el sıkışma için).
    pub fn karsi_ayarla(&mut self, adres: SocketAddr) {
        self.karsi = adres;
    }

    /// Paylaşılan duraklat/devam anahtarı.
    pub fn duraklatma(&self) -> Duraklatma {
        self.duraklatma.clone()
    }

    /// Hız sınırını değiştirir.
    pub fn hiz_ayarla(&mut self, hiz: HizSinirlayici) {
        self.hiz = hiz;
    }

    /// Gönderilen toplam bayt (ölçüm için).
    pub fn gonderilen(&self) -> u64 {
        self.gonderilen_bayt
    }

    /// Alınan toplam bayt (ölçüm için).
    pub fn alinan(&self) -> u64 {
        self.alinan_bayt
    }

    /// Bekleyen tamamlanmamış çerçeve taslağı sayısı (teşhis ve ölçüm için).
    pub fn bekleyen_taslak(&self) -> usize {
        self.birlesim.bekleyen()
    }

    /// Tamamlanan çerçeve sayısı (teşhis ve ölçüm için).
    pub fn tamamlanan_cerceve(&self) -> u64 {
        self.birlesim.tamamlanan()
    }

    /// Gönderim kanalında bir sonraki sıra numarası.
    pub fn siradaki_sira(&self) -> u64 {
        self.gonderen.siradaki_sira()
    }

    /// Çerçeveyi şifreleyip (gerekiyorsa segmentleyerek) karşı tarafa gönderir.
    ///
    /// Çok segmentli çerçeveler **pencereli** gönderilir ve karşı taraftan
    /// ilerleme bildirimi beklenir. Bu akış denetimi olmadan Windows'un ~64 KiB
    /// lık öntanımlı UDP alma tamponu taşar ve paketler sessizce kaybolur
    /// (ölçüldü: 200 KiB gönderiminde yalnızca 66 KiB ulaştı).
    ///
    /// # Hatalar
    ///
    /// Soket hatası, duraklatma durumu, nonce tükenmesi veya
    /// `SEGMENT_ACK_DENEME` denemesinde ilerleme alınamazsa hata döner.
    pub fn gonder(&mut self, cerceve: &Cerceve) -> Sonuc<usize> {
        if cerceve.sifreli_mi() {
            self.sifreli_gonder(cerceve)
        } else {
            self.duz_gonder(cerceve)
        }
    }

    /// Düz metin çerçeve gönderir (yalnız el sıkışma paketleri için).
    pub fn duz_gonder(&mut self, cerceve: &Cerceve) -> Sonuc<usize> {
        let yigin = cerceve.kodla()?;
        let mut paket = Vec::with_capacity(1 + yigin.len());
        paket.push(DUZ_ISARET);
        paket.extend_from_slice(&yigin);
        self.karsi_bekle()?;
        self.hiz.harca(paket.len() as u64);
        self.soket.send_to(&paket, self.karsi)?;
        self.gonderilen_bayt += paket.len() as u64;
        Ok(paket.len())
    }

    /// Şifreli çerçeve gönderir.
    pub fn sifreli_gonder(&mut self, cerceve: &Cerceve) -> Sonuc<usize> {
        let yigin = cerceve.kodla()?;
        let paket = self.gonderen.sifrele(&yigin)?;
        let cerceve_kimligi = self.birlesim.kimlik_ver();
        let parcalar = bol(cerceve_kimligi, &paket)?;
        let toplam = paket.len();
        self.karsi_bekle()?;
        if parcalar.is_empty() {
            self.hiz.harca(paket.len() as u64);
            self.soket.send_to(&paket, self.karsi)?;
        } else {
            self.pencereli_gonder(cerceve_kimligi, &parcalar)?;
        }
        self.gonderilen_bayt += toplam as u64;
        Ok(toplam)
    }

    /// Segmentleri pencere hâlinde gönderir; her pencereden sonra ilerleme bekler.
    fn pencereli_gonder(&mut self, cerceve_kimligi: u32, parcalar: &[Vec<u8>]) -> Sonuc<()> {
        let toplam = parcalar.len();
        let mut baslangic = 0usize;
        let mut deneme = 0u32;
        while baslangic < toplam {
            let pencere = SEGMENT_PENCERE.min(toplam - baslangic);
            for parca in &parcalar[baslangic..baslangic + pencere] {
                self.karsi_bekle()?;
                self.hiz.harca(parca.len() as u64);
                self.soket.send_to(parca, self.karsi)?;
            }
            if self.pencere_onay_bekle(cerceve_kimligi, baslangic, pencere) {
                deneme = 0;
                baslangic += pencere;
            } else {
                deneme += 1;
                if deneme > SEGMENT_ACK_DENEME {
                    return Err(Hata::ZamanAsimi {
                        beklenti: "segment ilerleme bildirimi",
                    });
                }
            }
        }
        Ok(())
    }

    /// Bir pencere için ilerleme bildirimi bekler; alındıysa `true` döner.
    fn pencere_onay_bekle(
        &mut self,
        cerceve_kimligi: u32,
        baslangic: usize,
        pencere: usize,
    ) -> bool {
        let hedef_sira = (baslangic + pencere - 1) as u16;
        let bitis = Instant::now() + SEGMENT_ACK_ZAMANI;
        let mut tampon = vec![0u8; 64];
        while Instant::now() < bitis {
            let kalan = bitis
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            if self.soket.set_read_timeout(Some(kalan)).is_err() {
                return false;
            }
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, kaynak)) if kaynak == self.karsi => {
                    self.alinan_bayt += boyut as u64;
                    if boyut != ACK_UZUNLUGU || tampon[0] != ACK_ISARETI {
                        // Çerçeve değil: bu çağrı yalnızca ilerleme bekliyordu,
                        // paket atlanır (üst katman kendi sırasında bekleyecek).
                        continue;
                    }
                    let kimlik = u32::from_be_bytes([tampon[1], tampon[2], tampon[3], tampon[4]]);
                    let sira = u16::from_be_bytes([tampon[5], tampon[6]]);
                    if kimlik == cerceve_kimligi && sira >= hedef_sira {
                        return true;
                    }
                }
                Ok(_) => {}
                Err(hata) => {
                    // UDP'de ICMP kaynakli "baglanti sifirlandi" hatasi gecici
                    // olabilir (karsi taraf oturumu kapatmis olabilir). Bekleme
                    // penceresi dolana kadar devam edilir; kalici hata
                    // zaman asimi olarak yukari cikar.
                    if !matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::ConnectionReset
                    ) {
                        return false;
                    }
                }
            }
        }
        false
    }

    /// İlerleme bildirimi paketini üretir.
    fn ack_paketi(cerceve_kimligi: u32, sira: u16) -> Vec<u8> {
        let mut paket = Vec::with_capacity(ACK_UZUNLUGU);
        paket.push(ACK_ISARETI);
        paket.extend_from_slice(&cerceve_kimligi.to_be_bytes());
        paket.extend_from_slice(&sira.to_be_bytes());
        paket
    }

    /// İstenen türde bir çerçeve gelene kadar bekler.
    ///
    /// Diğer türler `hazir` tamponuna konur ve sonraki çağrılarda önce oradan
    /// karşılanır; bu, "yanlış sırada gelen bildirim" durumunda oturumun
    /// kilitlenmesini engeller. Zaman aşımında [`Hata::ZamanAsimi`] döner.
    pub fn bekle(&mut self, istenen_tur: u8, zaman_asimi: Duration) -> Sonuc<Cerceve> {
        let bitis = Instant::now() + zaman_asimi;
        let mut tampon = vec![0u8; AZAMI_DATAGRAM];
        loop {
            if let Some(cerceve) = self.hazir_ara(istenen_tur) {
                return Ok(cerceve);
            }
            // Tampon siniri: surekli bildirim alip hic istenen ture ulasamayan
            // oturumda bellek sinirsiz buyumesin.
            if self.hazir.len() > TAMPON_SINIRI {
                self.hazir.clear();
            }
            let kalan = bitis.saturating_duration_since(Instant::now());
            if kalan.is_zero() {
                return Err(Hata::ZamanAsimi {
                    beklenti: "cerceve",
                });
            }
            self.soket
                .set_read_timeout(Some(kalan.min(Duration::from_millis(250))))?;
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, kaynak)) => {
                    self.alinan_bayt += boyut as u64;
                    self.son_okuma = Some(Instant::now());
                    if kaynak != self.karsi {
                        // El sikisma tamamlanana kadar kaynak belirsizdir; o asamada
                        // bekle_duz kullanilir. Buraya yalniz kimligi dogrulanmis
                        // bir oturumdan paket gelir, kaynak eşleşmiyorsa yoksayilir.
                        continue;
                    }
                    if let Some(c) = self.datagram_isle(&tampon[..boyut])? {
                        self.hazir.push(c);
                    }
                }
                Err(hata)
                    if matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(hata) => return Err(hata.into()),
            }
            self.birlesim.bayat_taslaklari_temizle(Instant::now());
        }
    }

    /// Verilen türlerden **herhangi birini** bekle; sıra fark etmez.
    ///
    /// Sunucu rolünde istekler karışık gelir (manifest talebi, parça talebi,
    /// çakışma bildirimi); bu yöntem tek bir tür beklerken diğerlerini kaybetmez.
    /// Zaman aşımında [`Hata::ZamanAsimi`] döner.
    pub fn bekle_birisi(&mut self, turler: &[u8], zaman_asimi: Duration) -> Sonuc<Cerceve> {
        let bitis = Instant::now() + zaman_asimi;
        let mut tampon = vec![0u8; AZAMI_DATAGRAM];
        loop {
            if let Some(cerceve) = self.hazir_ara_birisi(turler) {
                return Ok(cerceve);
            }
            if self.hazir.len() > TAMPON_SINIRI {
                self.hazir.clear();
            }
            let kalan = bitis.saturating_duration_since(Instant::now());
            if kalan.is_zero() {
                return Err(Hata::ZamanAsimi {
                    beklenti: "birlestirilmis cerceve turu",
                });
            }
            self.soket
                .set_read_timeout(Some(kalan.min(Duration::from_millis(250))))?;
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, kaynak)) => {
                    self.alinan_bayt += boyut as u64;
                    self.son_okuma = Some(Instant::now());
                    if kaynak != self.karsi {
                        continue;
                    }
                    if let Some(c) = self.datagram_isle(&tampon[..boyut])? {
                        self.hazir.push(c);
                    }
                }
                Err(hata)
                    if matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(hata) => return Err(hata.into()),
            }
            self.birlesim.bayat_taslaklari_temizle(Instant::now());
        }
    }

    /// Düz metin (el sıkışma) paketleri için çok türlü bekleme.
    pub fn bekle_duz_birisi(&mut self, turler: &[u8], zaman_asimi: Duration) -> Sonuc<Cerceve> {
        let bitis = Instant::now() + zaman_asimi;
        let mut tampon = vec![0u8; AZAMI_DATAGRAM];
        loop {
            let kalan = bitis.saturating_duration_since(Instant::now());
            if kalan.is_zero() {
                return Err(Hata::ZamanAsimi {
                    beklenti: "el sikisma duz metin",
                });
            }
            self.soket.set_read_timeout(Some(kalan))?;
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, _)) => {
                    self.alinan_bayt += boyut as u64;
                    if boyut < 2 || tampon[0] != DUZ_ISARET {
                        continue;
                    }
                    let cerceve = Cerceve::coz(&tampon[1..boyut])?;
                    if turler.contains(&cerceve.tur()) {
                        return Ok(cerceve);
                    }
                }
                Err(hata)
                    if matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(hata) => return Err(hata.into()),
            }
        }
    }

    /// Düz metin (el sıkışma) paketlerini kabul eder.
    ///
    /// Şifreli çerçeve bu aşamada bir hata döndürür: el sıkışmadan önce şifreli
    /// trafik kabul etmek, kimlik doğrulama yapılmadan veri kabul etmek anlamına
    /// gelirdi.
    pub fn bekle_duz(&mut self, istenen_tur: u8, zaman_asimi: Duration) -> Sonuc<Cerceve> {
        let bitis = Instant::now() + zaman_asimi;
        let mut tampon = vec![0u8; AZAMI_DATAGRAM];
        loop {
            let kalan = bitis.saturating_duration_since(Instant::now());
            if kalan.is_zero() {
                return Err(Hata::ZamanAsimi {
                    beklenti: "el sikisma duz metin",
                });
            }
            self.soket.set_read_timeout(Some(kalan))?;
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, _)) => {
                    self.alinan_bayt += boyut as u64;
                    if boyut < 2 || tampon[0] != DUZ_ISARET {
                        continue;
                    }
                    let cerceve = Cerceve::coz(&tampon[1..boyut])?;
                    if cerceve.tur() == istenen_tur {
                        return Ok(cerceve);
                    }
                    if cerceve.tur() == tur::SURUM_HATASI {
                        return Ok(cerceve);
                    }
                }
                Err(hata)
                    if matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(hata) => return Err(hata.into()),
            }
        }
    }

    /// Gelen datagramı işler; çerçeve tamamsa döndürür.
    ///
    /// Eksik çerçeve durumunda periyodik **ilerleme bildirimi** gönderilir; bu,
    /// gönderen tarafın kaybolan segmenti yeniden göndermesini sağlar.
    fn datagram_isle(&mut self, datagram: &[u8]) -> Sonuc<Option<Cerceve>> {
        if datagram.first() == Some(&ACK_ISARETI) {
            return Ok(None);
        }
        let cerceve_kimligi = if crate::protok::segment_mi_pub(datagram) {
            Some(u32::from_be_bytes([
                datagram[4],
                datagram[5],
                datagram[6],
                datagram[7],
            ]))
        } else {
            None
        };
        let adet = crate::protok::segment_sayisi(datagram).unwrap_or(0);
        let birlestirilmis = self.birlesim.besle(datagram, Instant::now())?;
        if birlestirilmis.is_none() {
            self.gelen_segment += 1;
            // Her segmentte ilerleme bildirimi gonderilir. Bildirim 7 bayttir;
            // gonderen taraf pencere sonunu bekledigi icin seyrek bildirim
            // (orn. "her 16 segmentte bir") iki tarafi birbirini bekletir.
            self.ilerleme_bildir();
            return Ok(None);
        }
        self.gelen_segment = 0;
        // Cerceve tamamlandiginda **son** ilerleme bildirimi de gonderilir;
        // aksi hÃ¢lde gonderen taraf son segmenti gonderdikten sonra onay
        // alamaz ve tum pencereyi gereksiz yere yeniden gonderir.
        if let Some(kimlik) = cerceve_kimligi {
            let paket = Self::ack_paketi(kimlik, adet.saturating_sub(1));
            let _ = self.soket.send_to(&paket, self.karsi);
        }
        let yuk = birlestirilmis.unwrap_or_default();
        if yuk.is_empty() {
            return Err(Hata::BozukPaket("birlestirilmis cerceve bos".to_string()));
        }
        let cerceve = match &yuk[..4] {
            [DUZ_ISARET, ..] => Cerceve::coz(&yuk[1..])?,
            [b'P', b'S', ..] => {
                let duz = self.alan.coz(&yuk)?;
                Cerceve::coz(&duz)?
            }
            _ => {
                return Err(Hata::BozukPaket(format!(
                    "tasinan cerceve turu taninmadi (ilk bayt {:#04x})",
                    yuk[0]
                )))
            }
        };
        Ok(Some(cerceve))
    }

    /// Bekleyen taslakların kesintisiz ilerlemesini karşı tarafa bildirir.
    fn ilerleme_bildir(&mut self) {
        for kimlik in self.birlesim.kimlikleri() {
            if let Some(sira) = self.birlesim.en_yuksek_ardisik(kimlik) {
                let paket = Self::ack_paketi(kimlik, sira);
                let _ = self.soket.send_to(&paket, self.karsi);
            }
        }
    }
    fn hazir_ara(&mut self, istenen_tur: u8) -> Option<Cerceve> {
        let sira = self.hazir.iter().position(|c| c.tur() == istenen_tur);
        sira.map(|i| self.hazir.remove(i))
    }

    fn hazir_ara_birisi(&mut self, turler: &[u8]) -> Option<Cerceve> {
        let sira = self
            .hazir
            .iter()
            .position(|c| turler.contains(&c.tur()))
            .or_else(|| {
                // "IstekBitti" her zaman önceliklidir: kapanış işareti geciktirilirse
                // oturum takılı kalır.
                self.hazir.iter().position(|c| c.tur() == tur::ISTEK_BITTI)
            });
        sira.map(|i| self.hazir.remove(i))
    }

    /// Duraklatma durumundaysa bekler.
    fn karsi_bekle(&self) -> Sonuc<()> {
        if !self.duraklatma.duraklatildi_mi() {
            return Ok(());
        }
        while self.duraklatma.duraklatildi_mi() {
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Son başarılı okumanın zamanı (günlük için).
    pub fn son_okuma(&self) -> Option<Instant> {
        self.son_okuma
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kimlik::{Gizli, OturumOzutu};
    use crate::protok::UzakDosya;
    use crate::sifre::{oturum_tanimlayici, KanitMuhrü, Oturum, Yon};
    use std::thread;

    fn ozut() -> OturumOzutu {
        OturumOzutu::turet(&Gizli::metinden("tasima-testi")).unwrap()
    }

    fn cift() -> (Tasima, Tasima) {
        let soket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let soket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_a = soket_a.local_addr().unwrap();
        let adres_b = soket_b.local_addr().unwrap();
        let o = ozut();
        let istemci = Oturum::istemci(&o).unwrap();
        let sunucu = Oturum::sunucu(&o).unwrap();
        let a = Tasima::yeni(
            soket_a,
            adres_b,
            crate::sifre::SifreliKanal::gonderen(
                crate::sifre::Anahtar::yeni(*istemci.gonderen.baytlar()),
                Yon::IstemciEs,
            ),
            crate::sifre::SifreliKanal::alan(
                crate::sifre::Anahtar::yeni(*istemci.alan.baytlar()),
                Yon::EsIstemci,
            ),
            HizSinirlayici::sinirsiz(),
            Duraklatma::yeni(),
        );
        let b = Tasima::yeni(
            soket_b,
            adres_a,
            crate::sifre::SifreliKanal::gonderen(
                crate::sifre::Anahtar::yeni(*sunucu.gonderen.baytlar()),
                Yon::EsIstemci,
            ),
            crate::sifre::SifreliKanal::alan(
                crate::sifre::Anahtar::yeni(*sunucu.alan.baytlar()),
                Yon::IstemciEs,
            ),
            HizSinirlayici::sinirsiz(),
            Duraklatma::yeni(),
        );
        (a, b)
    }

    #[test]
    fn duz_metin_cerceve_iletilir() {
        let (mut a, mut b) = cift();
        a.duz_gonder(&Cerceve::ManifestAl).unwrap();
        let gelen = b
            .bekle_duz(tur::MANIFEST_AL, Duration::from_secs(2))
            .unwrap();
        assert_eq!(gelen, Cerceve::ManifestAl);
        assert!(b.alinan() > 0);
    }

    #[test]
    fn sifreli_kucuk_cerceve_iletilir() {
        let (mut a, mut b) = cift();
        a.sifreli_gonder(&Cerceve::IstekBitti).unwrap();
        let gelen = b.bekle(tur::ISTEK_BITTI, Duration::from_secs(2)).unwrap();
        assert_eq!(gelen, Cerceve::IstekBitti);
    }

    #[test]
    fn sifreli_buyuk_cerceve_segmentlenerek_iletilir() {
        // AlÄ±cÄ± ayrÄ± iÅŸ parÃ§acÄ±ÄŸÄ±nda Ã§alÄ±ÅŸÄ±r: gÃ¶nderim, pencere ilerleme
        // bildirimini **eÅŸzamanlÄ±** bekler; tek iÅŸ parÃ§acÄ±ÄŸÄ± bunu yapamaz.
        let (mut a, b) = cift();
        let veri: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let beklenen = veri.len();
        let alici = thread::spawn(move || {
            let mut b = b;
            b.bekle(tur::PARCA_GELDI, Duration::from_secs(30))
        });
        let cerceve = Cerceve::ParcaGeldi {
            dosya_karmasi: [1u8; 32],
            parca_karmasi: [2u8; 32],
            veri,
        };
        a.sifreli_gonder(&cerceve).unwrap();
        match alici.join().unwrap().unwrap() {
            Cerceve::ParcaGeldi { veri, .. } => assert_eq!(veri.len(), beklenen),
            diger => panic!("beklenmeyen cerceve: {diger:?}"),
        }
    }

    #[test]
    fn yanlis_sira_tur_uzerinde_zaman_asimi_verir() {
        let (mut a, mut b) = cift();
        a.sifreli_gonder(&Cerceve::IstekBitti).unwrap();
        let hata = b
            .bekle(tur::MANIFEST, Duration::from_millis(300))
            .unwrap_err();
        assert!(matches!(hata, Hata::ZamanAsimi { .. }));
    }

    #[test]
    fn duz_metin_beklerken_sifreli_paket_kabul_edilmez() {
        let (mut a, mut b) = cift();
        a.sifreli_gonder(&Cerceve::IstekBitti).unwrap();
        let hata = b
            .bekle_duz(tur::MANIFEST_AL, Duration::from_millis(300))
            .unwrap_err();
        assert!(matches!(hata, Hata::ZamanAsimi { .. }));
    }

    #[test]
    fn sira_disi_cerceveler_tamponlanir_ve_sonra_verilir() {
        let (mut a, mut b) = cift();
        a.sifreli_gonder(&Cerceve::Yok).unwrap();
        a.sifreli_gonder(&Cerceve::IstekBitti).unwrap();
        assert_eq!(
            b.bekle(tur::ISTEK_BITTI, Duration::from_secs(2)).unwrap(),
            Cerceve::IstekBitti
        );
        assert_eq!(
            b.bekle(tur::YOK, Duration::from_secs(1)).unwrap(),
            Cerceve::Yok
        );
    }

    #[test]
    fn bozuk_sifreli_paket_hata_dondurur() {
        let soket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let soket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_a = soket_a.local_addr().unwrap();
        let adres_b = soket_b.local_addr().unwrap();
        let o = ozut();
        let istemci = Oturum::istemci(&o).unwrap();
        // Anahtarı tutmayan bir saldırgan geçerli bir görünümlü paket üretemez:
        // Poly1305 etiketi tutmaz.
        let sahte_soket = soket_a.try_clone().unwrap();
        let _a = Tasima::yeni(
            soket_a,
            adres_b,
            crate::sifre::SifreliKanal::gonderen(
                crate::sifre::Anahtar::yeni(*istemci.gonderen.baytlar()),
                Yon::IstemciEs,
            ),
            crate::sifre::SifreliKanal::alan(
                crate::sifre::Anahtar::yeni(*istemci.alan.baytlar()),
                Yon::EsIstemci,
            ),
            HizSinirlayici::sinirsiz(),
            Duraklatma::yeni(),
        );
        let mut b = Tasima::yeni(
            soket_b,
            adres_a,
            crate::sifre::SifreliKanal::gonderen(
                crate::sifre::Anahtar::yeni(*istemci.gonderen.baytlar()),
                Yon::EsIstemci,
            ),
            crate::sifre::SifreliKanal::alan(
                crate::sifre::Anahtar::yeni(*istemci.alan.baytlar()),
                Yon::IstemciEs,
            ),
            HizSinirlayici::sinirsiz(),
            Duraklatma::yeni(),
        );
        let mut veri = Vec::new();
        veri.extend_from_slice(b"PS01");
        veri.extend_from_slice(&0u64.to_le_bytes());
        veri.extend_from_slice(&[0u8; 32]);
        sahte_soket.send_to(&veri, adres_b).unwrap();
        let hata = b.bekle(tur::YOK, Duration::from_millis(400)).unwrap_err();
        assert!(matches!(
            hata,
            Hata::SifrelemeHatasi | Hata::ZamanAsimi { .. }
        ));
    }

    #[test]
    fn kanit_muhrü_ve_oturum_tanimlayici_birlikte_calisir() {
        let o = ozut();
        let m = KanitMuhrü::turet(&o).unwrap();
        let tanim = oturum_tanimlayici([9u8; 8], [8u8; 8]);
        let kanit = m.mruhle(b"PEERSYNC-DOGRULA-V1", &tanim).unwrap();
        assert!(m.ac(b"PEERSYNC-DOGRULA-V1", &kanit, &tanim).is_ok());
    }

    #[test]
    fn manifest_cercevesi_kapsamli_iletilir() {
        let (mut a, b) = cift();
        let alici = thread::spawn(move || {
            let mut b = b;
            b.bekle(tur::MANIFEST, Duration::from_secs(30))
        });
        let dosyalar: Vec<UzakDosya> = (0..500u32)
            .map(|i| UzakDosya {
                yol: format!("klasor{i}/dosya.txt"),
                boyut: u64::from(i) * 100,
                karma: [i as u8; 32],
                parca_sayisi: i,
                liste_ozeti: [(i + 1) as u8; 32],
                revizyon: u64::from(i),
                sahip: [i as u8; 16],
            })
            .collect();
        a.sifreli_gonder(&Cerceve::Manifest {
            dosyalar: dosyalar.clone(),
        })
        .unwrap();
        match alici.join().unwrap().unwrap() {
            Cerceve::Manifest { dosyalar: gelen } => assert_eq!(gelen, dosyalar),
            diger => panic!("beklenmeyen cerceve: {diger:?}"),
        }
    }
}
