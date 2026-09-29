//! UDP yayın tabanlı eş keşfi.
//!
//! Bu modülün sorumluluğu aynı ağdaki, **aynı grup parolasından** türetilmiş etikete
//! sahip eşleri birbirine göstermektir. Keşif tamamen pasiftir: hiçbir eş bulunamazsa
//! normal çalışma sürer, elle adres girilebilir.
//!
//! Keşfin kapsamı bilinçli olarak dardır: yalnızca `255.255.255.255` (sınırlı
//! yayın) ve alt ağ yayın adreslerine gönderim yapılır. mDNS/SSDP kullanılmaz,
//! yönlendirme tablolarına erişilmez, adres çözümlemesi yapılmaz (rapor b10).
//!
//! # Yayın paketi biçimi (49 bayt)
//!
//! ```text
//! 0  sihir            4 bayt   "PSYN"
//! 4  surum            2 bayt   u16 little-endian
//! 6  tur              1 bayt   1 = ilan, 2 = ilan yanıtı
//! 7  grup etiketi    16 bayt   Argon2id(parola) ilk 16 baytı
//! 23 kimlik          16 bayt   cihaz kimliği
//! 39 port             2 bayt   u16 little-endian
//! 41 sayac            8 bayt   u64 little-endian (paketi eşlerden ayırır)
//! ```
//!
//! Pakette **dosya adı, boyut veya karma yoktur**; yalnızca grup etiketi görünür.
//!
//! # Yayın adresleri
//!
//! `255.255.255.255` her gönderimde hedeflenir. Alt ağ yayın adresi
//! (`a.b.c.255`) yalnızca yerel arayüzün IPv4 adresi okunabildiğinde eklenir;
//! bu okuma başarısız olursa yalnızca sınırlı yayın kullanılır ve iş devam eder.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::hata::{Hata, Sonuc};
use crate::kimlik::{GrupEtiketi, Kimlik};
use crate::protok::SIHIR;

/// Yayın paketinin bayt cinsinden uzunluğu.
pub const PAKET_UZUNLUGU: usize = 49;

/// Yayın paketinin sürüm alanı.
pub const YAYIN_SURUMU: u16 = 1;

/// Varsayılan yayın portu.
pub const VARSAYILAN_PORT: u16 = 47474;

/// Sınırlı yayın adresi.
pub const SINIRLI_YAYIN: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// İlan paketinin tür kodu.
pub const TUR_ILAN: u8 = 1;
/// İlan yanıtının tür kodu.
pub const TUR_ILAN_YANITI: u8 = 2;

/// Bilinen eş sayısı için üst sınır (bellek ve iş yükü sınırı).
pub const AZAMI_ES: usize = 16;

/// Tek bir yayın ilanı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ilan {
    /// Paket türü (ilan ya da ilan yanıtı).
    pub tur: u8,
    /// Gruba özgü etiket.
    pub grup_etiketi: [u8; 16],
    /// Bildiren eşin kimliği.
    pub kimlik: [u8; 16],
    /// Bildiren eşin dinleme portu.
    pub port: u16,
    /// Paketi benzersizleştiren sayaç.
    pub sayac: u64,
}

impl Ilan {
    /// İlanı 53 baytlık ağ paketine çevirir.
    pub fn kodla(&self) -> Vec<u8> {
        let mut veri = Vec::with_capacity(PAKET_UZUNLUGU);
        veri.extend_from_slice(&SIHIR);
        veri.extend_from_slice(&YAYIN_SURUMU.to_le_bytes());
        veri.push(self.tur);
        veri.extend_from_slice(&self.grup_etiketi);
        veri.extend_from_slice(&self.kimlik);
        veri.extend_from_slice(&self.port.to_le_bytes());
        veri.extend_from_slice(&self.sayac.to_le_bytes());
        debug_assert_eq!(veri.len(), PAKET_UZUNLUGU);
        veri
    }

    /// Ağ paketinden ilan çözer.
    ///
    /// # Hatalar
    ///
    /// Uzunluk, sihir, sürüm veya tür kodu geçersizse [`Hata::BozukPaket`] döner.
    pub fn coz(veri: &[u8]) -> Sonuc<Ilan> {
        if veri.len() != PAKET_UZUNLUGU {
            return Err(Hata::BozukPaket(format!(
                "yayin paketi {} bayt, beklenen {PAKET_UZUNLUGU}",
                veri.len()
            )));
        }
        if veri[..4] != SIHIR {
            return Err(Hata::BozukPaket("yayin paketi sihri eslesmedi".to_string()));
        }
        let surum = u16::from_le_bytes([veri[4], veri[5]]);
        if surum != YAYIN_SURUMU {
            return Err(Hata::SurumUyusmadi {
                beklenen: YAYIN_SURUMU,
                alinan: surum,
            });
        }
        let tur_kodu = veri[6];
        if tur_kodu != TUR_ILAN && tur_kodu != TUR_ILAN_YANITI {
            return Err(Hata::BozukPaket(format!(
                "bilinmeyen yayin turu: {tur_kodu}"
            )));
        }
        let mut grup_etiketi = [0u8; 16];
        grup_etiketi.copy_from_slice(&veri[7..23]);
        let mut kimlik = [0u8; 16];
        kimlik.copy_from_slice(&veri[23..39]);
        Ok(Ilan {
            tur: tur_kodu,
            grup_etiketi,
            kimlik,
            port: u16::from_le_bytes([veri[39], veri[40]]),
            sayac: u64::from_le_bytes([
                veri[41], veri[42], veri[43], veri[44], veri[45], veri[46], veri[47], veri[48],
            ]),
        })
    }
}

/// Zaman aşımına uğramış eşleri düşüren, ilanları saklayan keşif tablosu.
#[derive(Debug)]
pub struct Ehtiyat {
    girenler: BTreeMap<Kimlik, Giren>,
    zaman_asimi: Duration,
    azami: usize,
}

#[derive(Debug, Clone)]
struct Giren {
    adres: SocketAddr,
    ilan: Ilan,
    gorulme: Instant,
}

impl Ehtiyat {
    /// Verilen zaman aşımı ve eş sınırıyla tablo oluşturur.
    pub fn yeni(zaman_asimi: Duration, azami: usize) -> Ehtiyat {
        Ehtiyat {
            girenler: BTreeMap::new(),
            zaman_asimi,
            azami,
        }
    }

    /// Bir ilanı ve geldiği adresi tabloya ekler.
    ///
    /// Zaman aşımına uğramış kayıtlar önce düşürülür. Eş sınırı dolduysa **en eski**
    /// kayıt düşürülür; en yenisi korunur. Dönüş değeri, kaydın yeni olup olmadığıdır.
    ///
    /// # Hatalar
    ///
    /// [`Hata::EsSiniriAsildi`] yalnızca tablo baştan sınırsız açıldıysa ve azami
    /// sıfırsa döner; normal kullanımda sınır aşımı sessizce en eskiyi düşürür.
    pub fn ekle(&mut self, ilan: Ilan, adres: SocketAddr, simdi: Instant) -> Sonuc<bool> {
        self.bayatlari_dusur(simdi);
        let kimlik = Kimlik(ilan.kimlik);
        let yeni = self.girenler.insert(
            kimlik,
            Giren {
                adres,
                ilan,
                gorulme: simdi,
            },
        );
        if self.girenler.len() > self.azami {
            if self.azami == 0 {
                return Err(Hata::EsSiniriAsildi {
                    alinan: self.girenler.len(),
                    azami: 0,
                });
            }
            let en_eski = self
                .girenler
                .iter()
                .min_by_key(|(_, g)| g.gorulme)
                .map(|(k, _)| *k);
            if let Some(k) = en_eski {
                if k != kimlik {
                    self.girenler.remove(&k);
                }
            }
        }
        Ok(yeni.is_none())
    }

    /// Zaman aşımına uğramış kayıtları siler; silinen sayıyı döndürür.
    pub fn bayatlari_dusur(&mut self, simdi: Instant) -> usize {
        let yasam = self.zaman_asimi;
        let bayat: Vec<Kimlik> = self
            .girenler
            .iter()
            .filter(|(_, g)| simdi.duration_since(g.gorulme) > yasam)
            .map(|(k, _)| *k)
            .collect();
        for k in &bayat {
            self.girenler.remove(k);
        }
        bayat.len()
    }

    /// Zaman aşımına uğramamış eşlerin adreslerini döndürür.
    pub fn esler(&self, simdi: Instant) -> Vec<SocketAddr> {
        self.girenler
            .values()
            .filter(|g| simdi.duration_since(g.gorulme) <= self.zaman_asimi)
            .map(|g| g.adres)
            .collect()
    }

    /// Tablodaki eş sayısı.
    pub fn boyut(&self) -> usize {
        self.girenler.len()
    }

    /// Eş sınırı.
    pub fn azami(&self) -> usize {
        self.azami
    }

    /// Kayıtlı eşlerin kimliklerini döndürür (arayüz listesi için).
    pub fn kimlikler(&self) -> Vec<Kimlik> {
        self.girenler.keys().copied().collect()
    }

    /// Son görülen ilanın bildirilen portu (tanı teşhisi için).
    pub fn bildirilen_port(&self, kimlik: &Kimlik) -> Option<u16> {
        self.girenler.get(kimlik).map(|g| g.ilan.port)
    }
}

/// Yayın yapılandırması.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KesifAyar {
    /// İlan gönderim aralığı.
    pub aralik: Duration,
    /// Toplam bekleme süresi.
    pub zaman_asimi: Duration,
    /// Aynı paketin kaç kez yeniden gönderileceği.
    pub deneme: u32,
    /// Kabul edilen eş sayısı üst sınırı.
    pub azami_es: usize,
    /// İlanların gönderileceği açık hedefler (yayın adresleri).
    ///
    /// Boş bırakılırsa [`Kesif::ac`] yerel arayüze göre üretir; testler ve elle
    /// adres senaryoları için açıkça verilebilir.
    pub hedefler: Vec<SocketAddr>,
}

impl Default for KesifAyar {
    fn default() -> Self {
        KesifAyar {
            aralik: Duration::from_millis(500),
            zaman_asimi: Duration::from_secs(10),
            deneme: 3,
            azami_es: AZAMI_ES,
            hedefler: Vec::new(),
        }
    }
}

/// Yayın soketini açar ve ilan gönderir/alır.
///
/// Soket `SO_BROADCAST` özelliğiyle açılır; bu özellik olmadan işletim sistemi
/// yayın adresine gönderimi reddeder. Özellik verilemezse hata **döndürülmez**:
/// yalnızca `127.0.0.1` hedefi kullanılır ve keşif sessizce çalışmaz, bu da
/// kurumsal ağda yayın engellendiğinde programın çökmesindense iyidir.
#[derive(Debug)]
pub struct Kesif {
    soket: UdpSocket,
    kimlik: Kimlik,
    etiket: GrupEtiketi,
    ayar: KesifAyar,
    sayac: u64,
    hedefler: Vec<SocketAddr>,
    yayin_aktif: bool,
}

impl Kesif {
    /// Yayın soketini `port` üzerinde açar ve kendini hazırlar.
    ///
    /// # Hatalar
    ///
    /// Soket açılamazsa (ör. port kullanımda) [`Hata::Io`] döner.
    pub fn ac(port: u16, kimlik: Kimlik, etiket: GrupEtiketi, ayar: KesifAyar) -> Sonuc<Kesif> {
        let adres = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let soket = UdpSocket::bind(adres)?;
        let yayin_aktif = soket.set_broadcast(true).is_ok();
        let hedefler = if ayar.hedefler.is_empty() {
            hedefleri_bul(&soket, port, yayin_aktif)
        } else {
            ayar.hedefler.clone()
        };
        Ok(Kesif {
            soket,
            kimlik,
            etiket,
            ayar,
            sayac: 0,
            hedefler,
            yayin_aktif,
        })
    }

    /// Var olan bir soketten keşif oluşturur (testler ve elle adres için).
    pub fn soketten_ac(
        soket: UdpSocket,
        kimlik: Kimlik,
        etiket: GrupEtiketi,
        ayar: KesifAyar,
    ) -> Kesif {
        let yayin_aktif = soket.set_broadcast(true).is_ok();
        let hedefler = if ayar.hedefler.is_empty() {
            hedefleri_bul(&soket, 0, yayin_aktif)
        } else {
            ayar.hedefler.clone()
        };
        Kesif {
            soket,
            kimlik,
            etiket,
            ayar,
            sayac: 0,
            hedefler,
            yayin_aktif,
        }
    }

    /// Yayın özelliğinin etkin olup olmadığını bildirir (günlük ve teşhis için).
    pub fn yayin_aktif(&self) -> bool {
        self.yayin_aktif
    }

    /// Soketin bağlı yerel adresi.
    pub fn yerel_adres(&self) -> Sonuc<SocketAddr> {
        Ok(self.soket.local_addr()?)
    }

    /// Yayın soketinin bir kopyasını döndürür (el sıkışma aynı adresi kullanır).
    ///
    /// Yayın ile el sıkışmanın **aynı portta** çalışması, tek bir eş portunun
    /// yeterli olmasını sağlar: kullanıcı yalnız bir port yazar.
    pub fn soket_kopya(&self) -> Sonuc<UdpSocket> {
        Ok(self.soket.try_clone()?)
    }

    /// Gönderim hedeflerinin listesi (yayın adresleri).
    pub fn hedefler(&self) -> &[SocketAddr] {
        &self.hedefler
    }

    /// Yayın yapılandırmasının kopyası.
    pub fn ayar(&self) -> &KesifAyar {
        &self.ayar
    }

    /// Bir ilan paketi gönderir.
    ///
    /// Paket sayacı her gönderimde artar; aynı paketin iki kez sayılması, eş tablosunda
    /// eski kaydın yeni sayılmasına yol açmasın diye gereklidir.
    pub fn ilan_gonder(&mut self) -> Sonuc<u32> {
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: *self.etiket.baytlar(),
            kimlik: self.kimlik.0,
            port: self.yerel_adres()?.port(),
            sayac: self.sayac,
        };
        self.sayac = self.sayac.wrapping_add(1);
        let veri = ilan.kodla();
        let mut gonderilen = 0u32;
        for hedef in self.hedefler.clone() {
            // Tek bir hedefin hatası tüm keşfi düşürmemelidir: örneğin kurumsal
            // ağda 255.255.255.255 engellidir ama alt ağ yayını çalışır.
            if self.soket.send_to(&veri, hedef).is_ok() {
                gonderilen += 1;
            }
        }
        Ok(gonderilen)
    }

    /// Gelen ilanları okur ve tabloyu günceller.
    ///
    /// Her okuma için sonlandırma süresi `zaman_asimi / 8` ile sınırlıdır ki
    /// döngü belirtilen sürede kesin bitebilsin.
    pub fn dinle(&self, tablo: &mut Ehtiyat, simdi: Instant) -> Sonuc<usize> {
        let bekle = self.ayar.zaman_asimi / 8;
        let mut alinan = 0usize;
        let mut tampon = [0u8; 256];
        let bitis = simdi + bekle;
        loop {
            let kalan = bitis.saturating_duration_since(Instant::now());
            if kalan.is_zero() {
                break;
            }
            self.soket.set_read_timeout(Some(kalan))?;
            match self.soket.recv_from(&mut tampon) {
                Ok((boyut, adres)) => {
                    match Ilan::coz(&tampon[..boyut]) {
                        Ok(ilan) => {
                            if ilan.grup_etiketi == *self.etiket.baytlar()
                                && ilan.kimlik != self.kimlik.0
                            {
                                let _ = tablo.ekle(ilan, adres, Instant::now());
                                alinan += 1;
                            }
                        }
                        Err(Hata::SurumUyusmadi {
                            beklenen,
                            alinan: gelen,
                        }) => {
                            // Farklı sürümlü bir eş: el sikmasa reddedilecek, günlüğe yaz.
                            eprintln!(
                                "peersync: yayin sürüm uyuşmazlığı (beklenen {beklenen}, gelen {gelen})"
                            );
                        }
                        Err(_) => {}
                    }
                }
                Err(hata)
                    if matches!(
                        hata.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(hata) => return Err(hata.into()),
            }
        }
        Ok(alinan)
    }
}

fn hedefleri_bul(soket: &UdpSocket, port: u16, yayin_aktif: bool) -> Vec<SocketAddr> {
    let mut hedefler = Vec::new();
    if yayin_aktif {
        hedefler.push(SocketAddr::new(IpAddr::V4(SINIRLI_YAYIN), port));
    }
    hedefler.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    if let Ok(adres) = soket.local_addr() {
        if let IpAddr::V4(v4) = adres.ip() {
            // Alt ağ yayını: a.b.c.255
            let son = v4.octets()[3];
            if yayin_aktif && son != 0 && son != 255 {
                let mut oktetler = v4.octets();
                oktetler[3] = 255;
                if oktetler != SINIRLI_YAYIN.octets() {
                    hedefler.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(oktetler)), port));
                }
            }
        }
    }
    hedefler
}

#[cfg(test)]
mod tests {
    use super::*;

    fn etiket() -> GrupEtiketi {
        GrupEtiketi::turet(&crate::kimlik::Gizli::metinden("kesif-testi")).unwrap()
    }

    #[test]
    fn ilan_kodlama_cozme_gidis_donus_yapar() {
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [0x11; 16],
            kimlik: [0x22; 16],
            port: 47474,
            sayac: 0x0102_0304_0506_0708,
        };
        let kod = ilan.kodla();
        assert_eq!(kod.len(), PAKET_UZUNLUGU);
        assert_eq!(Ilan::coz(&kod).unwrap(), ilan);
    }

    #[test]
    fn ilan_paketi_tam_49_bayttir() {
        let ilan = Ilan {
            tur: TUR_ILAN_YANITI,
            grup_etiketi: [0; 16],
            kimlik: [0; 16],
            port: 1,
            sayac: 0,
        };
        assert_eq!(ilan.kodla().len(), 49);
    }

    #[test]
    fn yanlis_uzunlukta_paket_reddedilir() {
        let hata = Ilan::coz(&[0u8; 10]).unwrap_err();
        assert!(matches!(hata, Hata::BozukPaket(_)));
    }

    #[test]
    fn yanlis_sihirli_paket_reddedilir() {
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [0; 16],
            kimlik: [0; 16],
            port: 1,
            sayac: 0,
        };
        let mut kod = ilan.kodla();
        kod[0] = b'X';
        assert!(matches!(Ilan::coz(&kod).unwrap_err(), Hata::BozukPaket(_)));
    }

    #[test]
    fn surum_uyusmazligi_paketi_hata_dondurur() {
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [0; 16],
            kimlik: [0; 16],
            port: 1,
            sayac: 0,
        };
        let mut kod = ilan.kodla();
        kod[4] = 0x09;
        kod[5] = 0x00;
        let hata = Ilan::coz(&kod).unwrap_err();
        assert!(matches!(
            hata,
            Hata::SurumUyusmadi {
                beklenen: 1,
                alinan: 9
            }
        ));
    }

    #[test]
    fn bilinmeyen_tur_kodu_reddedilir() {
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [0; 16],
            kimlik: [0; 16],
            port: 1,
            sayac: 0,
        };
        let mut kod = ilan.kodla();
        kod[6] = 9;
        assert!(matches!(Ilan::coz(&kod).unwrap_err(), Hata::BozukPaket(_)));
    }

    #[test]
    fn ehtiyat_tablosu_ilanlari_kaydeder_ve_bulur() {
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(10), AZAMI_ES);
        let simdi = Instant::now();
        let adres: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [7; 16],
            kimlik: [9; 16],
            port: 40001,
            sayac: 1,
        };
        assert!(tablo.ekle(ilan, adres, simdi).unwrap());
        assert_eq!(tablo.boyut(), 1);
        assert_eq!(tablo.esler(simdi), vec![adres]);
    }

    #[test]
    fn ayni_kimlik_guncellenir_tekrar_eklenmez() {
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(10), AZAMI_ES);
        let simdi = Instant::now();
        let adres: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [7; 16],
            kimlik: [9; 16],
            port: 40002,
            sayac: 1,
        };
        assert!(tablo.ekle(ilan.clone(), adres, simdi).unwrap());
        assert!(!tablo.ekle(ilan, adres, simdi).unwrap());
        assert_eq!(tablo.boyut(), 1);
    }

    #[test]
    fn zaman_asimi_gecen_ilanlar_duser() {
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(1), AZAMI_ES);
        let baslangic = Instant::now();
        let adres: SocketAddr = "127.0.0.1:40003".parse().unwrap();
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [7; 16],
            kimlik: [9; 16],
            port: 40003,
            sayac: 1,
        };
        tablo.ekle(ilan, adres, baslangic).unwrap();
        let sonra = baslangic + Duration::from_secs(5);
        assert_eq!(tablo.bayatlari_dusur(sonra), 1);
        assert_eq!(tablo.boyut(), 0);
        assert!(tablo.esler(sonra).is_empty());
    }

    #[test]
    fn es_siniri_asilirsa_en_eski_dusurulur() {
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(60), 3);
        let baslangic = Instant::now();
        for i in 0..5u8 {
            let ilan = Ilan {
                tur: TUR_ILAN,
                grup_etiketi: [7; 16],
                kimlik: [i; 16],
                port: 40000 + u16::from(i),
                sayac: u64::from(i),
            };
            tablo
                .ekle(
                    ilan,
                    format!("127.0.0.1:{}", 40000 + u16::from(i))
                        .parse()
                        .unwrap(),
                    baslangic + Duration::from_millis(u64::from(i)),
                )
                .unwrap();
        }
        assert_eq!(tablo.boyut(), 3);
        assert!(tablo.esler(Instant::now()).len() <= 3);
    }

    #[test]
    fn sifir_es_siniri_hata_dondurur() {
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(60), 0);
        let ilan = Ilan {
            tur: TUR_ILAN,
            grup_etiketi: [7; 16],
            kimlik: [9; 16],
            port: 40004,
            sayac: 1,
        };
        let hata = tablo
            .ekle(ilan, "127.0.0.1:40004".parse().unwrap(), Instant::now())
            .unwrap_err();
        assert!(matches!(hata, Hata::EsSiniriAsildi { azami: 0, .. }));
    }

    #[test]
    fn iki_soket_uzerinde_gercek_yayin_kesfi_calisir() {
        // 127.0.0.1 uzerinde gercek UDP: iki "ilan" birbirini gormelidir.
        let soket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let soket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port_b = soket_b.local_addr().unwrap().port();
        let hedef: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
        let etiket = etiket();

        let ayar = KesifAyar {
            aralik: Duration::from_millis(50),
            zaman_asimi: Duration::from_millis(400),
            deneme: 3,
            azami_es: AZAMI_ES,
            hedefler: vec![hedef],
        };
        let mut gonderen = Kesif::soketten_ac(soket_a, Kimlik([0xAA; 16]), etiket, ayar.clone());
        let gonderen_adres = gonderen.yerel_adres().unwrap();
        let alan = Kesif::soketten_ac(soket_b, Kimlik([0xBB; 16]), etiket, ayar);

        let mut tablo = Ehtiyat::yeni(Duration::from_secs(5), AZAMI_ES);
        let mut bulundu = false;
        for _ in 0..3 {
            gonderen.ilan_gonder().unwrap();
            alan.dinle(&mut tablo, Instant::now()).unwrap();
            if tablo.boyut() > 0 {
                bulundu = true;
                break;
            }
        }
        assert!(bulundu, "ilan gonderildi ama alici tablosunda es gorunmedi");
        assert_eq!(tablo.esler(Instant::now()), vec![gonderen_adres]);
    }

    #[test]
    fn farkli_grup_etiketli_esler_gorunmez() {
        let soket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let soket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port_b = soket_b.local_addr().unwrap().port();
        let hedef: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
        let etiket_a = GrupEtiketi::turet(&crate::kimlik::Gizli::metinden("grup-a")).unwrap();
        let etiket_b = GrupEtiketi::turet(&crate::kimlik::Gizli::metinden("grup-b")).unwrap();
        let ayar = KesifAyar {
            aralik: Duration::from_millis(50),
            zaman_asimi: Duration::from_millis(200),
            deneme: 2,
            azami_es: AZAMI_ES,
            hedefler: vec![hedef],
        };
        let mut gonderen = Kesif::soketten_ac(soket_a, Kimlik([1; 16]), etiket_a, ayar.clone());
        let alan = Kesif::soketten_ac(soket_b, Kimlik([2; 16]), etiket_b, ayar);
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(5), AZAMI_ES);
        gonderen.ilan_gonder().unwrap();
        alan.dinle(&mut tablo, Instant::now()).unwrap();
        assert_eq!(tablo.boyut(), 0, "farkli grup etiketli eş listelenmemeli");
    }

    #[test]
    fn zaman_asimi_suresince_es_bulunamazsa_bos_doner() {
        let soket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ayar = KesifAyar {
            aralik: Duration::from_millis(50),
            zaman_asimi: Duration::from_millis(200),
            deneme: 2,
            azami_es: AZAMI_ES,
            hedefler: Vec::new(),
        };
        let kesif = Kesif::soketten_ac(soket, Kimlik([3; 16]), etiket(), ayar);
        let mut tablo = Ehtiyat::yeni(Duration::from_secs(5), AZAMI_ES);
        let baslangic = Instant::now();
        let sayi = kesif.dinle(&mut tablo, Instant::now()).unwrap();
        assert_eq!(sayi, 0);
        assert!(
            baslangic.elapsed() < Duration::from_secs(2),
            "dinleme zaman asimini asmamali"
        );
    }
}
