//! El sıkışma durum makinesi: karşılıklı parola doğrulama ve oturum kurulumu.
//!
//! Bu modülün sorumluluğu iki tarafın **aynı grup parolasını** bildiğini kanıtlamak
//! ve bu kanıt üzerinden iki yönlü oturum anahtarı kurmaktır. Bu modülün
//! sorumluluğu *değil*: baytların taşınması (bkz. `crate::tasma`) ve verinin
//! senkronizasyonu (bkz. `crate::senkron`).
//!
//! # Durum makinesi
//!
//! ```text
//! ISTEMCI                                        SUNUCU
//!    |  Merhaba (düz metin) -------------------------->|
//!    |                     MerhabaYanit + kanıt (düz metin)
//!    |  <------------------------------------------------|
//!    |  kanıtı AÇ; başarısızsa BAĞLANTI KURULMAZ       |
//!    |  MerhabaYanit(kanıt) (düz metin) -------------->|
//!    |                       kanıtı AÇ; başarısızsa KES |
//!    |<----------- şifreli çerçeveler ------------------|
//! ```
//!
//! # Güvenlik kararları
//!
//! 1. **Parola asla taşınmaz.** İki taraf da aynı sabit metni (`DOGRULA_METNI`)
//!    kanıt anahtarıyla şifreleyip ilk 32 baytını gönderir. Anahtar yanlış
//!    paroladan türetilmişse açma **her zaman** başarısız olur.
//! 2. **Sürüm anlaşmazlığı açıkça bildirilir** (`SurumHatasi` çerçevesi) ve
//!    oturum kurulmaz.
//! 3. **Doğrulama başarısız olursa bağlantı derhal kapatılır**: [`Baglanti`]
//!    üretilmez, hiçbir şifreli çerçeve gönderilmez.
//! 4. **Tekrarlama koruması:** kanıt nonce'u, iki tarafın da bildiği
//!    `oturum_tanimlayici`den türetilir; tanımlayıcı iki rastgele sayaçtan kurulur,
//!    bu yüzden üçüncü bir gözlemci geçmiş bir kanıtı yeniden oynatamaz.
//! 5. **Zayıf parametre reddi:** istemci sunucudan daha düşük Argon2id maliyeti
//!    bildirirse istek yok sayılır; böylece bir saldırgan zayıf türetmeyi
//!    dayatarak kaba kuvveti ucuzlatamaz.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::hata::{Hata, Sonuc};
use crate::kimlik::{GrupEtiketi, Kimlik, OturumOzutu, Turetme};
use crate::protok::{tur, Cerceve, AZAMI_DATAGRAM, SURUM};
use crate::sifre::{oturum_tanimlayici, Anahtar, KanitMuhrü, Oturum, SifreliKanal};
use crate::tasma::{Tasima, DUZ_ISARET};

/// İki tarafın da bildiği, mühürlenecek sabit metin.
pub const DOGRULA_METNI: &[u8] = b"PEERSYNC-DOGRULA-V1";

/// El sıkışma zaman aşımı ayarı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SikismaAyar {
    /// Bir aşamanın bekleneceği azami süre.
    pub zaman_asimi: Duration,
    /// Zaman aşımında kaç kez yeniden deneneceği.
    pub deneme: u32,
}

impl Default for SikismaAyar {
    fn default() -> Self {
        SikismaAyar {
            zaman_asimi: Duration::from_secs(5),
            deneme: 3,
        }
    }
}

/// El sıkışma sonunda kurulan oturum.
#[derive(Debug)]
pub struct Baglanti {
    /// Türetilmiş anahtar çifti.
    pub oturum: Oturum,
    /// Karşı tarafın kimliği.
    pub karsi_kimlik: Kimlik,
    /// Karşı tarafın adresi.
    pub karsi_adres: SocketAddr,
    /// Oturuma özgü tanımlayıcı (günlük ve teşhis için; sır değildir).
    pub oturum_id: [u8; 12],
}

impl Baglanti {
    /// Gönderme kanalı üretir.
    pub fn gonderen_kanal(&self) -> SifreliKanal {
        SifreliKanal::gonderen(
            Anahtar::yeni(*self.oturum.gonderen.baytlar()),
            self.oturum.gonderen_yon,
        )
    }

    /// Alma kanalı üretir.
    pub fn alan_kanal(&self) -> SifreliKanal {
        SifreliKanal::alan(
            Anahtar::yeni(*self.oturum.alan.baytlar()),
            self.oturum.gonderen_yon.karsi(),
        )
    }

    /// Kurulan oturumdan taşıma uçlarını üretir.
    pub fn tasima(
        &self,
        soket: UdpSocket,
        hiz: crate::kuyruk::HizSinirlayici,
        duraklatma: crate::kuyruk::Duraklatma,
    ) -> Tasima {
        Tasima::yeni(
            soket,
            self.karsi_adres,
            self.gonderen_kanal(),
            self.alan_kanal(),
            hiz,
            duraklatma,
        )
    }

    /// Oturum kimliğinin ilk 8 baytını onaltılık metne çevirir (günlük için).
    pub fn kisa_oturum_id(&self) -> String {
        self.oturum_id[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Rastgele sayaç üretir (8 bayt, işletim sistemi entropisinden).
pub fn rastgele_sayac() -> Sonuc<[u8; 8]> {
    let mut baytlar = [0u8; 8];
    getrandom::getrandom(&mut baytlar)
        .map_err(|_| Hata::BozukPaket("işletim sistemi entropisi alınamadı".to_string()))?;
    Ok(baytlar)
}

fn duz_yig(cerceve: &Cerceve) -> Sonuc<Vec<u8>> {
    let govde = cerceve.kodla()?;
    let mut paket = Vec::with_capacity(1 + govde.len());
    paket.push(DUZ_ISARET);
    paket.extend_from_slice(&govde);
    Ok(paket)
}

fn duz_oku(veri: &[u8]) -> Sonuc<Cerceve> {
    if veri.len() < 2 || veri[0] != DUZ_ISARET {
        return Err(Hata::BozukPaket(
            "düz metin işareti yok: el sıkışma paketi bekleniyordu".to_string(),
        ));
    }
    Cerceve::coz(&veri[1..])
}

fn zaman_asimi_mi(hata: &std::io::Error) -> bool {
    matches!(
        hata.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Protokol sürümünü doğrular ve uyuşmazlık çerçevesi üretir.
pub fn surum_kontrol(alinan: u16) -> Sonuc<u16> {
    if alinan == SURUM {
        Ok(SURUM)
    } else {
        Err(Hata::SurumUyusmadi {
            beklenen: SURUM,
            alinan,
        })
    }
}

/// İstemci tarafı: el sıkışmayı başlatır ve tamamlar.
///
/// # Hatalar
///
/// - Sürüm uyuşmazlığında [`Hata::SurumUyusmazi`] yerine [`Hata::SurumUyusmadi`].
/// - Parola/kanıt uyuşmazlığında [`Hata::KimlikDogrulanmadi`] ve oturum kurulmaz.
/// - Zaman aşımında [`Hata::ZamanAsimi`].
pub fn istemci(
    soket: &UdpSocket,
    karsi: SocketAddr,
    benim_kimlik: Kimlik,
    etiket: GrupEtiketi,
    ozut: &OturumOzutu,
    ayar: SikismaAyar,
) -> Sonuc<Baglanti> {
    let ture = Turetme::oturum();
    let istemci_nonce = rastgele_sayac()?;
    let (karsi_kimlik, es_nonce, kanit) = {
        let mut deneme = 0u32;
        // Toplam deneme sayisi sinirlidir: yalnizca zaman asimi sayan bir dongu,
        // surekli gelen yanlis paketlerde (orn. ayni makinede yanlis yonlu trafik)
        // sonsuza kadar dongude kalir.
        let azami_deneme = ayar.deneme.saturating_mul(2).saturating_add(2);
        loop {
            deneme += 1;
            if deneme > azami_deneme {
                return Err(Hata::ZamanAsimi {
                    beklenti: "el sikisma merhaba yaniti",
                });
            }
            let paket = duz_yig(&Cerceve::Merhaba {
                surum: SURUM,
                grup_ozeti: *etiket.baytlar(),
                kimlik: benim_kimlik.0,
                nonce: istemci_nonce,
                argon_bellek_kib: ture.bellek_kib,
                argon_gecis: ture.gecis,
            })?;
            soket.send_to(&paket, karsi)?;
            let mut tampon = vec![0u8; AZAMI_DATAGRAM];
            soket
                .set_read_timeout(Some(ayar.zaman_asimi))
                .map_err(Hata::Io)?;
            let sonuc = soket.recv_from(&mut tampon);
            match sonuc {
                Ok((boyut, kaynak)) if kaynak == karsi => match duz_oku(&tampon[..boyut]) {
                    Ok(Cerceve::SurumHatasi { beklenen, alinan }) => {
                        return Err(Hata::SurumUyusmadi { beklenen, alinan });
                    }
                    Ok(Cerceve::MerhabaYanit {
                        surum,
                        kimlik,
                        nonce,
                        kanit,
                        ..
                    }) => {
                        surum_kontrol(surum)?;
                        break (kimlik, nonce, kanit);
                    }
                    Ok(_) => continue,
                    Err(_) => continue,
                },
                Ok(_) => continue,
                Err(hata) if zaman_asimi_mi(&hata) => {}
                Err(hata) => return Err(hata.into()),
            }
        }
    };

    let tanim = oturum_tanimlayici(istemci_nonce, es_nonce);
    let muhre = KanitMuhrü::turet(ozut)?;
    // Yanlış parola burada yakalanır: hata döner, oturum kurulmaz.
    muhre.ac(DOGRULA_METNI, &kanit, &tanim)?;

    let dogrulama = muhre.mruhle(DOGRULA_METNI, &tanim)?;
    let paket = duz_yig(&Cerceve::MerhabaYanit {
        surum: SURUM,
        kimlik: benim_kimlik.0,
        nonce: [0u8; 8],
        argon_bellek_kib: ture.bellek_kib,
        argon_gecis: ture.gecis,
        kanit: dogrulama,
    })?;
    soket.send_to(&paket, karsi)?;

    Ok(Baglanti {
        oturum: Oturum::istemci(ozut)?,
        karsi_kimlik: Kimlik(karsi_kimlik),
        karsi_adres: karsi,
        oturum_id: tanim,
    })
}

/// Sunucu tarafı: el sıkışmayı kabul eder ve tamamlar.
///
/// # Hatalar
///
/// [`Hata::SurumUyusmadi`], [`Hata::ZamanAsimi`], [`Hata::KimlikDogrulanmadi`].
/// Üçü de **hiçbir taşıma kanalı kurulmadan** döner.
pub fn sunucu(
    soket: &UdpSocket,
    benim_kimlik: Kimlik,
    etiket: GrupEtiketi,
    ozut: &OturumOzutu,
    ayar: SikismaAyar,
) -> Sonuc<Baglanti> {
    let ture = Turetme::oturum();
    let (istemci_adres, istemci_kimlik, istemci_nonce) = {
        let mut deneme = 0u32;
        let azami_deneme = ayar.deneme.saturating_mul(2).saturating_add(2);
        loop {
            deneme += 1;
            if deneme > azami_deneme {
                return Err(Hata::ZamanAsimi {
                    beklenti: "el sikisma merhaba",
                });
            }
            let mut tampon = vec![0u8; AZAMI_DATAGRAM];
            soket
                .set_read_timeout(Some(ayar.zaman_asimi))
                .map_err(Hata::Io)?;
            let sonuc = soket.recv_from(&mut tampon);
            match sonuc {
                Ok((boyut, adres)) => match duz_oku(&tampon[..boyut]) {
                    Ok(Cerceve::Merhaba {
                        surum,
                        grup_ozeti,
                        kimlik,
                        nonce,
                        argon_bellek_kib,
                        argon_gecis,
                    }) => {
                        if surum != SURUM {
                            let bildirim = Cerceve::SurumHatasi {
                                beklenen: SURUM,
                                alinan: surum,
                            };
                            let _ = soket.send_to(&duz_yig(&bildirim)?, adres);
                            return Err(Hata::SurumUyusmadi {
                                beklenen: SURUM,
                                alinan: surum,
                            });
                        }
                        if grup_ozeti != *etiket.baytlar() || kimlik == benim_kimlik.0 {
                            continue;
                        }
                        if argon_bellek_kib < ture.bellek_kib || argon_gecis < ture.gecis {
                            continue;
                        }
                        break (adres, kimlik, nonce);
                    }
                    Ok(_) => continue,
                    Err(_) => continue,
                },
                Err(hata) if zaman_asimi_mi(&hata) => {}
                Err(hata) => return Err(hata.into()),
            }
        }
    };

    let es_nonce = rastgele_sayac()?;
    let tanim = oturum_tanimlayici(istemci_nonce, es_nonce);
    let muhre = KanitMuhrü::turet(ozut)?;
    let kanit = muhre.mruhle(DOGRULA_METNI, &tanim)?;
    let paket = duz_yig(&Cerceve::MerhabaYanit {
        surum: SURUM,
        kimlik: benim_kimlik.0,
        nonce: es_nonce,
        argon_bellek_kib: ture.bellek_kib,
        argon_gecis: ture.gecis,
        kanit,
    })?;
    soket.send_to(&paket, istemci_adres)?;

    let mut alindi = None;
    for _ in 0..ayar.deneme.max(1) + 1 {
        let mut tampon = vec![0u8; AZAMI_DATAGRAM];
        soket
            .set_read_timeout(Some(ayar.zaman_asimi))
            .map_err(Hata::Io)?;
        let sonuc = soket.recv_from(&mut tampon);
        match sonuc {
            Ok((boyut, adres)) if adres == istemci_adres => {
                if let Ok(Cerceve::MerhabaYanit {
                    kanit: k, surum, ..
                }) = duz_oku(&tampon[..boyut])
                {
                    surum_kontrol(surum)?;
                    alindi = Some(k);
                    break;
                }
            }
            Ok(_) => {}
            Err(hata) if zaman_asimi_mi(&hata) => {}
            Err(hata) => return Err(hata.into()),
        }
    }
    let dogrulama_kaniti = alindi.ok_or(Hata::ZamanAsimi {
        beklenti: "el sikisma dogrulama kaniti",
    })?;
    // Yanlış parola burada yakalanır: oturum KURULMAZ ve karşı taraf bağlantıyı keser.
    muhre.ac(DOGRULA_METNI, &dogrulama_kaniti, &tanim)?;

    Ok(Baglanti {
        oturum: Oturum::sunucu(ozut)?,
        karsi_kimlik: Kimlik(istemci_kimlik),
        karsi_adres: istemci_adres,
        oturum_id: tanim,
    })
}

/// El sıkışmanın ardından ilk şifreli çerçeve türü (sunucu tarafı beklemesinde kullanılır).
pub const OTURUM_BASLA_TURU: u8 = tur::MANIFEST_AL;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kimlik::Gizli;
    use std::thread;

    fn ozut(parola: &str) -> OturumOzutu {
        OturumOzutu::turet(&Gizli::metinden(parola)).unwrap()
    }

    /// Soketten bir paket alır; gelmezse 0 döndürür.
    fn al(soket: &UdpSocket, tampon: &mut [u8], sure: Duration) -> usize {
        if soket.set_read_timeout(Some(sure)).is_err() {
            return 0;
        }
        soket.recv_from(tampon).map_or(0, |(n, _)| n)
    }

    fn hizli_ayar() -> SikismaAyar {
        SikismaAyar {
            zaman_asimi: Duration::from_millis(700),
            deneme: 2,
        }
    }

    #[test]
    fn rastgele_sayac_uretilir_ve_tekrarlanmaz() {
        let a = rastgele_sayac().unwrap();
        let b = rastgele_sayac().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 8);
    }

    #[test]
    fn surum_kontrol_eslesen_surumu_kabul_eder() {
        assert_eq!(surum_kontrol(SURUM).unwrap(), SURUM);
    }

    #[test]
    fn surum_kontrol_uyusmazlik_hatasi_dondurur() {
        let hata = surum_kontrol(99).unwrap_err();
        assert!(matches!(
            hata,
            Hata::SurumUyusmadi {
                beklenen: 1,
                alinan: 99
            }
        ));
    }

    #[test]
    fn duz_yig_isaretli_paket_uretir() {
        let paket = duz_yig(&Cerceve::ManifestAl).unwrap();
        assert_eq!(paket[0], DUZ_ISARET);
        assert_eq!(duz_oku(&paket).unwrap(), Cerceve::ManifestAl);
    }

    #[test]
    fn isaretsiz_paket_el_sikmada_bozuk_sayilir() {
        let paket = Cerceve::ManifestAl.kodla().unwrap();
        assert!(matches!(duz_oku(&paket).unwrap_err(), Hata::BozukPaket(_)));
    }

    #[test]
    fn iki_is_parcaciginda_el_sikisma_basarilir() {
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("grup-2026")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let soket_istemci = soket_i.try_clone().unwrap();
        let o_sunucu = ozut("dogru-parola-2026");
        let o_istemci = ozut("dogru-parola-2026");
        let etiket_s = etiket;
        let is_parcacigi = thread::spawn(move || {
            sunucu(&soket_sunucu, Kimlik([0x11; 16]), etiket_s, &o_sunucu, ayar)
        });
        let baglanti = istemci(
            &soket_istemci,
            adres_s,
            Kimlik([0x22; 16]),
            etiket,
            &o_istemci,
            ayar,
        );
        let sunucu_sonuc = is_parcacigi.join().unwrap();
        let baglanti = baglanti.unwrap();
        let sunucu_baglanti = sunucu_sonuc.unwrap();
        assert_eq!(baglanti.karsi_kimlik, Kimlik([0x11; 16]));
        assert_eq!(sunucu_baglanti.karsi_kimlik, Kimlik([0x22; 16]));
        assert_eq!(baglanti.oturum_id, sunucu_baglanti.oturum_id);
    }

    #[test]
    fn el_sikisma_ardindan_sifreli_kanal_calisir() {
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("kanal-grubu")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let soket_istemci = soket_i.try_clone().unwrap();
        let o_sunucu = ozut("kanal-parolasi");
        let o_istemci = ozut("kanal-parolasi");
        let is_parcacigi =
            thread::spawn(move || sunucu(&soket_sunucu, Kimlik([7; 16]), etiket, &o_sunucu, ayar));
        let baglanti = istemci(
            &soket_istemci,
            adres_s,
            Kimlik([8; 16]),
            etiket,
            &o_istemci,
            ayar,
        )
        .unwrap();
        let sunucu_baglanti = is_parcacigi.join().unwrap().unwrap();

        let mut gonderen = baglanti.gonderen_kanal();
        let mut alan = sunucu_baglanti.alan_kanal();
        let paket = gonderen.sifrele(b"el sikisma sonrasi").unwrap();
        assert_eq!(alan.coz(&paket).unwrap(), b"el sikisma sonrasi".to_vec());
        assert_eq!(baglanti.kisa_oturum_id().len(), 16);
    }

    #[test]
    fn yanlis_parola_istemcide_kimlik_dogrulanmadi_verir() {
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("grup-2026")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let soket_istemci = soket_i.try_clone().unwrap();
        let o_sunucu = ozut("dogru-parola-2026");
        let o_istemci = ozut("yanlis-parola-2026");
        let is_parcacigi =
            thread::spawn(move || sunucu(&soket_sunucu, Kimlik([1; 16]), etiket, &o_sunucu, ayar));
        let hata = istemci(
            &soket_istemci,
            adres_s,
            Kimlik([2; 16]),
            etiket,
            &o_istemci,
            ayar,
        )
        .unwrap_err();
        assert!(
            matches!(hata, Hata::KimlikDogrulanmadi { .. }),
            "beklenmeyen hata: {hata}"
        );
        let sunucu_hata = is_parcacigi.join().unwrap().unwrap_err();
        assert!(matches!(
            sunucu_hata,
            Hata::KimlikDogrulanmadi { .. } | Hata::ZamanAsimi { .. }
        ));
    }

    #[test]
    fn yanlis_parola_sunucuda_baglanti_kurulmaz() {
        // Sunucu tarafı: istemci dogrulama kanitini yanlis gonderir.
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("grup-2026")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let soket_istemci = soket_i.try_clone().unwrap();
        let o_sunucu = ozut("dogru-parola");
        let is_parcacigi =
            thread::spawn(move || sunucu(&soket_sunucu, Kimlik([1; 16]), etiket, &o_sunucu, ayar));
        // Sahte istemci: dogrulama kanitini bozuk gonderiyor.
        let paket = duz_yig(&Cerceve::Merhaba {
            surum: SURUM,
            grup_ozeti: *etiket.baytlar(),
            kimlik: [0x33; 16],
            nonce: [7u8; 8],
            argon_bellek_kib: 19 * 1024,
            argon_gecis: 2,
        })
        .unwrap();
        soket_istemci.send_to(&paket, adres_s).unwrap();

        let bozuk = duz_yig(&Cerceve::MerhabaYanit {
            surum: SURUM,
            kimlik: [0x33; 16],
            nonce: [0u8; 8],
            argon_bellek_kib: 19 * 1024,
            argon_gecis: 2,
            kanit: [0xFF; 32],
        })
        .unwrap();
        soket_istemci.send_to(&bozuk, adres_s).unwrap();
        let sunucu_sonuc = is_parcacigi.join().unwrap();
        let hata = sunucu_sonuc.expect_err("bozuk kanitla oturum kurulmamali");
        assert!(matches!(
            hata,
            Hata::KimlikDogrulanmadi { .. } | Hata::ZamanAsimi { .. }
        ));
    }

    #[test]
    fn surum_uyusmazligi_her_iki_tarafta_reddedilir() {
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("grup-surum")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let o_sunucu = ozut("parola");
        let is_parcacigi = {
            let etiket_sunucu = etiket;
            thread::spawn(move || {
                sunucu(
                    &soket_sunucu,
                    Kimlik([0x55; 16]),
                    etiket_sunucu,
                    &o_sunucu,
                    ayar,
                )
            })
        };
        // Istemci tarafi surum 99 bildirir; sunucu reddetmeli ve bildirim gondermeli.
        let paket = duz_yig(&Cerceve::Merhaba {
            surum: 99,
            grup_ozeti: *etiket.baytlar(),
            kimlik: [0x44; 16],
            nonce: [5u8; 8],
            argon_bellek_kib: 19 * 1024,
            argon_gecis: 2,
        })
        .unwrap();
        soket_i.send_to(&paket, adres_s).unwrap();
        let mut yanit = vec![0u8; 512];
        let okunan = al(&soket_i, &mut yanit, ayar.zaman_asimi);
        let hata = is_parcacigi.join().unwrap().unwrap_err();
        assert!(matches!(hata, Hata::SurumUyusmadi { alinan: 99, .. }));
        if okunan > 0 {
            match duz_oku(&yanit[..okunan]).unwrap() {
                Cerceve::SurumHatasi { beklenen, alinan } => {
                    assert_eq!(beklenen, SURUM);
                    assert_eq!(alinan, 99);
                }
                diger => panic!("beklenmeyen cerceve: {diger:?}"),
            }
        }
    }

    #[test]
    fn surucu_yok_deneme() {
        // Karşı taraf yokken sunucu hiçbir oturum kurmadan zaman aşımına düşer.
        let soket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("yardimci")).unwrap();
        let hata = sunucu(
            &soket,
            Kimlik([0x55; 16]),
            etiket,
            &ozut("parola"),
            SikismaAyar {
                zaman_asimi: Duration::from_millis(60),
                deneme: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(hata, Hata::ZamanAsimi { .. }));
    }

    #[test]
    fn farkli_grup_etiketi_ile_el_sikisma_kurulamaz() {
        let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adres_s = soket_s.local_addr().unwrap();
        let soket_i = UdpSocket::bind("127.0.0.1:0").unwrap();
        let etiket_s = GrupEtiketi::turet(&Gizli::metinden("grup-bir")).unwrap();
        let etiket_i = GrupEtiketi::turet(&Gizli::metinden("grup-iki")).unwrap();
        let ayar = hizli_ayar();
        let soket_sunucu = soket_s.try_clone().unwrap();
        let soket_istemci = soket_i.try_clone().unwrap();
        let o_sunucu = ozut("parola");
        let o_istemci = ozut("parola");
        let is_parcacigi = thread::spawn(move || {
            sunucu(&soket_sunucu, Kimlik([1; 16]), etiket_s, &o_sunucu, ayar)
        });
        let hata = istemci(
            &soket_istemci,
            adres_s,
            Kimlik([2; 16]),
            etiket_i,
            &o_istemci,
            ayar,
        )
        .unwrap_err();
        assert!(matches!(hata, Hata::ZamanAsimi { .. }));
        assert!(is_parcacigi.join().unwrap().is_err());
    }

    #[test]
    fn karsi_yoksa_zaman_asimi_verir() {
        let soket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let hedef = soket.local_addr().unwrap();
        let etiket = GrupEtiketi::turet(&Gizli::metinden("yok-biri")).unwrap();
        let hata = istemci(
            &soket,
            hedef,
            Kimlik([3; 16]),
            etiket,
            &ozut("parola"),
            hizli_ayar(),
        )
        .unwrap_err();
        assert!(matches!(hata, Hata::ZamanAsimi { .. }));
    }
}
