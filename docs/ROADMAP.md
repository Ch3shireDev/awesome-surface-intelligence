# Ograniczenia i plan

Wymagania i sposób ich sprawdzenia: [Status](status.md).

## Co jest gotowe

Skan etapami, historia zmian, panel z rolami, szyfrowanie, harmonogram, import i eksport, integracja z DefectDojo.
Czysty start, demo i restart bez utraty danych sprawdza workflow `clean-start` w GitHub Actions.

## Znane ograniczenia

| ograniczenie | co robić dziś |
|---|---|
| UDP jest domyślnie wyłączone | włączyć świadomie, patrz [Bezpieczeństwo](guide/safety.md) |
| pełny skan TCP przez relay lub NAT może gubić porty | podać porty celu jawnie |
| test 16 384 adresów wykonano na loopbacku | w prawdziwej sieci czas będzie dłuższy |
| dwa skany z tej samej sekundy dostają to samo ID, drugi nie zapisuje się do bazy | nie uruchamiać dwóch skanów naraz |
| dwa zbiory celów w jednym teście DefectDojo zamykają sobie znaleziska | osobny produkt lub engagement na zbiór |

## Dalsze prace

- unikalne ID przebiegu,
- test skali w prawdziwej sieci,
- wgrywanie sygnatur z panelu.
