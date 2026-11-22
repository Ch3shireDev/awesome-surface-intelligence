---
layout: home
hero:
  name: ASI
  text: Attack Surface Intelligence
  tagline: Cykliczny, bezpieczny discovery scan dużej infrastruktury (10 000+ IP) z podziałem na paczki nmap, postępem na żywo i integracją z DefectDojo.
  actions:
    - theme: brand
      text: Szybki start
      link: /guide/quickstart
    - theme: alt
      text: Jak testować
      link: /guide/jury
features:
  - title: Wejście CSV / JSON / TXT
    details: IP, zakresy CIDR i domeny w jednym schemacie. Domeny tylko podpisują adresy z inwentarza — nigdy nie rozszerzają zakresu skanu.
  - title: Dwufazowy skan z adaptacyjnymi paczkami
    details: Szybkie discovery w dużych paczkach, potem skan usług tylko na aktywnych hostach. Rozmiar paczki dobierany z mierzonego czasu na host.
  - title: Postęp w czasie rzeczywistym
    details: Pasek w terminalu i panel web (SSE) z tym samym stanem — fazy, paczki, workery, ETA, wykryte usługi, status uploadu.
  - title: DefectDojo z historią zmian
    details: Jedno znalezisko na IP:port, reimport do stałego testu — DefectDojo sam liczy nowe, zamknięte i reaktywowane usługi.
---

## Jak to działa

1. **Podajesz cele** w panelu albo w pliku.
2. **ASI skanuje etapami**: żywe hosty → usługi → HTTP → sygnatury.
3. **Porównuje z historią** i pokazuje, co jest nowe, zmienione, niestabilne lub zniknęło.
4. **Wysyła wyniki** do DefectDojo.

Pierwszy raz? Przejdź [Szybki start](/guide/quickstart), potem [ścieżkę testowania](/guide/jury).

## Słowniczek

| pojęcie | znaczenie |
|---|---|
| **cel** | adres IP, zakres CIDR albo domena, którą wolno skanować |
| **przebieg** | jedno uruchomienie skanu zbioru celów |
| **asset** | wykryty host albo port, z historią między przebiegami |
| **obserwacja** | pojedynczy fakt z przebiegu: otwarty port, usługa, odpowiedź HTTP, trafienie sygnatury |
| **sygnatura** | reguła YAML rozpoznająca produkt lub ekspozycję, bez exploitów |
| **missing / gone** | brak do potwierdzenia / zniknięcie potwierdzone kolejnymi brakami |
| **flapping** | asset niestabilny, na przemian jest i go nie ma |
| **DefectDojo (DD)** | zewnętrzny system do zarządzania znaleziskami, do którego ASI wysyła wyniki |
| **DEV-n, SEC-n, LAB-n** | identyfikatory wymagań i testów w opisach, można je pominąć przy czytaniu |
