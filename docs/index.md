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
      text: Status projektu
      link: /status
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
