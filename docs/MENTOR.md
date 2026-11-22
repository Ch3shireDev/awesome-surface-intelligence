# Ustalenia z mentorem CBI AGH (21.11.2026, 14:44)

> **Wiążące.** To są ustalenia z konsultacji z mentorem/sędzią wyzwania. Mają pierwszeństwo przed wcześniejszymi
> założeniami w `VISION.md`, `ROADMAP.md`. Jeśli coś w repo im przeczy, popraw repo, nie ustalenia.
> Zapis w decyzjach: [`DECISIONS.md`](DECISIONS.md), decyzja 11.

Źródło: nagranie `21 lis o 14_44.m4a` (7:50), transkrypcja Whisper large-v3. Rozmawiali: mentor (M), Daniel (D),
Paweł (P). Pełna transkrypcja niżej.

## Ustalenia

| # | temat | ustalenie | co to znaczy dla nas |
|---|---|---|---|
| 1 | Rola vs DefectDojo | Nasza aplikacja to **źródło danych (feed) dla DefectDojo**, nie konkurencja ani rozwiązanie „zbudowane na DD”. Uruchamiamy skanery i wysyłamy wyniki do DD. | Zgodne z decyzją 8. Eksport do DD (`reimport-scan`) to obowiązkowa część demo. |
| 2 | Web GUI | **Web GUI jest wymagane** i wysoko punktowane („tam jest całe mięso”: formularze, role, enkrypcja). Wszystkim ma się dać zarządzać z poziomu Web GUI. | Odwraca „na razie bez web UI” z VISION/decyzji 8. Panel web (DEV-4: formularz celów, assety, dashboard) to priorytet. |
| 3 | Architektura (wzorzec MISP) | Mentor **zachęca**, żeby Web GUI było **nakładką (wrapperem) na komendy CLI** działające w Linuksie i na bazę danych, jak w MISP. | Obecny kierunek jest dobry: `asi` CLI + skanery jako komendy (nmap, httpx, …), GUI je woła i czyta bazę. Modułowość skanerów jako osobnych komend to plus. |
| 4 | Baza i szyfrowanie | Zalecany **PostgreSQL** (DD też na nim działa). **Encryption at rest** w bazie = **„darmowe” 5% oceny**. | Postgres dla `asi` (DEV-1). Szyfrowanie w spoczynku musi być **włączone i pokazane w demo/dokumentacji**. Uwaga techniczna niżej. |
| 5 | RBAC | RBAC to **tylko 10%** oceny. **Jedno konto admina jest akceptowalne** („będę rad z tym przeżyć”). Jeśli RBAC, to **wyłącznie lokalny** w naszej aplikacji, **bez synchronizacji z kontami DefectDojo** przez API. | Najpierw jedno konto admina i logowanie do GUI. 4 role (DEV-3) dopiero, gdy zostanie czas. Nie dotykamy użytkowników DD. |
| 6 | Skanery | Zaakceptowane: `nmap`, `httpx`, Wappalyzer i inne narzędzia CLI, także wykrywanie usług. Im bardziej modularne uruchamianie z konsoli, tym lepiej. | SEC-4 (httpx), SEC-5 (nuclei), wykrywanie technologii (Wappalyzer/httpx `-tech-detect`) mają zielone światło. |

### Uwaga techniczna do pkt 4

Mentor powiedział, że Postgres „out of the box” ma encryption at rest. Zwykły PostgreSQL nie ma wbudowanego TDE
(patrz decyzja 9). Żeby zgarnąć te 5%, robimy to tak, żeby dało się to **pokazać**:

1. szyfrowanie pól wrażliwych w aplikacji, AES-256-GCM (SEC-6), już zaplanowane,
2. warstwa na poziomie danych Postgresa: zaszyfrowany wolumen z danymi bazy (LUKS / dm-crypt na VM) albo
   `pg_tde` (Percona), jeśli da się szybko podpiąć do naszego compose,
3. krótka sekcja w dokumentacji: „co jest szyfrowane, czym i gdzie są klucze”.

## Pełna transkrypcja (oczyszczona)

**[00:00] D:** Dobra, zobaczmy. Ja mam pytanie, bo na dalsze zadania były wymienione role, formularze, zakładki itd. To ma być coś dostarczonego osobno przez nas, czy to może być w konfiguracji tego, co będzie dostarczane przez nas?

**[00:45] M:** Dobra, więc usiądźmy i już będę wam nawijał. Proszę, rozgośćcie się.

**[00:52] M:** Jeszcze raz. Pytanie jest takie: jak są formularze i tak dalej, tak?

**[01:00] D:** Tak. Ile z tego to może być po prostu kwestia konfiguracji, a ile to ma być nasz własny kod?

**[01:12] M:** No i przewidujemy funkcjonowanie aplikacji — tego, co wy piszecie. Wasze rozwiązanie nazwijmy to w ten sposób. No i to są te skanery.

**[01:33] D:** Dobra, czyli nasze rozwiązanie ma być po prostu jednym ze źródeł do DefectDojo?

**[01:37] M:** Tak jest. Dokładnie tak. Co do GUI i tak dalej — to my tak na serio, to faktycznie o to chodzi. Natomiast jeśli popatrzycie na RBAC, to RBAC jest oceniany tylko na 10%. Więc jeśli będzie tylko jedno konto — będę rad z tym przeżyć. To jest zrozumiałe, ponieważ w wypadku tworzenia RBAC musielibyście to zrobić tak naprawdę RBAC-first, inaczej będzie to zajmowało bardzo dużo czasu. I teraz: te wszystkie formularze, całe GUI — tu chodzi o to, że tutaj jest całe mięso. Formularze, role, enkrypcja — wszystko w tym miejscu. Nie wiem, czy pytaliście nas o enkrypcję wcześniej?

**[02:37] D:** Nie.

**[02:38] M:** Więc do enkrypcji generalnie zalecamy użycie Postgresa, ponieważ DefectDojo też hula na Postgresie. Postgres od razu, out of the box, ma *encryption at rest* — i to jest w ocenie darmowe 5%. Więc nie ma powodu, żeby nie zalecić używania Postgresa. A macie już coś swojego?

**[02:58] D:** W pierwszej chwili myśleliśmy po prostu o zrobieniu tego jako apkę terminalową (CLI), nie? Ale rozumiemy, że...

**[03:04] M:** Nie, tam jest UI wyszczególniony, żeby z poziomu Web GUI wszystko było zarządzane. Natomiast jeśli chcecie, możecie to zrobić na takiej zasadzie, że jest jakiś *underlying CLI*, który puszcza komendy — tak jak na przykład w MISP-ie jest. Nie wiem, czy korzystaliście z MISP-a?

**[03:25] D:** No chyba nie.

**[03:27] M:** Nie wszystkie programy tak mają, niektóre mają swoje proprietary komendy, biblioteki itd., ale MISP jest tak stworzony, że on woła komendy, które faktycznie funkcjonują w Linuksie. Więc jak wasze Web GUI byłoby tylko i wyłącznie wrapperem na komendy, które tam istnieją i na bazę danych — to jest jak najbardziej akceptowalne! Jeśli mieliście pomysł zrobienia tego jako CLI, to ja was do tego zachęcam, bo Web GUI jako nakładka będzie super.

**[04:11] D:** Dobra, jeszcze zadam takie pytanie: w DefectDojo, z tego co rozumiem, też są konta użytkowników i też jest RBAC. Czy konta użytkowników w DefectDojo mają być jakoś zsynchronizowane z kontami w naszej aplikacji?

**[04:22] M:** Nie, nie mają. W DefectDojo to już sprawdzałem z kolegą — DefectDojo niby ma RBAC przez API, ale to nie jest funkcjonalność *drop-in*. Więc z tego tytułu, jeśli ma być RBAC, to powinien być wyłącznie lokalny. Nie musicie tego synchronizować przez żadne API, zresztą byłoby ciężko. Nie nastawiajcie się na to.

**[05:00] D:** Mnie głównie zastanawiało, czy to ma być rozwiązanie oparte o DefectDojo, czy coś, co się integruje z DefectDojo — i to jest ta druga opcja.

**[05:06] M:** Dobra, a tutaj napisałeś na przykład te skanery, tak? To tutaj mam na przykład nmapa. Ale są też inne wśród skanerów?

**[05:14] D:** Tak, tak, tak. Na przykład httpx i inne. Bo nmapa rozpracowaliśmy na razie.

**[05:21] M:** Ale tutaj jeszcze możecie wrzucić wykrywanie serwisów i tak dalej — to się dopuszcza.

**[05:29] P:** Mamy httpx, Wappalyzer itd. W repozytorium mamy całą listę skanerów.

**[05:52] M:** No więc myślę, że to sobie ogarniecie. I jeśli planowaliście to jako CLI z nakładką GUI, to będzie wam jeszcze łatwiej zrobić to modularnie. Bo jak to puszcza same komendy i ładuje do bazy, to jest dużo bardziej modularne. Powiedzcie mi tylko, proszę, jak się nazywacie jako drużyna, żebyśmy was zapamiętali.

**[06:14]–[07:43]** Sprawy organizacyjne: nazwa drużyny (do sprawdzenia na Discordzie), mentor zapisał Daniela Gustawa. Bez dalszych ustaleń technicznych.

<sub>Poprawione przesłyszenia Whispera: Defend Dojo → DefectDojo, airbag → RBAC, bui/GUE → Web GUI, inkrytszy netres → encryption at rest, łapka laser → Wappalyzer, ATTPX → httpx.</sub>
