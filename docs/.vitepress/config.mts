import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'pl-PL',
  title: 'ASI',
  description: 'Attack Surface Intelligence — discovery scan dużej infrastruktury z integracją DefectDojo',
  cleanUrls: true,
  lastUpdated: false,
  themeConfig: {
    nav: [
      { text: 'Start', link: '/guide/quickstart' },
      { text: 'Roadmapa', link: '/ROADMAP' },
      { text: 'Status projektu', link: '/status' },
      { text: 'Wizja', link: '/VISION' },
      { text: 'Zadania', link: '/TASKS' },
      { text: 'Ustalenia z mentorem', link: '/MENTOR' },
    ],
    sidebar: [
      { text: 'Wprowadzenie', items: [
        { text: 'Czym jest ASI', link: '/' },
        { text: 'Szybki start', link: '/guide/quickstart' },
        { text: 'Architektura', link: '/guide/architecture' },
      ]},
      { text: 'Działanie', items: [
        { text: 'Format celów (CSV/JSON/TXT)', link: '/guide/targets' },
        { text: 'Podział na paczki nmap', link: '/guide/chunking' },
        { text: 'Panel web (GUI)', link: '/guide/gui' },
        { text: 'Harmonogram i okna czasowe', link: '/guide/schedule' },
        { text: 'Postęp: CLI i panel web', link: '/guide/progress' },
        { text: 'Integracja z DefectDojo', link: '/guide/defectdojo' },
        { text: 'Porównanie przebiegów', link: '/guide/diff' },
        { text: 'Historia i stany assetów', link: '/guide/history' },
        { text: 'Bezpieczeństwo skanowania', link: '/guide/safety' },
        { text: 'Lab testowy i demo', link: '/guide/lab' },
      ]},
      { text: 'Referencja', items: [
        { text: 'Komendy CLI', link: '/guide/cli' },
        { text: 'Adaptery skanerów', link: '/guide/adapters' },
        { text: 'Baza danych', link: '/guide/database' },
        { text: 'Pliki wynikowe', link: '/guide/outputs' },
      ]},
      { text: 'Projekt', items: [
        { text: 'Wizja i architektura docelowa', link: '/VISION' },
        { text: 'Zadania i podział pracy', link: '/TASKS' },
        { text: 'Ustalenia z mentorem (wiążące)', link: '/MENTOR' },
        { text: 'Decyzje', link: '/DECISIONS' },
        { text: 'Roadmapa: gdzie jesteśmy', link: '/ROADMAP' },
        { text: 'Status: zrobione / do zrobienia / decyzje', link: '/status' },
      ]},
    ],
    outline: { level: [2, 3], label: 'Na tej stronie' },
    docFooter: { prev: 'Poprzednia', next: 'Następna' },
    search: { provider: 'local' },
  },
})
