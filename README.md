# Virtual Software Machine (VSM)

> User-mode песочница на Go для цифровой криминалистики и OSINT.
> A user-mode sandbox in Go for digital forensics & OSINT.

[![CI](https://github.com/AristarhUcolov/Virtual-Software-Machine/actions/workflows/ci.yml/badge.svg)](https://github.com/AristarhUcolov/Virtual-Software-Machine/actions/workflows/ci.yml)

**Язык / Language:** [**#RU** — Русский](#ru) · [**#ENG** — English](#eng)

---

## RU

User-mode песочница для **цифровой криминалистики и OSINT**. VSM запускает
программу (`.exe` и др.) в изолированном пространстве, перехватывает её
обращения к диску, реестру, сети и процессам и формирует подробный отчёт:
*что, где и как* файл сохраняет, изменяет, добавляет и куда подключается.

Интерфейс и отчёты — **двуязычные** (русский и английский).

### Что делает VSM

| Этап | Описание |
|---|---|
| 🧊 Снимок ДО | Скан файловой системы и реестра до запуска. |
| 🚀 Изолированный запуск | Запуск в **Job Object** + токен **Low Integrity** + перенаправление `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%` в папку-песочницу. |
| 👁 Наблюдение | Хронология событий файловой системы и реестра в реальном времени. |
| 🌐 Сеть | IP-адреса подключений дерева процессов (TCP/UDP), порт, состояние, сервис, обратный DNS. |
| 🔎 DNS | Доменные имена, разрешённые во время анализа (снимок кэша DNS-резолвера, без прав администратора). |
| 🧬 Процессы | Все процессы дерева песочницы с их командными строками — что и как запустил анализируемый файл. |
| 🧊 Снимок ПОСЛЕ | Повторный скан и вычисление разницы. |
| 🎯 След программы | Изменения делятся на «след программы» (запись в песочницу) и «прочий шум ОС». |
| ⚖️ Вердикт | Эвристический анализ: вердикт (Чисто / Подозрительно / Опасно) и индикаторы компрометации. |
| 📄 Отчёт | `report.html`, `report.json`, `iocs.txt` и `iocs.stix.json` (STIX 2.1 для MISP / threat-intel). |

### Архитектура

```
cmd/vsm        — графическое приложение (Fyne)
cmd/vsm-cli    — консольное приложение (без CGO)
internal/
  i18n         — двуязычный каталог сообщений
  config       — корни наблюдения, ветки реестра, лимиты
  snapshot     — снимки и diff файловой системы и реестра
  monitor      — наблюдатель файловой системы в реальном времени
  regmon       — наблюдатель ключей автозагрузки реестра
  netmon       — мониторинг сетевых подключений (IP)
  dnsmon       — снимок кэша DNS-резолвера (доменные имена)
  procmon      — мониторинг процессов дерева песочницы
  analyze      — эвристики IOC и итоговый вердикт
  sandbox      — изоляция запуска (Job Object, токен, редирект)
  report       — генерация отчётов HTML / JSON / IOC
```

### Сборка

Требуется **Go 1.26+**.

```powershell
.\build.ps1            # собрать CLI и GUI
.\build.ps1 -CliOnly   # только консольную версию (компилятор C не нужен)
```

GUI на Fyne использует CGO — нужен компилятор C (mingw-w64):

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT
```

### Использование

**GUI:** запустите `bin\vsm.exe`, выберите файл, нажмите «Запустить в песочнице».

**CLI:**

```powershell
bin\vsm-cli.exe -lang ru -target "C:\путь\sample.exe" -timeout 60
bin\vsm-cli.exe -lang en -target "C:\путь\sample.exe" -low=false
bin\vsm-cli.exe -target "C:\путь\sample.exe" -wsb   # анализ в Windows Sandbox
```

Отчёты сохраняются в `%LOCALAPPDATA%\VSM\workspace\session-<дата>\`:
`report.html` (наглядный), `report.json` (машиночитаемый), `iocs.txt`
(переносимый список индикаторов для VirusTotal / блоклистов / threat-feed).

### Безопасность и ограничения

⚠️ **Важно.** VSM — это **user-mode** инструмент. Он снижает риск (Low
Integrity, Job Object, перенаправление записи), но **не заменяет** полную
изоляцию. Настоящий аналог Sandboxie использует kernel-драйвер; на чистом
Go это невозможно. Для действительно опасных образцов запускайте VSM
**внутри виртуальной машины** (Hyper-V / VMware) или в Windows Sandbox.
Если запуск с Low Integrity недоступен, VSM переходит в режим Medium и
честно указывает это в отчёте. Инструмент предназначен **только для
законного** анализа ПО, цифровой криминалистики, OSINT и обучения.

### Дорожная карта

- [x] Сетевой мониторинг: IP-адреса, порты, сервисы, обратный DNS.
- [x] Мониторинг процессов дерева песочницы.
- [x] Эвристический вердикт и индикаторы компрометации (IOC).
- [x] Разделение следа программы и фонового шума ОС.
- [x] Перехват реестра через `RegNotifyChangeKeyValue` в реальном времени.
- [x] Экспорт индикаторов в переносимый файл `iocs.txt`.
- [x] Интеграция с Windows Sandbox (`.wsb`) для аппаратной изоляции (флаг `-wsb`).
- [x] DNS-мониторинг (имена резолвинга) через кэш DNS-резолвера — без прав администратора.
- [x] Экспорт индикаторов в формат STIX 2.1 (импортируется в MISP).

### Лицензия

Учебно-исследовательский проект. Используйте ответственно.

[⬆ Наверх](#virtual-software-machine-vsm) · [Switch to **#ENG** English](#eng)

---

## ENG

A user-mode sandbox for **digital forensics & OSINT**. VSM runs a program
(`.exe` and others) in an isolated space, captures its disk, registry,
network and process activity and produces a detailed report of *what, where
and how* the file saves, modifies, adds and connects.

The interface and reports are **bilingual** (Russian and English).

### What VSM does

| Stage | Description |
|---|---|
| 🧊 Pre-snapshot | Scan of the file system and registry before the run. |
| 🚀 Isolated run | Runs inside a **Job Object** + **Low Integrity** token + redirection of `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%` into a sandbox folder. |
| 👁 Live watch | Real-time timeline of file-system and registry events. |
| 🌐 Network | Connection IP addresses of the process tree (TCP/UDP): port, state, service, reverse DNS. |
| 🔎 DNS | Domain names resolved during the analysis (DNS resolver cache snapshot, no administrator rights). |
| 🧬 Processes | Every process of the sandbox tree with its command line — what and how the analysed file launched. |
| 🧊 Post-snapshot | Re-scan and difference computation. |
| 🎯 Footprint | Changes are split into "program footprint" (writes into the sandbox) and "other OS noise". |
| ⚖️ Verdict | Heuristic analysis: a verdict (Clean / Suspicious / Dangerous) and indicators of compromise. |
| 📄 Report | `report.html`, `report.json`, `iocs.txt` and `iocs.stix.json` (STIX 2.1 for MISP / threat intel). |

### Architecture

```
cmd/vsm        — graphical application (Fyne)
cmd/vsm-cli    — console application (CGO-free)
internal/
  i18n         — bilingual message catalog
  config       — watch roots, registry keys, limits
  snapshot     — file-system and registry snapshots & diff
  monitor      — real-time file-system watcher
  regmon       — real-time registry autorun watcher
  netmon       — network connection monitoring (IP)
  dnsmon       — DNS resolver cache snapshot (domain names)
  procmon      — sandbox process-tree monitoring
  analyze      — IOC heuristics and final verdict
  sandbox      — execution containment (Job Object, token, redirection)
  report       — HTML / JSON / IOC report generation
```

### Build

Requires **Go 1.26+**.

```powershell
.\build.ps1            # build both CLI and GUI
.\build.ps1 -CliOnly   # CLI only (no C compiler needed)
```

The Fyne GUI uses CGO — a C compiler (mingw-w64) is required:

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT
```

### Usage

**GUI:** run `bin\vsm.exe`, pick a file, press "Run in sandbox".

**CLI:**

```powershell
bin\vsm-cli.exe -lang en -target "C:\path\sample.exe" -timeout 60
bin\vsm-cli.exe -lang ru -target "C:\path\sample.exe" -low=false
bin\vsm-cli.exe -target "C:\path\sample.exe" -wsb   # analyse in Windows Sandbox
```

Reports are saved to `%LOCALAPPDATA%\VSM\workspace\session-<date>\`:
`report.html` (visual), `report.json` (machine-readable), `iocs.txt`
(a portable indicator list for VirusTotal / blocklists / threat feeds).

### Security & limitations

⚠️ **Important.** VSM is a **user-mode** tool. It reduces risk (Low
Integrity, Job Object, write redirection) but does **not** replace full
isolation. A true Sandboxie equivalent uses a kernel driver, which is not
possible in pure Go. Analyse genuinely dangerous samples **inside a virtual
machine** (Hyper-V / VMware) or Windows Sandbox. If Low Integrity is
unavailable, VSM falls back to Medium and states so honestly in the report.
The tool is intended **only for lawful** software analysis, digital
forensics, OSINT and education.

### Roadmap

- [x] Network monitoring: IP addresses, ports, services, reverse DNS.
- [x] Sandbox process-tree monitoring.
- [x] Heuristic verdict and indicators of compromise (IOC).
- [x] Separation of the program footprint from OS background noise.
- [x] Real-time registry interception via `RegNotifyChangeKeyValue`.
- [x] Export of indicators into a portable `iocs.txt` file.
- [x] Windows Sandbox (`.wsb`) integration for hardware isolation (`-wsb` flag).
- [x] DNS monitoring (resolved names) via the DNS resolver cache — no administrator rights.
- [x] Indicator export to STIX 2.1 format (importable into MISP).

### License

Educational / research project. Use responsibly.

[⬆ Top](#virtual-software-machine-vsm) · [Перейти к **#RU** Русский](#ru)
