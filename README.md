# Virtual Software Machine (VSM)

**RU** — User-mode песочница для **цифровой криминалистики и OSINT**. VSM
запускает программу (`.exe` и др.) в изолированном пространстве, перехватывает
её обращения к диску и реестру и формирует подробный отчёт: *что, где и как*
файл сохраняет, изменяет и добавляет.

**EN** — A user-mode sandbox for **digital forensics & OSINT**. VSM runs a
program (`.exe` and others) in an isolated space, captures its disk and
registry activity and produces a detailed report of *what, where and how* the
file saves, modifies and adds.

> Интерфейс и отчёты — на **двух языках**: русском и английском.
> The interface and reports are **bilingual**: Russian and English.

---

## Что делает VSM / What VSM does

| Этап / Stage | Описание / Description |
|---|---|
| 🧊 Снимок ДО / Pre-snapshot | Скан файловой системы и реестра до запуска. |
| 🚀 Изолированный запуск / Isolated run | Запуск в **Job Object** + **Low Integrity** токен + перенаправление `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%` в папку-песочницу. |
| 👁 Наблюдение / Live watch | Хронология файловых событий в реальном времени. |
| 🌐 Сеть / Network | IP-адреса подключений дерева процессов (TCP/UDP), порт, состояние, сервис и обратный DNS. |
| 🧬 Процессы / Processes | Все процессы дерева песочницы: что именно запустил анализируемый файл (PID, путь, время жизни). |
| 🧊 Снимок ПОСЛЕ / Post-snapshot | Повторный скан и вычисление разницы. |
| ⚖️ Вердикт / Verdict | Эвристический анализ: вердикт (Чисто / Подозрительно / Опасно) и список индикаторов компрометации (IOC). |
| 📄 Отчёт / Report | `report.html` (наглядный) и `report.json` (машиночитаемый) с SHA-256 каждого нового файла. |

Каждая запись, которую программа считала записью в `%APPDATA%` и т.п.,
показывается в отчёте с **реальным предполагаемым назначением** — видно, *куда*
программа намеревалась сохранить файл.

## Как это устроено / Architecture

```
cmd/vsm        — графическое приложение (Fyne)            / GUI app
cmd/vsm-cli    — консольное приложение (без CGO)          / CLI app
internal/
  i18n         — двуязычный каталог сообщений             / bilingual catalog
  config       — корни наблюдения, ветки реестра, лимиты  / watch roots, limits
  snapshot     — снимки и diff ФС и реестра               / FS & registry diff
  monitor      — наблюдатель ФС в реальном времени        / real-time watcher
  netmon       — мониторинг сетевых подключений (IP)      / network connections
  procmon      — мониторинг процессов дерева песочницы    / process tree
  analyze      — эвристики IOC и итоговый вердикт          / IOC heuristics & verdict
  sandbox      — изоляция запуска (Job Object, токен)     / process containment
  report       — генерация HTML/JSON отчёта               / report generation
```

## Сборка / Build

Требуется **Go 1.26+**.

```powershell
# Собрать всё (для GUI нужен компилятор C — mingw-w64):
.\build.ps1

# Только консольная версия (компилятор C не нужен):
.\build.ps1 -CliOnly
```

GUI на Fyne использует CGO. Если нет компилятора C — установите его:

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT   # пример mingw-w64
```

## Использование / Usage

**GUI:** запустите `bin\vsm.exe`, выберите файл, нажмите «Запустить в песочнице».

**CLI:**

```powershell
bin\vsm-cli.exe -lang ru -target "C:\path\to\sample.exe" -timeout 60
bin\vsm-cli.exe -lang en -target "C:\path\to\sample.exe" -low=false
```

Отчёты сохраняются в `%LOCALAPPDATA%\VSM\workspace\session-<дата>\`.

## Безопасность и ограничения / Security & limitations

⚠️ **Важно / Important**

- VSM — это **user-mode** инструмент. Он снижает риск (Low Integrity, Job
  Object, перенаправление записи), но **не заменяет** полную изоляцию.
  Настоящий аналог Sandboxie использует kernel-драйвер; на чистом Go это
  невозможно.
- Для действительно опасных образцов запускайте VSM **внутри виртуальной
  машины** (Hyper-V / VMware) или в Windows Sandbox.
- Если запуск с Low Integrity недоступен, VSM автоматически переходит в режим
  Medium и честно указывает это в отчёте (поле «Режим целостности»).
- Инструмент предназначен **только для законного** анализа ПО, цифровой
  криминалистики, OSINT и обучения.

— VSM is a **user-mode** tool. It reduces risk but does **not** replace full
isolation. Analyse genuinely dangerous samples inside a VM or Windows Sandbox.

## Дорожная карта / Roadmap

- [x] Сетевой мониторинг: IP-адреса подключений, порты, сервисы, обратный DNS.
- [x] Мониторинг процессов дерева песочницы (что запустил анализируемый файл).
- [x] Эвристический вердикт и индикаторы компрометации (IOC).
- [ ] Интеграция с Windows Sandbox (`.wsb`) для аппаратной изоляции.
- [ ] ETW-мониторинг процессов и DNS-запросов (имена доменов до подключения).
- [ ] Перехват реестра через `RegNotifyChangeKeyValue` в реальном времени.
- [ ] Фильтрация фонового «шума» ОС в diff-отчёте.
- [ ] Экспорт отчёта в формат STIX / MISP для обмена индикаторами.

## Лицензия / License

Учебно-исследовательский проект. Используйте ответственно.
Educational / research project. Use responsibly.
