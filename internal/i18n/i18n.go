// Package i18n provides a minimal bilingual (Russian / English) message
// catalog for the Virtual Software Machine.
//
// Пакет i18n предоставляет минимальный двуязычный (русский / английский)
// каталог сообщений для Virtual Software Machine.
package i18n

import "fmt"

// Lang is a supported interface language. // Lang — поддерживаемый язык интерфейса.
type Lang string

const (
	RU Lang = "ru"
	EN Lang = "en"
)

// Langs lists every supported language. // Langs перечисляет все поддерживаемые языки.
var Langs = []Lang{RU, EN}

// Normalize maps an arbitrary string to a supported language, defaulting to RU.
func Normalize(s string) Lang {
	switch s {
	case "en", "EN", "english", "English":
		return EN
	default:
		return RU
	}
}

// catalog maps a message key to its translations. // catalog: ключ -> переводы.
var catalog = map[string]map[Lang]string{
	"app.title":     {RU: "Virtual Software Machine — Цифровая криминалистика и OSINT", EN: "Virtual Software Machine — Digital Forensics & OSINT"},
	"app.subtitle":  {RU: "Безопасный запуск ПО с полным отчётом об изменениях", EN: "Safe software execution with a full change report"},
	"lang.label":    {RU: "Язык интерфейса", EN: "Interface language"},
	"field.target":  {RU: "Файл для анализа (.exe и др.)", EN: "File to analyse (.exe and others)"},
	"field.browse":  {RU: "Обзор…", EN: "Browse…"},
	"field.args":    {RU: "Аргументы запуска", EN: "Launch arguments"},
	"field.timeout": {RU: "Таймаут, сек", EN: "Timeout, sec"},
	"field.lowint":  {RU: "Низкий уровень целостности (Low Integrity)", EN: "Low integrity level"},
	"field.run":     {RU: "Запустить в песочнице", EN: "Run in sandbox"},
	"field.openrep": {RU: "Открыть отчёт", EN: "Open report"},
	"field.opendir": {RU: "Открыть папку сессии", EN: "Open session folder"},

	"status.idle":     {RU: "Готов к запуску", EN: "Ready"},
	"status.prepare":  {RU: "Подготовка песочницы…", EN: "Preparing sandbox…"},
	"status.snapbe":   {RU: "Снимок системы ДО запуска…", EN: "Taking pre-run snapshot…"},
	"status.launch":   {RU: "Запуск процесса в изоляции…", EN: "Launching isolated process…"},
	"status.running":  {RU: "Процесс выполняется…", EN: "Process is running…"},
	"status.snapaf":   {RU: "Снимок системы ПОСЛЕ запуска…", EN: "Taking post-run snapshot…"},
	"status.diff":     {RU: "Сравнение изменений…", EN: "Comparing changes…"},
	"status.report":   {RU: "Формирование отчёта…", EN: "Generating report…"},
	"status.done":     {RU: "Готово. Отчёт сохранён.", EN: "Done. Report saved."},
	"status.error":    {RU: "Ошибка", EN: "Error"},

	"section.summary":   {RU: "Сводка", EN: "Summary"},
	"section.process":   {RU: "Процесс", EN: "Process"},
	"section.files":     {RU: "Изменения файловой системы", EN: "File system changes"},
	"section.footprint": {RU: "След программы — что и куда она записала", EN: "Program footprint — what it wrote and where"},
	"section.syschanges": {RU: "Прочие изменения системы (возможен фоновый шум ОС)", EN: "Other system changes (may include OS background noise)"},
	"note.footprint":    {RU: "Эти записи перенаправлены в песочницу — их сделала сама анализируемая программа.", EN: "These writes were redirected into the sandbox — they were made by the analysed program itself."},
	"note.syschanges":   {RU: "Изменения вне песочницы. Снимок «до/после» фиксирует и постороннюю активность ОС, поэтому здесь возможен шум.", EN: "Changes outside the sandbox. The before/after snapshot also captures unrelated OS activity, so noise is possible here."},
	"section.registry":  {RU: "Изменения реестра Windows", EN: "Windows registry changes"},
	"section.timeline":  {RU: "Хронология событий", EN: "Event timeline"},
	"section.redirects": {RU: "Карта виртуализации (перенаправления)", EN: "Virtualization map (redirections)"},

	"label.added":     {RU: "Добавлено", EN: "Added"},
	"label.modified":  {RU: "Изменено", EN: "Modified"},
	"label.deleted":   {RU: "Удалено", EN: "Deleted"},
	"label.pid":       {RU: "PID процесса", EN: "Process PID"},
	"label.exitcode":  {RU: "Код возврата", EN: "Exit code"},
	"label.duration":  {RU: "Длительность", EN: "Duration"},
	"label.integrity": {RU: "Режим целостности", EN: "Integrity mode"},
	"label.timedout":  {RU: "Прерван по таймауту", EN: "Terminated by timeout"},
	"label.yes":       {RU: "Да", EN: "Yes"},
	"label.no":        {RU: "Нет", EN: "No"},
	"label.target":    {RU: "Анализируемый файл", EN: "Analysed file"},
	"label.sha256":    {RU: "SHA-256", EN: "SHA-256"},
	"label.size":      {RU: "Размер", EN: "Size"},
	"label.path":      {RU: "Путь", EN: "Path"},
	"label.realpath":  {RU: "Реальное назначение", EN: "Intended destination"},
	"label.envvar":    {RU: "Переменная", EN: "Variable"},
	"label.session":   {RU: "Папка сессии", EN: "Session folder"},
	"label.generated": {RU: "Отчёт создан", EN: "Report generated"},
	"label.regkey":    {RU: "Ключ", EN: "Key"},
	"label.regvalue":  {RU: "Значение", EN: "Value"},
	"label.regtype":   {RU: "Тип", EN: "Type"},
	"label.regdata":   {RU: "Данные", EN: "Data"},
	"label.time":      {RU: "Время", EN: "Time"},
	"label.event":     {RU: "Событие", EN: "Event"},

	"section.network": {RU: "Сетевые подключения (IP-адреса)", EN: "Network connections (IP addresses)"},
	"label.proto":     {RU: "Протокол", EN: "Protocol"},
	"label.local":     {RU: "Локальный адрес", EN: "Local address"},
	"label.remote":    {RU: "Удалённый адрес", EN: "Remote address"},
	"label.state":     {RU: "Состояние", EN: "State"},
	"label.host":      {RU: "Хост (обратный DNS)", EN: "Host (reverse DNS)"},
	"label.service":   {RU: "Сервис", EN: "Service"},
	"label.firstseen": {RU: "Замечен", EN: "First seen"},

	"section.processes": {RU: "Процессы дерева песочницы", EN: "Sandbox process tree"},
	"label.image":       {RU: "Образ (путь к файлу)", EN: "Image (file path)"},
	"label.lastseen":    {RU: "Активен до", EN: "Last seen"},
	"label.role":        {RU: "Роль", EN: "Role"},
	"label.roottarget":  {RU: "Анализируемая цель", EN: "Analysed target"},
	"label.child":       {RU: "Порождённый процесс", EN: "Spawned process"},

	"section.verdict": {RU: "Вердикт и индикаторы компрометации (IOC)", EN: "Verdict & indicators of compromise (IOC)"},
	"label.verdict":   {RU: "Вердикт", EN: "Verdict"},
	"label.score":     {RU: "Уровень риска", EN: "Risk score"},
	"label.severity":  {RU: "Важность", EN: "Severity"},
	"label.indicator": {RU: "Индикатор", EN: "Indicator"},
	"label.detail":    {RU: "Детали", EN: "Details"},
	"verdict.clean":   {RU: "Чисто — явных угроз не обнаружено", EN: "Clean — no clear threats detected"},
	"verdict.suspicious": {RU: "Подозрительно — требуется внимание аналитика", EN: "Suspicious — analyst attention required"},
	"verdict.dangerous":  {RU: "Опасно — обнаружены признаки вредоносного поведения", EN: "Dangerous — signs of malicious behaviour detected"},
	"sev.high":   {RU: "Высокая", EN: "High"},
	"sev.medium": {RU: "Средняя", EN: "Medium"},
	"sev.low":    {RU: "Низкая", EN: "Low"},
	"sev.info":   {RU: "Инфо", EN: "Info"},
	"ioc.run":      {RU: "Закрепление в автозагрузке через реестр", EN: "Persistence via registry autorun"},
	"ioc.startup":  {RU: "Закрепление через папку «Автозагрузка»", EN: "Persistence via the Startup folder"},
	"ioc.dropped":  {RU: "Созданы исполняемые файлы / скрипты", EN: "Executable files / scripts created"},
	"ioc.sysdir":   {RU: "Изменены системные каталоги", EN: "System directories modified"},
	"ioc.network":  {RU: "Исходящие подключения к внешним адресам", EN: "Outbound connections to external addresses"},
	"ioc.lolbin":   {RU: "Запуск системных интерпретаторов (LOLBin)", EN: "System interpreters launched (LOLBin)"},
	"ioc.cmdline":  {RU: "Подозрительная командная строка процесса", EN: "Suspicious process command line"},
	"ioc.children": {RU: "Порождены дочерние процессы", EN: "Child processes spawned"},
	"ioc.timeout":  {RU: "Процесс не завершился самостоятельно", EN: "The process did not exit on its own"},
	"ioc.timeout.detail": {RU: "Прерван по таймауту — возможно, ожидал ввод, завис или работал в фоне.", EN: "Terminated by timeout — it may have waited for input, hung, or run in the background."},
	"msg.verdict":  {RU: "ВЕРДИКТ", EN: "VERDICT"},
	"msg.ioccount": {RU: "Индикаторов компрометации: %d", EN: "Indicators of compromise: %d"},

	"msg.nochanges":  {RU: "Изменений не обнаружено.", EN: "No changes detected."},
	"msg.fscount":    {RU: "Изменений в файловой системе: %d", EN: "File system changes: %d"},
	"msg.footprintcount": {RU: "След программы — записей в песочнице: %d", EN: "Program footprint — writes in sandbox: %d"},
	"msg.syscount":   {RU: "Прочих изменений системы: %d", EN: "Other system changes: %d"},
	"msg.regcount":   {RU: "Изменений в реестре: %d", EN: "Registry changes: %d"},
	"msg.evcount":    {RU: "Событий в хронологии: %d", EN: "Timeline events: %d"},
	"msg.netcount":   {RU: "Сетевых подключений: %d", EN: "Network connections: %d"},
	"msg.proccount":  {RU: "Процессов в песочнице: %d", EN: "Processes in sandbox: %d"},
	"msg.notarget":   {RU: "Не выбран файл для анализа.", EN: "No file selected for analysis."},
	"msg.nofile":     {RU: "Файл не найден: %s", EN: "File not found: %s"},
	"msg.contained":  {RU: "Запись перенаправлена в песочницу (приложение считало, что пишет сюда: %s)", EN: "Write redirected into the sandbox (the app believed it was writing to: %s)"},

	"disclaimer": {
		RU: "Инструмент предназначен для законного анализа ПО, цифровой криминалистики и OSINT. " +
			"User-mode песочница снижает риск, но не заменяет полноценную изоляцию (ВМ/Hyper-V). " +
			"Анализируйте подозрительные файлы на изолированной машине.",
		EN: "This tool is intended for lawful software analysis, digital forensics and OSINT. " +
			"The user-mode sandbox reduces risk but does not replace full isolation (VM/Hyper-V). " +
			"Analyse suspicious files on an isolated machine.",
	},
}

// T returns the translation for key in lang, formatting any args.
// T возвращает перевод ключа key на языке lang с подстановкой args.
func T(lang Lang, key string, args ...any) string {
	m, ok := catalog[key]
	if !ok {
		return key
	}
	s, ok := m[lang]
	if !ok || s == "" {
		s = m[EN]
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}
