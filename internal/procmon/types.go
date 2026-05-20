// Package procmon tracks every process that lives inside the sandbox Job
// Object during a run, so the report can show exactly what the analysed file
// launched — its child processes, helpers and spawned tools.
//
// Пакет procmon отслеживает каждый процесс, работавший внутри Job Object
// песочницы за время сессии, чтобы в отчёте было видно, что именно запустил
// анализируемый файл — его дочерние процессы и вспомогательные инструменты.
package procmon

import "time"

// Process is one process observed inside the sandbox process tree.
// Process — один процесс, замеченный в дереве процессов песочницы.
type Process struct {
	PID         int       `json:"pid"`
	Image       string    `json:"image"`        // full path to the executable
	CommandLine string    `json:"command_line"` // full command line, if readable
	IsRoot      bool      `json:"is_root"`      // the analysed target itself
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}
