// Package netmon observes the network endpoints used by the sandboxed process
// tree: it polls the Windows TCP/UDP connection tables, keeps only the rows
// owned by processes inside our Job Object, and enriches each remote address
// with a reverse-DNS host name and a well-known service name.
//
// Пакет netmon наблюдает за сетевыми точками, которые использует дерево
// процессов в песочнице: опрашивает таблицы TCP/UDP-соединений Windows,
// оставляет только строки процессов из нашего Job Object и дополняет каждый
// удалённый адрес обратным DNS-именем и названием известного сервиса.
package netmon

import "time"

// Conn is one observed network endpoint used by the sandboxed process tree.
// Conn — одна наблюдённая сетевая точка дерева процессов песочницы.
type Conn struct {
	Proto      string    `json:"proto"`       // "TCP" / "UDP"
	PID        int       `json:"pid"`         // owning process id
	LocalAddr  string    `json:"local_addr"`  // local IP
	LocalPort  uint16    `json:"local_port"`  // local port
	RemoteAddr string    `json:"remote_addr"` // remote IP ("" for UDP sockets)
	RemotePort uint16    `json:"remote_port"` // remote port
	State      string    `json:"state"`       // TCP state, or "—" for UDP
	Host       string    `json:"host"`        // reverse-DNS name of RemoteAddr
	Service    string    `json:"service"`     // well-known service for RemotePort
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}
