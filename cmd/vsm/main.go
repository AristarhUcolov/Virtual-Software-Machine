//go:build windows

// Command vsm is the graphical Virtual Software Machine: a user-mode sandbox
// for digital forensics and OSINT. Build it with -ldflags "-H=windowsgui" to
// suppress the console window.
//
// Команда vsm — графическая Virtual Software Machine: user-mode песочница для
// цифровой криминалистики и OSINT.
package main

import "vsm/internal/gui"

func main() {
	gui.Run()
}
