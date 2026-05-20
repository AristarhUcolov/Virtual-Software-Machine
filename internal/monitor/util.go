package monitor

import "os"

// filepathStat reports whether path currently exists and is a directory.
// filepathStat сообщает, существует ли путь и является ли он каталогом.
func filepathStat(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}
