package base

import "time"

type DirectoryServiceProcess struct {
	AllowedFunctions []string
	StartingTime     time.Time
	DatabaseId       int64
}

func (u *DirectoryServiceProcess) IsAllowedFunction(names ...string) bool {
	for i := range names {
		found := false
		for x := range u.AllowedFunctions {
			if names[i] == u.AllowedFunctions[x] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
