package version

import (
	"path"
	"runtime/debug"
	"strconv"
	"time"
)

const unknown = "unknown"

// Build information
//
//nolint:gochecknoglobals
var (
	name      = unknown
	version   = unknown
	revision  = unknown
	modified  = unknown
	buildTime = unknown
)

// Name returns the name of the application.
func Name() string {
	return name
}

// Version returns the version of the application.
func Version() string {
	return version
}

// Revision returns the revision of the application.
func Revision() string {
	return revision
}

// Modified returns the modification status (if the source tree was modified) of the application.
func Modified() string {
	return modified
}

// BuildTime returns the build time of the application.
func BuildTime() string {
	return buildTime
}

func init() { //nolint:gochecknoinits,gocognit
	// Handle case when info was provided at build time
	if name != unknown && version != unknown && revision != unknown && modified != unknown && buildTime != unknown {
		return
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	if info.Main.Path != "" && name == unknown {
		name = path.Base(info.Main.Path)
	}

	if info.Main.Version != "" && version == unknown {
		version = info.Main.Version
	}

	for _, setting := range info.Settings {
		if setting.Value == "" {
			continue
		}

		switch setting.Key {
		case "vcs.revision":
			if revision != unknown {
				continue
			}
			revision = setting.Value
		case "vcs.modified":
			if modified != unknown {
				continue
			}
			modified = setting.Value
			if isModified, err := strconv.ParseBool(modified); err == nil {
				if isModified {
					modified = "modified"
				} else {
					modified = "not modified"
				}
			}
		case "vcs.time":
			if buildTime != unknown {
				continue
			}
			buildTime = setting.Value
			if t, err := time.Parse(time.RFC3339, buildTime); err == nil {
				buildTime = t.UTC().Format("2006-01-02 15:04:05 MST")
			}
		default:
			continue
		}
	}
}
