package parser

import (
	"regexp"
	"strings"
)

var (
	npmUnsupportedPrefixes = []string{
		"workspace:",
		"file:",
		"link:",
		"git+",
		"http://",
		"https://",
		"git://",
		"github:",
	}
	pythonUnsupportedPrefixes = []string{
		"-r",
		"-c",
		"-e",
		"git+",
		"http://",
		"https://",
		"svn+",
		"hg+",
		"bzr+",
	}
	pep503Pattern = regexp.MustCompile(`[-_.]+`)
)

func normalizeNPMConstraint(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	lower := strings.ToLower(spec)
	for _, prefix := range npmUnsupportedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return "", false
		}
	}
	if strings.Contains(spec, "||") {
		return "", false
	}

	parts := strings.Fields(strings.ReplaceAll(spec, ",", " "))
	if len(parts) == 0 {
		return "", false
	}

	var minimum string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch {
		case part == "*" || strings.EqualFold(part, "latest"):
			return "", false
		case strings.HasPrefix(part, "^"),
			strings.HasPrefix(part, "~"),
			strings.HasPrefix(part, ">="),
			strings.HasPrefix(part, "="):
			v := strings.TrimLeft(part, "^~=>")
			if coerced, ok := coerceSemver(v); ok {
				if minimum == "" {
					minimum = coerced
				}
				continue
			}
			return "", false
		case strings.HasPrefix(part, ">"),
			strings.HasPrefix(part, "<"),
			strings.HasPrefix(part, "<="):
			if strings.HasPrefix(part, ">") && !strings.HasPrefix(part, ">=") {
				return "", false
			}
			if strings.HasPrefix(part, "<") {
				continue
			}
		default:
			if coerced, ok := coerceSemver(part); ok {
				if minimum == "" {
					minimum = coerced
				}
				continue
			}
			return "", false
		}
	}

	return minimum, minimum != ""
}

func normalizePythonName(name string) string {
	return pep503Pattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

func normalizePythonConstraint(spec string) (string, bool) {
	if spec == "" {
		return "", false
	}

	parts := strings.Split(spec, ",")
	var minimum string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "=="):
			return strings.TrimSpace(strings.TrimPrefix(part, "==")), true
		case strings.HasPrefix(part, "~="),
			strings.HasPrefix(part, ">="):
			v := strings.TrimLeft(part, "~=>")
			if v == "" {
				return "", false
			}
			if minimum == "" {
				minimum = v
			}
		case strings.HasPrefix(part, ">"),
			strings.HasPrefix(part, "<"),
			strings.HasPrefix(part, "<="):
			if strings.HasPrefix(part, ">") && !strings.HasPrefix(part, ">=") {
				return "", false
			}
		case part == "":
			continue
		default:
			return "", false
		}
	}

	return minimum, minimum != ""
}

func unsupportedPrefix(line string, prefixes []string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func coerceSemver(v string) (string, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" {
		return "", false
	}
	if strings.ContainsAny(v, "*xX") {
		v = strings.NewReplacer("*", "0", "x", "0", "X", "0").Replace(v)
	}
	parts := strings.Split(v, "-")
	core := strings.Split(parts[0], ".")
	switch len(core) {
	case 1:
		core = append(core, "0", "0")
	case 2:
		core = append(core, "0")
	case 3:
	default:
		return "", false
	}
	for _, segment := range core {
		if segment == "" || !isDigits(segment) {
			return "", false
		}
	}

	value := strings.Join(core, ".")
	if len(parts) > 1 {
		value += "-" + strings.Join(parts[1:], "-")
	}
	return value, true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
