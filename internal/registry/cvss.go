package registry

import (
	"math"
	"strconv"
	"strings"
)

func parseOSVCVSS(items []osvSeverity) *float64 {
	for _, item := range items {
		score := strings.TrimSpace(item.Score)
		if score == "" {
			continue
		}
		if value, err := strconv.ParseFloat(score, 64); err == nil {
			return &value
		}
		if strings.HasPrefix(score, "CVSS:3.") {
			if value, ok := parseCVSSv3Vector(score); ok {
				return &value
			}
		}
	}
	return nil
}

func parseCVSSv3Vector(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 8 {
		return 0, false
	}
	metrics := make(map[string]string, len(parts))
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	scope := metrics["S"]
	av, ok := scoreByKey(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := scoreByKey(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	ui, ok := scoreByKey(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	c, ok := scoreByKey(metrics["C"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}
	i, ok := scoreByKey(metrics["I"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}
	a, ok := scoreByKey(metrics["A"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}
	pr := cvssPR(metrics["PR"], scope)
	if pr == 0 && metrics["PR"] != "N" {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	impact := 6.42 * iss
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, true
	}

	base := impact + exploitability
	if scope == "C" {
		base *= 1.08
	}
	if base > 10 {
		base = 10
	}
	return math.Ceil((base-1e-9)*10) / 10, true
}

func scoreByKey(key string, values map[string]float64) (float64, bool) {
	value, ok := values[key]
	return value, ok
}

func cvssPR(value, scope string) float64 {
	switch scope {
	case "C":
		switch value {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.5
		}
	default:
		switch value {
		case "N":
			return 0.85
		case "L":
			return 0.62
		case "H":
			return 0.27
		}
	}
	return 0
}
