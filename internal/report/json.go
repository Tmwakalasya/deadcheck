package report

import (
	"encoding/json"
	"io"

	"github.com/tuntufye/deadcheck/internal/model"
)

func WriteJSON(w io.Writer, result model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
