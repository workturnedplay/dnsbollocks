//go:build windows
// +build windows

package dnsbollocks

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestQueryFilterHandler_FilterSurvivesWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := queryFilterHandler{Handler: slog.NewJSONHandler(&buf, nil)}
	log := slog.New(h).With(slog.Int("pid", 1))

	log.Info("not a query")
	log.Info("a query", slog.String("category", "query"))

	out := buf.String()
	if strings.Contains(out, "not a query") {
		t.Errorf("non-query line leaked through the filter after .With(): %s", out)
	}
	if !strings.Contains(out, "a query") {
		t.Errorf("query line was dropped: %s", out)
	}
}