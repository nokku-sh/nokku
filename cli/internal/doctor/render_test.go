package doctor

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func testReport() Report {
	return Report{
		Fixes: []string{"made the config dir private"},
		Checks: []Check{
			{Section: "System", Name: "nk", Status: StatusInfo, Detail: "dev linux/amd64"},
			{Section: "System", Name: "TPM", Status: StatusOK},
			{Section: "SSH", Name: "~/.ssh/config", Status: StatusFail, Detail: "missing the Nokku include"},
			{Section: "SSH", Name: "identity", Status: StatusWarn, Detail: "none yet"},
		},
	}
}

func TestReportJSON(t *testing.T) {
	t.Parallel()
	b, err := json.MarshalIndent(testReport(), "", "  ")
	require.NoError(t, err)
	assert.JSONEq(t, `{
  "fixes": [
    "made the config dir private"
  ],
  "checks": [
    {
      "section": "System",
      "name": "nk",
      "status": "info",
      "detail": "dev linux/amd64"
    },
    {
      "section": "System",
      "name": "TPM",
      "status": "ok"
    },
    {
      "section": "SSH",
      "name": "~/.ssh/config",
      "status": "fail",
      "detail": "missing the Nokku include"
    },
    {
      "section": "SSH",
      "name": "identity",
      "status": "warn",
      "detail": "none yet"
    }
  ]
}`, string(b))
}

func TestPrintText(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	Print(&b, testReport())
	assert.Equal(t, `  ✔ made the config dir private

System
  ℹ nk             dev linux/amd64
  ✔ TPM          

SSH
  ✖ ~/.ssh/config  missing the Nokku include
  ⚠ identity       none yet

Result: 1 ok, 1 warn, 1 fail (run `+"`nk doctor --fix` or `nk login`"+`)
`, ansi.ReplaceAllString(b.String(), ""))
}
