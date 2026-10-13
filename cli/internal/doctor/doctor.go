package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/cli/internal/enclave"
	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

type Check struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

type Report struct {
	Fixes  []string `json:"fixes,omitempty"`
	Checks []Check  `json:"checks"`
}

func (r *Report) add(section, name string, status Status, detail string) {
	r.Checks = append(r.Checks, Check{Section: section, Name: name, Status: status, Detail: detail})
}

// ExitCode returns 0 when healthy, 1 with warnings, and 2 on any failure.
func (r *Report) ExitCode() int {
	code := 0
	for _, c := range r.Checks {
		switch c.Status {
		case StatusFail:
			return 2
		case StatusWarn:
			code = 1
		case StatusOK, StatusInfo:
		}
	}
	return code
}

// Run never logs in. It only changes files when fix is set.
func Run(ctx context.Context, s *state.State, fix bool) Report {
	var r Report
	if fix {
		r.Fixes = repair(s)
	}
	checkSystem(ctx, &r)
	checkAccount(ctx, &r, s)
	checkSSH(&r, s)
	return r
}

func checkSystem(ctx context.Context, r *Report) {
	const sec = "System"
	r.add(sec, "nk", StatusInfo, buildinfo.Version+" "+runtime.GOOS+"/"+runtime.GOARCH)

	if out, err := exec.CommandContext(ctx, "ssh", "-V").CombinedOutput(); err != nil {
		r.add(sec, "ssh", StatusFail, "ssh not found, install OpenSSH")
	} else {
		r.add(sec, "ssh", StatusOK, strings.TrimSpace(string(out)))
	}

	switch err := tpm.Available(); {
	case err == nil:
		r.add(sec, "TPM", StatusOK, "available")
	case runtime.GOOS == "darwin":
		status, detail := enclaveStatus()
		r.add(sec, "Secure Enclave", status, detail)
	case errors.Is(err, os.ErrPermission):
		r.add(sec, "TPM", StatusWarn, "no access, run: sudo usermod -aG tss $USER, then log in again")
	default:
		r.add(sec, "TPM", StatusInfo, "not available, using a machine-wrapped key")
	}
}

func enclaveStatus() (Status, string) {
	switch {
	case enclave.Enabled():
		return StatusOK, "available"
	case enclave.Available():
		return StatusInfo, "available but experimental, set NK_SECURE_ENCLAVE=1 before nk login to use it"
	}
	return StatusInfo, "not available, using a machine-wrapped key"
}

func checkAccount(ctx context.Context, r *Report, s *state.State) {
	const sec = "Account"
	switch {
	case s.ServiceAccount != nil:
		r.add(sec, "signed in", StatusOK, "service account "+s.ServiceAccount.Name)
	case s.User != nil && s.SessionValid():
		r.add(sec, "signed in", StatusOK, s.User.Email)
	case s.User != nil:
		r.add(sec, "signed in", StatusWarn, "session expired, run nk login")
	default:
		r.add(sec, "signed in", StatusWarn, "not signed in, run nk login")
	}
	r.add(sec, "servers", StatusInfo, strconv.Itoa(len(s.Targets)))

	if reachable(ctx, s) {
		r.add(sec, "Nokku", StatusOK, s.APIURL)
	} else {
		r.add(sec, "Nokku", StatusWarn, "cannot reach "+s.APIURL+", ssh keeps working with cached access")
	}
}

// Diagnostic only, a plain HTTP request with a short timeout.
func reachable(ctx context.Context, s *state.State) bool {
	roots, err := trust.Pool([]byte(s.APICA))
	if err != nil {
		return false
	}
	httpc, err := dpopclient.NewHTTPClient(roots, 3*time.Second)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	u := strings.TrimRight(s.APIURL, "/") + "/auth/device/nonce"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func checkSSH(r *Report, s *state.State) {
	const sec = "SSH"
	if data, err := os.ReadFile(paths.SSHUserConfig()); err == nil && ssh.HasInclude(data) {
		r.add(sec, "~/.ssh/config", StatusOK, "includes the Nokku config")
	} else {
		r.add(sec, "~/.ssh/config", StatusFail, "missing the Nokku include, run nk doctor --fix")
	}

	switch method := tpm.IdentityMethod(paths.SSHSignerFile()); {
	case method == tpm.MethodTPM:
		r.add(sec, "identity", StatusOK, "TPM key, never leaves the chip")
	case method == tpm.MethodEnclave:
		r.add(sec, "identity", StatusOK, "Secure Enclave key, never leaves the chip")
	case method == tpm.MethodSoft && (tpm.Available() == nil || enclave.Enabled()):
		// A software key is never moved to hardware on its own.
		r.add(sec, "identity", StatusWarn,
			"software key although this machine can keep it in hardware, run nk logout and nk login to move it")
	case method == tpm.MethodSoft:
		r.add(sec, "identity", StatusOK, "machine-wrapped key, tied to this machine's ID")
	default:
		r.add(sec, "identity", StatusWarn, "none yet, run nk login")
	}

	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(paths.ConfigDir()); err == nil && fi.Mode().Perm() != 0o700 {
			r.add(sec, "permissions", StatusWarn,
				fmt.Sprintf("%s is %04o, run nk doctor --fix", paths.ConfigDir(), fi.Mode().Perm()))
		}
	}

	// One certificate per server, fetched on its first ssh. Only servers that have one get a line.
	certs := 0
	for _, t := range s.Targets {
		data, err := os.ReadFile(paths.SSHCertificate(t.ID))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		certs++
		cert, err := ssh.ParseCert(data)
		if err != nil {
			r.add(sec, t.Name, StatusFail, "unreadable certificate, run nk login")
			continue
		}
		_, before := ssh.CertWindow(cert)
		switch left := time.Until(before); {
		case left <= 0:
			r.add(sec, t.Name, StatusWarn, "certificate expired, renewed on the next ssh or nk login")
		default:
			r.add(sec, t.Name, StatusOK, "certificate valid for "+ui.HumanizeDuration(left))
		}
	}
	if certs == 0 {
		r.add(sec, "certificates", StatusInfo, "none yet, fetched on the first ssh to a server")
	}
}

// repair regenerates what nk owns and reports only what it changed.
func repair(s *state.State) []string {
	var fixed []string
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(paths.ConfigDir()); err == nil && fi.Mode().Perm() != 0o700 &&
			os.Chmod(paths.ConfigDir(), 0o700) == nil { //nolint:gosec // a directory needs x
			fixed = append(fixed, "made "+paths.ConfigDir()+" private")
		}
	}

	before, _ := os.ReadFile(paths.SSHUserConfig())
	if err := ssh.WriteConfigs(s); err != nil {
		fixed = append(fixed, "could not regenerate the ssh config: "+err.Error())
	} else if after, _ := os.ReadFile(paths.SSHUserConfig()); string(before) != string(after) {
		fixed = append(fixed, "added the Nokku include to ~/.ssh/config")
	}

	// Without a synced snapshot the target list is empty for unrelated reasons, so never prune from it.
	if s.HasCachedData() {
		certs, _ := paths.SSHCertificates()
		if err := ssh.CleanupCerts(s.Targets); err == nil {
			if left, _ := paths.SSHCertificates(); len(left) < len(certs) {
				fixed = append(fixed, fmt.Sprintf("removed %d stale certificates", len(certs)-len(left)))
			}
		}
	}
	return fixed
}
