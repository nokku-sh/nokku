package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/tpm"
	"github.com/nokku-sh/nokku/internal/trust"
)

const (
	statusOK   Status = "ok"
	statusWarn Status = "warn"
	statusFail Status = "fail"
	statusInfo Status = "info"
)

type Status string

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

func (r *Report) ExitCode() int {
	code := 0
	for _, c := range r.Checks {
		switch c.Status {
		case statusFail:
			return 2
		case statusWarn:
			code = 1
		case statusOK, statusInfo:
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
	r.add(sec, "nk", statusInfo, buildinfo.Version+" "+runtime.GOOS+"/"+runtime.GOARCH)

	if out, err := exec.CommandContext(ctx, "ssh", "-V").CombinedOutput(); err != nil {
		r.add(sec, "ssh", statusFail, "ssh not found, install OpenSSH")
	} else {
		r.add(sec, "ssh", statusOK, strings.TrimSpace(string(out)))
	}

	switch err := tpm.Available(); {
	case err == nil:
		r.add(sec, "TPM", statusOK, "available")
	case errors.Is(err, os.ErrPermission):
		r.add(sec, "TPM", statusWarn, "no access, run: sudo usermod -aG tss $USER, then log in again")
	default:
		r.add(sec, "TPM", statusInfo, "not available, using a machine-wrapped key")
	}
}

func checkAccount(ctx context.Context, r *Report, s *state.State) {
	const sec = "Account"
	switch {
	case s.CIJob() && !s.SessionValid():
		r.add(sec, "signed in", statusWarn, "CI session ended, run nk login --ci")
	case s.ServiceAccount != nil:
		r.add(sec, "signed in", statusOK, "service account "+s.ServiceAccount.Name)
	case s.User != nil && s.SessionValid():
		r.add(sec, "signed in", statusOK, s.User.Email)
	case s.User != nil:
		r.add(sec, "signed in", statusWarn, "session expired, run nk login")
	default:
		r.add(sec, "signed in", statusWarn, "not signed in, run nk login")
	}
	r.add(sec, "servers", statusInfo, strconv.Itoa(len(s.Targets)))

	switch err := probe(ctx, s); {
	case err == nil:
		r.add(sec, "Nokku", statusOK, s.APIURL)
	case errors.Is(err, dpopclient.ErrAPIURLMismatch):
		r.add(sec, "Nokku", statusFail, err.Error())
	default:
		r.add(sec, "Nokku", statusWarn, "cannot reach "+s.APIURL+", ssh keeps working with cached access")
	}
}

func probe(ctx context.Context, s *state.State) error {
	roots, err := trust.Pool([]byte(s.APICA))
	if err != nil {
		return err
	}
	httpc, err := dpopclient.NewHTTPClient(roots, 3*time.Second)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = dpopclient.FetchNonce(ctx, httpc, s.APIURL)
	return err
}

func checkSSH(r *Report, s *state.State) {
	const sec = "SSH"
	if data, err := os.ReadFile(paths.SSHUserConfig()); err == nil && ssh.HasInclude(data) {
		r.add(sec, "~/.ssh/config", statusOK, "includes the Nokku config")
	} else {
		r.add(sec, "~/.ssh/config", statusFail, "missing the Nokku include, run nk doctor --fix")
	}

	switch method := tpm.IdentityMethod(paths.SSHSignerFile()); {
	case method == tpm.MethodTPM:
		r.add(sec, "identity", statusOK, "TPM key, never leaves the chip")
	case method == tpm.MethodSoft && tpm.Available() == nil:
		// A software key is never moved to hardware on its own.
		r.add(sec, "identity", statusWarn,
			"software key although this machine can keep it in hardware, run nk logout and nk login to move it")
	case method == tpm.MethodSoft:
		r.add(sec, "identity", statusOK, "machine-wrapped key, tied to this machine's ID")
	default:
		r.add(sec, "identity", statusWarn, "none yet, run nk login")
	}

	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(paths.ConfigDir()); err == nil && fi.Mode().Perm() != 0o700 {
			r.add(sec, "permissions", statusWarn,
				fmt.Sprintf("%s is %04o, run nk doctor --fix", paths.ConfigDir(), fi.Mode().Perm()))
		}
	}

	// Certificates come with the first ssh, only servers with one get a line.
	certs := 0
	for _, t := range s.Targets {
		data, err := os.ReadFile(paths.SSHCertificate(t.ID))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		certs++
		cert, err := ssh.ParseCert(data)
		if err != nil {
			r.add(sec, t.Name, statusFail, "unreadable certificate, run nk login")
			continue
		}
		_, before := ssh.CertWindow(cert)
		switch left := time.Until(before); {
		case left <= 0:
			r.add(sec, t.Name, statusWarn, "certificate expired, renewed on the next ssh or nk login")
		default:
			r.add(sec, t.Name, statusOK, "certificate valid for "+ui.HumanizeDuration(left))
		}
	}
	if certs == 0 {
		r.add(sec, "certificates", statusInfo, "none yet, fetched on the first ssh to a server")
	}
}

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

	// Without a synced snapshot the target list means nothing, so never prune.
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

func (r *Report) add(section, name string, status Status, detail string) {
	r.Checks = append(r.Checks, Check{Section: section, Name: name, Status: status, Detail: detail})
}
