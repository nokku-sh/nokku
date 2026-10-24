package client

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/smallstep/truststore"
	"golang.org/x/term"

	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/cli/internal/ui"
	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/trust"
)

// pinServer keeps the CA that --pin names, unless it is kept already.
func (c *Client) pinServer(ctx context.Context) error {
	pin := c.State.Pin
	if pin == "" || keeps(c.State.APICA, pin) {
		return nil
	}
	return c.keepCA(ctx, pin)
}

func keeps(ca, pin string) bool {
	want, err := trust.ParsePin(pin)
	if err != nil {
		return false
	}
	certs, err := trust.ParseBundle([]byte(ca))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(certs, func(cert *x509.Certificate) bool { return trust.Pin(cert) == want })
}

// Asks the way ssh asks about a host key. cause is the verification that failed.
func (c *Client) confirmServer(ctx context.Context, interactive bool, cause error) error {
	api := c.State.APIURL
	// A server this machine trusted before is never asked about again, like a changed host key in ssh.
	if c.State.APICA != "" || c.State.SessionToken != "" {
		return fmt.Errorf("the certificate of %s no longer comes from a CA this machine trusts, the connection "+
			"may be intercepted. If the CA really changed, run nk login --pin with the pin from the Nokku web app: %w",
			api, cause)
	}
	if !interactive || !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this machine does not trust the certificate of %s. Run nk login --pin with the pin "+
			"from the Nokku web app, it is under Profile, Security. Or pass --ca-file: %w", api, cause)
	}
	certs, err := trust.Advertised(ctx, api)
	if errors.Is(err, trust.ErrNoCA) {
		return fmt.Errorf("this machine does not trust the certificate of %s and the server names no CA. "+
			"Pass --ca-file with the CA of your company: %w", api, cause)
	}
	if err != nil {
		return err
	}

	// The web app shows the pin of the first CA. Only that one is shown and kept, so the pin compared is the pin kept.
	pin := trust.Pin(certs[0])
	fmt.Fprintf(os.Stderr, "\nThe certificate of %s comes from a CA this machine does not know.\n\n", api)
	// The name is not verified yet.
	fmt.Fprintf(os.Stderr, "  %s\n  %s\n\n", ui.PlainLine(certs[0].Subject.CommonName), ui.Bold(pin))
	fmt.Fprintln(os.Stderr, "Compare the pin with the one in the Nokku web app, under Profile, Security or Settings.")
	if !ask("Trust this CA for "+api+"?", false) {
		return errors.New("the server is not trusted, nothing was sent to it")
	}
	return c.keepCA(ctx, pin)
}

// keepCA checks the advertised CA against pin, stores it, and reconnects with it.
func (c *Client) keepCA(ctx context.Context, pin string) error {
	api := c.State.APIURL
	ca, err := trust.Bootstrap(ctx, api, pin)
	if err != nil {
		return err
	}
	c.State.APICA = string(ca)
	if err = c.State.Save(); err != nil {
		return err
	}
	if err = c.dial(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s Trusting the CA of %s\n", ui.Green("✔"), api)
	if !systemTrusts(ctx, api) && offerInstall(api, ca) {
		c.State.APICAInstalled = true
		return c.State.Save()
	}
	return nil
}

func systemTrusts(ctx context.Context, api string) bool {
	httpc, err := dpopclient.NewHTTPClient(nil, dialTimeout)
	if err != nil {
		return false
	}
	_, err = dpopclient.FetchNonce(ctx, httpc, api)
	return !trust.Untrusted(err)
}

// The browser sign-in needs the CA, a passkey does not work behind a certificate warning. Asked once, and only for a
// CA that can vouch for this server alone, like the core's own.
func offerInstall(api string, ca []byte) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	manual := "Install it by hand from " + strings.TrimRight(
		api,
		"/",
	) + trust.CAPath + " if the browser warns about the certificate."
	certs, err := trust.ParseBundle(ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow(fmt.Sprintf("warning: the CA cannot be installed: %v", err)))
		fmt.Fprintln(os.Stderr, manual)
		return false
	}
	host := apiHost(api)
	if !scopedTo(certs[0], host) {
		fmt.Fprintf(os.Stderr, "This CA is not limited to %s, so nk does not install it for every site.\n", host)
		fmt.Fprintln(os.Stderr, manual)
		return false
	}
	fmt.Fprintln(os.Stderr, "Your browser has to trust this CA too, or the sign-in page shows a certificate warning.")
	if !ask("Install it into the system trust store? This may ask for your password.", false) {
		fmt.Fprintln(os.Stderr, manual)
		return false
	}
	if err = truststore.Install(certs[0], truststore.WithFirefox(), truststore.WithPrefix("nokku-")); err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow(fmt.Sprintf("warning: the CA was not installed: %v", err)))
		fmt.Fprintln(os.Stderr, manual)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s Installed. Restart the browser if it still warns.\n", ui.Green("✔"))
	// Some browsers keep a certificate database of their own, which only certutil can write.
	if _, err = truststore.NewNSSTrust(); err != nil && !errors.Is(err, truststore.ErrTrustNotSupported) {
		fmt.Fprintln(os.Stderr, "certutil is not installed, so only the system trust store has the CA. "+
			"Most browsers read it. "+manual)
	}
	return true
}

// scopedTo reports whether ca vouches for host and the names below it only, never an IP address. A root in the
// system trust store is trusted by every program, so a wider one could be used against any site.
func scopedTo(ca *x509.Certificate, host string) bool {
	if !ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 ||
		!strings.EqualFold(ca.PermittedDNSDomains[0], host) || len(ca.PermittedIPRanges) > 0 {
		return false
	}
	var v4, v6 bool
	for _, n := range ca.ExcludedIPRanges {
		switch ones, bits := n.Mask.Size(); {
		case ones == 0 && bits == 32:
			v4 = true
		case ones == 0 && bits == 128:
			v6 = true
		}
	}
	return v4 && v6
}

func apiHost(api string) string {
	u, err := url.Parse(api)
	if err != nil {
		return api
	}
	return u.Hostname()
}

// OfferRemoval asks at sign-out, after it nk has no certificate left to remove the CA with.
func OfferRemoval(s *state.State) {
	if !s.APICAInstalled {
		return
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(
			os.Stderr,
			"The CA of %s stays in the system trust store, the web app in your browser needs it.\n",
			s.APIURL,
		)
		return
	}
	fmt.Fprintf(
		os.Stderr,
		"The CA of %s is in the system trust store, the web app in your browser needs it.\n",
		s.APIURL,
	)
	if !ask("Remove it too? This may ask for your password.", false) {
		fmt.Fprintln(os.Stderr, "It stays.")
		return
	}
	certs, err := trust.ParseBundle([]byte(s.APICA))
	if err == nil {
		err = truststore.Uninstall(certs[0], truststore.WithFirefox(), truststore.WithPrefix("nokku-"))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow(fmt.Sprintf("warning: the CA was not removed: %v", err)))
		return
	}
	fmt.Fprintf(os.Stderr, "%s Removed the CA\n", ui.Green("✔"))
}

func ask(question string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", question, hint)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "":
		return def
	}
	return false
}
