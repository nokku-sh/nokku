package client

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode"

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

// confirmServer asks whether to trust the CA the server advertises, the way
// ssh asks about a host key. cause is the verification that failed.
func (c *Client) confirmServer(ctx context.Context, interactive bool, cause error) error {
	api := c.State.APIURL
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

	fmt.Printf("\nThe certificate of %s comes from a CA this machine does not know.\n\n", api)
	for _, cert := range certs {
		// The name is not verified yet, and a control character starts an escape sequence.
		name := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, cert.Subject.CommonName)
		fmt.Printf("  %s\n  %s\n\n", name, ui.Bold(trust.Pin(cert)))
	}
	fmt.Println("Compare the pin with the one in the Nokku web app, under Profile, Security or Settings.")
	if !ask("Trust this CA for "+api+"?", false) {
		return errors.New("the server is not trusted, nothing was sent to it")
	}
	// The server may name a chain, its certificate comes from one of them.
	for _, cert := range certs {
		if err = c.keepCA(ctx, trust.Pin(cert)); err == nil {
			return nil
		}
	}
	return err
}

// keepCA checks the advertised CA against pin, stores it, and reconnects
// with it.
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
	fmt.Printf("%s Trusting the CA of %s\n", ui.Green("✔"), api)
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
	_, _, err = dpopclient.FetchNonce(ctx, httpc, api)
	return !trust.Untrusted(err)
}

// offerInstall asks whether the CA goes into the system trust store too. The
// sign-in runs in the browser, and a passkey does not work on a page with a
// certificate warning. It asks once, when the CA is first kept, and reports
// whether the CA went in.
func offerInstall(api string, ca []byte) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	manual := "Install it by hand from " + strings.TrimRight(
		api,
		"/",
	) + trust.CAPath + " if the browser warns about the certificate."
	fmt.Println("Your browser has to trust this CA too, or the sign-in page shows a certificate warning.")
	if !ask("Install it into the system trust store? This may ask for your password.", true) {
		fmt.Println(manual)
		return false
	}
	certs, err := trust.ParseBundle(ca)
	if err == nil {
		err = truststore.Install(certs[0], truststore.WithFirefox(), truststore.WithPrefix("nokku-"))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow(fmt.Sprintf("warning: the CA was not installed: %v", err)))
		fmt.Println(manual)
		return false
	}
	fmt.Printf("%s Installed. Restart the browser if it still warns.\n", ui.Green("✔"))
	// Some browsers keep a certificate database of their own, which only
	// certutil can write.
	if _, err = truststore.NewNSSTrust(); err != nil && !errors.Is(err, truststore.ErrTrustNotSupported) {
		fmt.Println("certutil is not installed, so only the system trust store has the CA. " +
			"Most browsers read it. " + manual)
	}
	return true
}

// OfferRemoval asks at sign-out whether the CA that nk installed for the
// browser goes too. After the sign-out nk has no certificate left to remove
// it with, so this is the one moment to ask.
func OfferRemoval(s *state.State) {
	if !s.APICAInstalled {
		return
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Printf("The CA of %s stays in the system trust store, the web app in your browser needs it.\n", s.APIURL)
		return
	}
	fmt.Printf("The CA of %s is in the system trust store, the web app in your browser needs it.\n", s.APIURL)
	if !ask("Remove it too? This may ask for your password.", false) {
		fmt.Println("It stays.")
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
	fmt.Printf("%s Removed the CA\n", ui.Green("✔"))
}

func ask(question string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Printf("%s %s ", question, hint)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "":
		return def
	}
	return false
}
