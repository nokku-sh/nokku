import { Button, Heading, Hr, Link, Section, Text } from "react-email";
import { CONFIG } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

/**
 * Marketing email for release digests. Static HTML by design — the exported
 * file (out/changelog.html) is meant to be uploaded to Resend as-is, no
 * template variables. Update the version/date and list, re-export, and paste.
 */
export default function Changelog() {
  return (
    <BaseLayout preview="Nokku 0.14 is out: SAML support, faster policy sync, and more." type="marketing">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Changelog
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        What's new in Nokku 0.14
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        This release focuses on enterprise readiness: a new SSO protocol, a leaner policy pipeline,
        and a handful of fixes that make day-to-day access management quieter.
      </Text>

      <Section className="my-7">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">New</Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-muted">
          <strong className="text-ink">SAML SSO</strong> for enterprise domains, alongside the
          existing OIDC support — map any IdP attribute to your groups.
          <br />
          <br />
          <strong className="text-ink">Policy dry-run mode</strong> on the CLI: preview which
          certificates a change would issue before it lands.
        </Text>
      </Section>

      <Section className="mb-7">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">Improved</Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-muted">
          <strong className="text-ink">Faster edge sync.</strong> Daemons now diff policy snapshots
          instead of re-pulling them, cutting typical sync time by ~60%.
        </Text>
      </Section>

      <Section className="mb-7">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">Fixed</Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-muted">
          <strong className="text-ink">Revocation propagation</strong> race that could keep a
          revoked certificate usable for up to 30 seconds.
        </Text>
      </Section>

      <Section className="rounded-xl border border-mistLine bg-mist px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">Upgrade notes</Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          Self-hosted: update the control plane and{" "}
          <code className="rounded bg-cloud px-1 font-mono">nokkud</code> together — the new sync
          protocol requires both sides. No config changes needed.
        </Text>
      </Section>

      <Section className="my-7">
        <Button
          href={CONFIG.CHANGELOG_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          View the full changelog
        </Button>
      </Section>

      <Hr className="my-7 border-line" />
      <Text className="m-0 text-sm leading-6 text-muted">
        Running Enterprise? The same release is available for your license key on{" "}
        <Link href={CONFIG.DOCS_URL} className="font-medium text-brand underline">
          the docs
        </Link>
        .
      </Text>
    </BaseLayout>
  );
}
