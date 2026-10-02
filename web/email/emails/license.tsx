import { Button, Heading, Hr, Link, Section, Text } from "react-email";
import { CONFIG, CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

/**
 * Enterprise license key email, sent by the license worker (a separate repo)
 * when a Stripe license subscription is purchased or renewed. The exported
 * HTML (web/email/out/license.html) is embedded in the Go worker and rendered
 * with html/template — adjust copy here, re-export, and copy it over.
 */
export default function LicenseKey() {
  return (
    <BaseLayout preview="Your Nokku Enterprise license key is ready.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Enterprise license
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Your license key
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Thanks for your purchase! Your Nokku Enterprise license for{" "}
        <strong className="text-ink">{CONSTANTS.CUSTOMER_EMAIL}</strong> unlocks unlimited quotas,
        SSO enforcement and 365-day audit retention on any self-hosted instance.
      </Text>

      <Section className="my-7 rounded-xl border border-line bg-mist px-5 py-4">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-muted">
          License key
        </Text>
        <Text className="m-0 mt-1 break-all font-mono text-sm font-bold leading-6 text-ink">
          {CONSTANTS.LICENSE_KEY}
        </Text>
        <Text className="m-0 mt-3 text-xs leading-5 text-muted">
          Valid until <strong className="text-ink">{CONSTANTS.LICENSE_EXPIRES}</strong>. Paste it
          under Billing in the web UI, it applies at once without a restart. Setting the{" "}
          <code className="rounded bg-cloud px-1 font-mono">NOKKU_LICENSE_KEY</code> environment
          variable works too. Renewals are emailed automatically each year.
        </Text>
      </Section>

      <Section className="mb-7">
        <Button
          href={CONFIG.DOCS_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Read the docs
        </Button>
      </Section>

      <Hr className="my-7 border-line" />
      <Text className="m-0 text-sm leading-6 text-muted">
        Questions about your license?{" "}
        <Link href={`mailto:${CONFIG.SUPPORT_EMAIL}`} className="font-medium text-brand underline">
          {CONFIG.SUPPORT_EMAIL}
        </Link>
      </Text>
    </BaseLayout>
  );
}
