import { Button, Heading, Hr, Link, Section, Text } from "react-email";
import { CONFIG } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

/**
 * Marketing email for announcing a new feature. Static HTML by design. The
 * exported file (out/product-update.html) is meant to be uploaded to Resend
 * as-is, no template variables. Tweak the copy, re-export, and paste.
 */
export default function ProductUpdate() {
  return (
    <BaseLayout preview="Nokku now rotates certificates automatically. Here's what that means for you." type="marketing">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Product update
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Automated certificate rotation is here.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Short-lived certificates are the core of Nokku, but rotating them by hand across
        hundreds of hosts is exactly the busywork you built this system to avoid. Starting today,
        the control plane handles the full rotation lifecycle for you.
      </Text>

      <Section className="my-7 rounded-xl border border-mistLine bg-mist px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">What's new</Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          <strong className="text-ink">Zero-touch renewal.</strong> Host certificates are renewed
          before expiry, with no daemon restart and no SSH session disruption.
          <br />
          <br />
          <strong className="text-ink">Rotation windows.</strong> Schedule rotations for quiet
          hours per host group, so cert churn never lands in your on-call queue.
          <br />
          <br />
          <strong className="text-ink">Full audit trail.</strong> Every rotation is recorded with
          the CA that signed it, enterprise audit retention included.
        </Text>
      </Section>

      <Section className="mb-7">
        <Button
          href={CONFIG.CHANGELOG_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Read the announcement
        </Button>
      </Section>

      <Text className="m-0 text-sm leading-6 text-muted">
        Running the daemon? Update <code className="rounded bg-cloud px-1 font-mono">nokkud</code>{" "}
        to the latest version to pick up rotation support. Everything else happens on the control
        plane.
      </Text>

      <Hr className="my-7 border-line" />
      <Text className="m-0 text-sm leading-6 text-muted">
        Questions or feedback? Reply to this email, or{" "}
        <Link href={CONFIG.DOCS_URL} className="font-medium text-brand underline">
          check the docs
        </Link>
        .
      </Text>
    </BaseLayout>
  );
}
