import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function EmailConfirm() {
  return (
    <BaseLayout type="instance" preview="Confirm the new email address of your Nokku account.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Email change
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Confirm your new email address.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-ink">
        You asked to use this address for your Nokku account. The account switches to it once you
        confirm, and you sign in with it from then on.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.LINK_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Confirm this address
        </Button>
      </Section>
      <Section className="rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">
          The link expires in {CONSTANTS.EXPIRATION}
        </Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          If you did not ask for this, ignore this email. Nothing changes without the link.
        </Text>
      </Section>
    </BaseLayout>
  );
}
