import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function EmailChange() {
  return (
    <BaseLayout type="instance" preview="The email address of your Nokku account is being changed.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Security notice
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Your email address is being changed.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Someone signed in to your account and asked to change its email address. The change
        happens once the new address is confirmed.
      </Text>
      <Section className="my-7 rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.2px] text-muted">
          New address
        </Text>
        <Text className="m-0 mt-4 text-sm leading-6 text-ink">{CONSTANTS.NEW_EMAIL}</Text>
      </Section>
      <Text className="m-0 text-base leading-7 text-muted">
        If this was you, there is nothing to do here. If it was not, cancel the change. This also
        works after the change went through: it puts this address back and signs the account out
        everywhere. Change your password afterwards.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.CANCEL_URL}
          className="box-border rounded-lg bg-ink px-5 py-3 text-sm font-bold text-white no-underline"
        >
          This wasn't me, cancel the change
        </Button>
      </Section>
      <Text className="m-0 text-sm leading-6 text-muted">
        The link works for {CONSTANTS.EXPIRATION}.
      </Text>
    </BaseLayout>
  );
}
