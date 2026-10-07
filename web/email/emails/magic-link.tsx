import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function MagicLink() {
  return (
    <BaseLayout type="instance" preview="Your sign-in link for Nokku.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">Sign in</Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Here is your sign-in link.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Open it in the browser you want to use. It works once and only for a short while.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.LINK_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Sign in
        </Button>
      </Section>
      <Section className="rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">
          Link expires in {CONSTANTS.EXPIRATION}
        </Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          If you did not ask to sign in, ignore this email. Nobody can use the link without it.
        </Text>
      </Section>
    </BaseLayout>
  );
}
