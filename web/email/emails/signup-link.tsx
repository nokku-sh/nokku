import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function SignupLink() {
  return (
    <BaseLayout type="instance" preview="Finish joining your workspace on Nokku.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        You are invited
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Join {CONSTANTS.WORKSPACE}.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Hi {CONSTANTS.USER_NAME}, this link creates your account and signs you in. You can add a
        passkey afterwards so you never need a link again.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.LINK_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Create my account
        </Button>
      </Section>
      <Section className="rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">
          Link expires in {CONSTANTS.EXPIRATION}
        </Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          If you were not expecting this, ignore it. No account is created until the link is used.
        </Text>
      </Section>
    </BaseLayout>
  );
}
