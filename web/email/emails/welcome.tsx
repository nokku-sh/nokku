import { Button, Heading, Hr, Link, Section, Text } from "react-email";
import { CONFIG, CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function Welcome() {
  return (
    <BaseLayout preview="Welcome to Nokku. Verify your email to get started.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Account setup
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Welcome aboard, {CONSTANTS.USER_NAME}.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Confirm your email address to activate your account.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.VERIFICATION_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Verify email address
        </Button>
      </Section>
      <Hr className="my-7 border-line" />
      <Section className="rounded-xl border border-[#bfe7e8] bg-mist px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">A secure start</Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          This verification link expires in <strong>{CONSTANTS.EXPIRATION}</strong>. If you did not
          create this account, you can safely ignore this email.
        </Text>
      </Section>
      <Text className="m-0 mt-7 text-sm leading-6 text-muted">
        Looking for implementation details?{" "}
        <Link href={CONFIG.DOCS_URL} className="font-medium text-brand underline">
          Read the docs
        </Link>
        .
      </Text>
    </BaseLayout>
  );
}
