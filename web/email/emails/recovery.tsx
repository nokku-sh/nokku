import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function Recovery() {
  return (
    <BaseLayout preview="Reset your Nokku password. This link is time-limited.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-danger">
        Security action
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Reset your password.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        We received a request to reset the password for your account. Choose a new, unique password
        to regain access.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.RECOVERY_URL}
          className="box-border rounded-lg bg-ink px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Reset password
        </Button>
      </Section>
      <Section className="rounded-xl border border-[#f5c7c2] bg-dangerSoft px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">Did not request this?</Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          You can safely ignore this email. Your current password will remain unchanged. This link
          expires in <strong>{CONSTANTS.EXPIRATION}</strong>.
        </Text>
      </Section>
    </BaseLayout>
  );
}
