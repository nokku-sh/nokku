import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function Verification() {
  return (
    <BaseLayout preview="Verify your email address to continue to Nokku.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Action required
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        Verify your email address.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        Confirm that this is the correct address for your account. This single click ensures your
        security notifications remain reliable.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.VERIFICATION_URL}
          className="box-border rounded-lg bg-brand px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Verify email address
        </Button>
      </Section>
      <Section className="rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-sm font-bold text-ink">
          Link expires in {CONSTANTS.EXPIRATION}
        </Text>
        <Text className="m-0 mt-1 text-sm leading-6 text-muted">
          If you did not request this verification, you can safely ignore this email.
        </Text>
      </Section>
    </BaseLayout>
  );
}
