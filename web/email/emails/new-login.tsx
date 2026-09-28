import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function NewLogin() {
  return (
    <BaseLayout preview="A new sign-in was recorded on your Nokku account.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Sign-in notice
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        New sign-in recorded.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-muted">
        A new sign-in to your account was just recorded. Review the details below to confirm this
        was you.
      </Text>
      <Section className="my-7 rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-xs font-bold uppercase tracking-[1.2px] text-muted">
          Sign-in details
        </Text>
        <Text className="m-0 mt-4 text-sm leading-6 text-ink">
          <strong>Name:</strong> {CONSTANTS.DEVICE_NAME}
        </Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-ink">
          <strong>When:</strong> {CONSTANTS.EVENT_TIME}
        </Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-ink">
          <strong>IP address:</strong> {CONSTANTS.IP_ADDRESS}
        </Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-ink">
          <strong>Device ID:</strong> {CONSTANTS.DEVICE_ID}
        </Text>
      </Section>
      <Text className="m-0 text-base leading-7 text-muted">
        If you do not recognize this sign-in, review your security settings immediately.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.PROFILE_URL}
          className="box-border rounded-lg bg-ink px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Review account security
        </Button>
      </Section>
    </BaseLayout>
  );
}
