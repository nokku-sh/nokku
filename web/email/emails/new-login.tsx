import { Button, Heading, Section, Text } from "react-email";
import { CONSTANTS } from "../constants/vars";
import BaseLayout from "../layouts/BaseLayout";

export default function NewLogin() {
  return (
    <BaseLayout type="instance" preview="A new device signed in to your Nokku account.">
      <Text className="m-0 text-xs font-bold uppercase tracking-[1.4px] text-brand">
        Sign-in notice
      </Text>
      <Heading className="m-0 mt-3 text-[30px] font-bold leading-9 tracking-[-0.6px] text-ink">
        New sign-in from {CONSTANTS.DEVICE_NAME}.
      </Heading>
      <Text className="m-0 mt-4 text-base leading-7 text-ink">
        A device we have not seen before signed in to your account. Check that this was you.
      </Text>
      <Section className="my-7 rounded-xl border border-line bg-cloud px-5 py-4">
        <Text className="m-0 text-sm leading-6 text-ink">
          <strong>Device:</strong> {CONSTANTS.DEVICE_NAME}
        </Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-ink">
          <strong>When:</strong> {CONSTANTS.EVENT_TIME}
        </Text>
        <Text className="m-0 mt-2 text-sm leading-6 text-ink">
          <strong>IP address:</strong> {CONSTANTS.IP_ADDRESS}
        </Text>
      </Section>
      <Text className="m-0 text-base leading-7 text-ink">
        If this was not you, sign that device out and check your passkeys.
      </Text>
      <Section className="my-7">
        <Button
          href={CONSTANTS.PROFILE_URL}
          className="box-border rounded-lg bg-ink px-5 py-3 text-sm font-bold text-white no-underline"
        >
          Review signed-in devices
        </Button>
      </Section>
      <Text className="m-0 text-xs leading-5 text-muted">Device ID {CONSTANTS.DEVICE_ID}</Text>
    </BaseLayout>
  );
}
