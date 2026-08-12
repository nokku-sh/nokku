import {
  Body,
  Container,
  Head,
  Html,
  Link,
  pixelBasedPreset,
  Preview,
  Section,
  Tailwind,
  Text,
  Font,
  Row,
} from "react-email";
import { CONFIG } from "../constants/vars";

interface BaseEmailLayoutProps {
  children: React.ReactNode;
  preview: string;
  type?: "transactional" | "marketing";
}

export default function BaseLayout({
  children,
  preview,
  type = "transactional",
}: BaseEmailLayoutProps) {
  return (
    <Tailwind
      config={{
        presets: [pixelBasedPreset],
        theme: {
          extend: {
            colors: {
              ink: "#172033",
              brand: "#087e8b",
              mist: "#edf8f9",
              cloud: "#f4f7fb",
              line: "#dce4ed",
              muted: "#607086",
              danger: "#b42318",
              dangerSoft: "#fff1f0",
            },
          },
        },
      }}
    >
      <Html lang="en">
        <Head />
        <Font
          fontFamily="Public Sans Variable"
          fallbackFontFamily="sans-serif"
          webFont={{
            url: "https://cdn.jsdelivr.net/fontsource/fonts/public-sans:vf@5.3.0/latin-wght-normal.woff2",
            format: "woff2",
          }}
          fontWeight={400}
          fontStyle="normal"
        />
        <Body className="m-0 bg-cloud py-10 font-sans text-ink">
          <Preview>{preview}</Preview>
          <Container className="mx-auto max-w-[600px] overflow-hidden rounded-2xl border border-line bg-white">
            <Section className="border-b border-line bg-ink px-8 py-7">
              <Text className="m-0 text-[22px] font-bold tracking-[-0.4px] text-white">
                nokku<span className="text-[#65d6da]">.</span>
              </Text>
            </Section>
            <Section className="px-8 py-8">{children}</Section>
            <Section className="border-t border-line bg-[#fafcfe] px-8 py-7">
              {type === "marketing" ? (
                <Text className="m-0 text-xs leading-5 text-muted">
                  You're receiving this because you subscribed to product updates from{" "}
                  {CONFIG.APP_NAME}. Want to change how often you hear from us?{" "}
                  <Link
                    href={CONFIG.UNSUBSCRIBE_URL}
                    className="font-medium text-brand no-underline"
                  >
                    Unsubscribe
                  </Link>
                  .
                </Text>
              ) : (
                <Text className="m-0 text-xs leading-5 text-muted">
                  This is a transactional security email about your {CONFIG.APP_NAME} account. If
                  you did not initiate this action, contact{" "}
                  <Link
                    href={`mailto:${CONFIG.SUPPORT_EMAIL}`}
                    className="font-medium text-brand no-underline"
                  >
                    {CONFIG.SUPPORT_EMAIL}
                  </Link>
                  .
                </Text>
              )}
              <Text className="m-0 mt-5 text-xs leading-5 text-muted">
                <Link href={CONFIG.APP_URL} className="text-muted underline">
                  Website
                </Link>
                {"  ·  "}
                <Link href={CONFIG.PRIVACY_URL} className="text-muted underline">
                  Privacy
                </Link>
                {"  ·  "}
                <Link href={CONFIG.TERMS_URL} className="text-muted underline">
                  Terms
                </Link>
                {"  ·  "}
                <Link href={CONFIG.IMPRINT_URL} className="text-muted underline">
                  Legal notice
                </Link>
              </Text>
              <Row className="flex mt-3 items-center">
                <Text className="text-[11px] leading-5 text-gray-500">
                  © {new Date().getFullYear()} {CONFIG.COMPANY_NAME}
                  <br />
                  {CONFIG.SUPPORT_EMAIL}
                  <br />
                  {CONFIG.COMPANY_ADDRESS}
                </Text>
              </Row>
            </Section>
          </Container>
        </Body>
      </Html>
    </Tailwind>
  );
}
