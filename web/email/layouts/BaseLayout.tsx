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
            // Hex copies of the web UI tokens in web/ui/src/routes/layout.css.
            colors: {
              ink: "#141920",
              brand: "#008794",
              mist: "#e5f8fa",
              mistLine: "#b2e2e7",
              cloud: "#f3f6f9",
              card: "#fcfdff",
              line: "#d4d8de",
              muted: "#5f636a",
              danger: "#be222a",
              dangerSoft: "#fff0ee",
              dangerLine: "#fac6c1",
              terminal: "#0c0f16",
              caret: "#15d1aa",
            },
          },
        },
      }}
    >
      <Html lang="en">
        <Head />
        <Font
          fontFamily="Manrope Variable"
          // Gmail and Outlook drop web fonts, so they land here.
          fallbackFontFamily={["Helvetica", "Arial", "sans-serif"]}
          webFont={{
            url: "https://cdn.jsdelivr.net/fontsource/fonts/manrope:vf@latest/latin-wght-normal.woff2",
            format: "woff2",
          }}
          fontWeight={400}
          fontStyle="normal"
        />
        <Body className="m-0 bg-cloud py-10 font-sans text-ink">
          <Preview>{preview}</Preview>
          <Container className="mx-auto max-w-[600px] overflow-hidden rounded-2xl border border-line bg-white">
            <Section className="border-b border-line bg-terminal px-8 py-7">
              <Text className="m-0 font-mono text-[22px] font-bold tracking-[-0.4px] text-white">
                <span className="text-caret">&gt;</span> nokku
              </Text>
            </Section>
            <Section className="px-8 py-8">{children}</Section>
            <Section className="border-t border-line bg-card px-8 py-7">
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
                <Text className="text-[11px] leading-5 text-muted">
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
