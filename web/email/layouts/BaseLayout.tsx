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
} from "react-email";
import { CONFIG } from "../constants/vars";

interface BaseEmailLayoutProps {
  children: React.ReactNode;
  preview: string;
}

export default function BaseLayout({ children, preview }: BaseEmailLayoutProps) {
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
              <Text className="m-0 text-xs leading-5 text-muted">
                This is a transactional security email about your {CONFIG.APP_NAME} account. If you
                did not initiate this action, contact{" "}
                <Link
                  href={`mailto:${CONFIG.SUPPORT_EMAIL}`}
                  className="font-medium text-brand no-underline"
                >
                  {CONFIG.SUPPORT_EMAIL}
                </Link>
                .
              </Text>
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
              <Text className="m-0 mt-3 text-[11px] leading-5 text-[#8b99aa]">
                © {new Date().getFullYear()} {CONFIG.COMPANY_NAME} · Austria
              </Text>
            </Section>
          </Container>
        </Body>
      </Html>
    </Tailwind>
  );
}
