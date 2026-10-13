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
} from "react-email";
import { CONFIG, CONSTANTS } from "../constants/vars";

interface BaseEmailLayoutProps {
  children: React.ReactNode;
  preview: string;
  // "instance" mails come from any Nokku server, so the server fills in whoever runs it.
  type: "license" | "marketing" | "instance";
}

export default function BaseLayout({ children, preview, type }: BaseEmailLayoutProps) {
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
        <Head>
          {/* Keeps Apple Mail and Outlook from recoloring the card in dark mode. */}
          <meta name="color-scheme" content="light" />
          <meta name="supported-color-schemes" content="light" />
        </Head>
        <Body className="m-0 bg-cloud py-10 font-sans text-ink">
          <Preview>{preview}</Preview>
          <Container className="mx-auto max-w-[600px] overflow-hidden rounded-2xl border border-line bg-white">
            <Section className="border-b border-line px-6 py-6 sm:px-8">
              <Text className="m-0 text-[22px] font-bold leading-7 tracking-[-0.6px] text-ink">
                nokku<span className="text-brand">.</span>
              </Text>
            </Section>
            <Section className="px-6 py-8 sm:px-8">{children}</Section>
            <Section className="border-t border-line bg-card px-6 py-7 sm:px-8">
              {type === "instance" ? <InstanceFooter /> : <CompanyFooter type={type} />}
            </Section>
          </Container>
        </Body>
      </Html>
    </Tailwind>
  );
}

function CompanyFooter({ type }: { type: "license" | "marketing" }) {
  return (
    <>
      {type === "marketing" ? (
        <Text className="m-0 text-xs leading-5 text-muted">
          You're receiving this because you subscribed to product updates from {CONFIG.APP_NAME}.
          Want to change how often you hear from us?{" "}
          <Link href={CONFIG.UNSUBSCRIBE_URL} className="font-medium text-brand no-underline">
            Unsubscribe
          </Link>
          .
        </Text>
      ) : (
        <Text className="m-0 text-xs leading-5 text-muted">
          You're receiving this because a {CONFIG.APP_NAME} Enterprise license was issued to this
          address. Questions? Write to{" "}
          <Link href={`mailto:${CONFIG.SUPPORT_EMAIL}`} className="font-medium text-brand no-underline">
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
      <Text className="m-0 mt-3 text-[11px] leading-5 text-muted">
        © {new Date().getFullYear()} {CONFIG.COMPANY_NAME}
        <br />
        {CONFIG.SUPPORT_EMAIL}
        <br />
        {CONFIG.COMPANY_ADDRESS}
      </Text>
    </>
  );
}

// Go template syntax, rendered by internal/email. Empty settings drop their part.
function InstanceFooter() {
  const o = CONSTANTS.OPERATOR;
  return (
    <>
      <Text className="m-0 text-xs leading-5 text-muted">
        This is a security email about your account on{" "}
        {`{{ if ${o.NAME} }}${o.NAME_VALUE}{{ else }}this Nokku server{{ end }}`}. If you did
        not do this,{" "}
        {`{{ if ${o.SUPPORT_EMAIL} }}`}contact{" "}
        <Link
          href={`mailto:${o.SUPPORT_EMAIL_VALUE}`}
          className="font-medium text-brand no-underline"
        >
          {o.SUPPORT_EMAIL_VALUE}
        </Link>
        {"{{ else }}tell your administrator{{ end }}"}.
      </Text>
      {`{{ if or ${o.WEBSITE} ${o.PRIVACY} ${o.TERMS} ${o.IMPRINT} }}`}
      <Text className="m-0 mt-5 text-xs leading-5 text-muted">
        {`{{ if ${o.WEBSITE} }}`}
        <Link href={o.WEBSITE_VALUE} className="mr-3 text-muted underline">Website</Link>
        {"{{ end }}"}
        {`{{ if ${o.PRIVACY} }}`}
        <Link href={o.PRIVACY_VALUE} className="mr-3 text-muted underline">Privacy</Link>
        {"{{ end }}"}
        {`{{ if ${o.TERMS} }}`}
        <Link href={o.TERMS_VALUE} className="mr-3 text-muted underline">Terms</Link>
        {"{{ end }}"}
        {`{{ if ${o.IMPRINT} }}`}
        <Link href={o.IMPRINT_VALUE} className="mr-3 text-muted underline">Imprint</Link>
        {"{{ end }}"}
      </Text>
      {"{{ end }}"}
      {`{{ if ${o.NAME} }}`}
      <Text className="m-0 mt-3 text-[11px] leading-5 text-muted">
        © {new Date().getFullYear()} {o.NAME_VALUE}
        {`{{ if ${o.ADDRESS} }}`}
        <br />
        {o.ADDRESS_VALUE}
        {"{{ end }}"}
      </Text>
      {"{{ end }}"}
    </>
  );
}
