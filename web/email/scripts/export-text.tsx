import { readdirSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { createElement } from "react";
import { render } from "@react-email/render";

// The CLI's plain text export uppercases headings, which would turn {{ .Workspace }} into {{ .WORKSPACE }}.
const emailsDir = join(__dirname, "../emails");
const outDir = join(__dirname, "../out/text");

const noUppercase = ["h1", "h2", "h3", "h4", "h5", "h6"].map((selector) => ({
  selector,
  options: { uppercase: false },
}));

async function main() {
  mkdirSync(outDir, { recursive: true });
  for (const file of readdirSync(emailsDir).filter((f) => f.endsWith(".tsx"))) {
    const { default: Email } = await import(join(emailsDir, file));
    const text = await render(createElement(Email), {
      plainText: true,
      htmlToTextOptions: {
        wordwrap: false,
        selectors: [...noUppercase, { selector: 'a[href^="mailto:"]', format: "anchor", options: { ignoreHref: true } }],
      },
    });
    writeFileSync(join(outDir, basename(file, ".tsx") + ".txt"), text);
  }
}

main();
