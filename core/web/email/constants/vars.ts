/** Kept in one place so preview and production exports stay aligned. */
export const CONFIG = {
  APP_NAME: "Nokku",
  APP_URL: "https://nokku.sh",
  DOCS_URL: "https://nokku.sh/docs",
  CHANGELOG_URL: "https://nokku.sh/changelog",
  PRIVACY_URL: "https://nokku.sh/legal/privacy",
  TERMS_URL: "https://nokku.sh/legal/terms",
  IMPRINT_URL: "https://nokku.sh/legal/impressum",
  SUPPORT_EMAIL: "support@mizuchi.dev",
  COMPANY_NAME: "Mizuchi Labs",
  COMPANY_ADDRESS: "Sirapuit 8, 6460 Imst, Austria",
  UNSUBSCRIBE_URL: "https://nokku.sh/unsubscribe",
} as const;

/** The variables the server injects, one per field of the structs in internal/email/template_data.go. */
export const CONSTANTS = {
  USER_NAME: "{{ .UserName }}",
  EXPIRATION: "{{ .Expiration }}",

  LINK_URL: "{{ .LinkURL }}",
  WORKSPACE: "{{ .Workspace }}",
  NEW_EMAIL: "{{ .NewEmail }}",
  CANCEL_URL: "{{ .CancelURL }}",

  PROFILE_URL: "{{ .ProfileURL }}",
  EVENT_TIME: "{{ .EventTime }}",
  IP_ADDRESS: "{{ .IPAddress }}",
  DEVICE_NAME: "{{ .DeviceName }}",
  DEVICE_ID: "{{ .DeviceID }}",

  // Filled by the server from NOKKU_OPERATOR_*. The bare names are for {{ if }} checks, the _VALUE ones for output.
  OPERATOR: {
    NAME: ".Operator.Name",
    NAME_VALUE: "{{ .Operator.Name }}",
    ADDRESS: ".Operator.Address",
    ADDRESS_VALUE: "{{ .Operator.Address }}",
    SUPPORT_EMAIL: ".Operator.SupportEmail",
    SUPPORT_EMAIL_VALUE: "{{ .Operator.SupportEmail }}",
    WEBSITE: ".Operator.WebsiteURL",
    WEBSITE_VALUE: "{{ .Operator.WebsiteURL }}",
    PRIVACY: ".Operator.PrivacyURL",
    PRIVACY_VALUE: "{{ .Operator.PrivacyURL }}",
    TERMS: ".Operator.TermsURL",
    TERMS_VALUE: "{{ .Operator.TermsURL }}",
    IMPRINT: ".Operator.ImprintURL",
    IMPRINT_VALUE: "{{ .Operator.ImprintURL }}",
  },

  // The license worker (a separate repo) fills these.
  LICENSE_KEY: "{{ .Key }}",
  CUSTOMER_EMAIL: "{{ .Email }}",
  LICENSE_EXPIRES: "{{ .ExpiresAt }}",
} as const;

export type Config = typeof CONFIG;
export type Constants = typeof CONSTANTS;
