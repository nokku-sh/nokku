/**
 * Static configuration for the email templates.
 * Kept in one place so preview and production exports stay aligned.
 */
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
  COMPANY_ADDRESS: "Musterstraße 1, 12345, Austria",
  UNSUBSCRIBE_URL: "https://nokku.sh/unsubscribe",
} as const;

/**
 * Template variables used in Go email templates.
 * These correspond to the variables injected by the Go backend.
 */
export const CONSTANTS = {
  // Common variables
  USER_NAME: "{{ .UserName }}",
  EXPIRATION: "{{ .Expiration }}",

  // Auth related
  VERIFICATION_URL: "{{ .VerificationURL }}",
  RECOVERY_URL: "{{ .RecoveryURL }}",

  // Security alert
  PROFILE_URL: "{{ .ProfileURL }}",
  EVENT_TYPE: "{{ .EventType }}",
  EVENT_TIME: "{{ .EventTime }}",
  LOCATION: "{{ .Location }}",

  // New Login / Device
  LOGIN_METHOD: "{{ .LoginMethod }}",
  DEVICE_INFO: "{{ .DeviceInfo }}",
  DEVICE_NAME: "{{ .DeviceName }}",
  DEVICE_ID: "{{ .DeviceID }}",

  // Role changed
  OLD_ROLE: "{{ .OldRole }}",
  NEW_ROLE: "{{ .NewRole }}",
  CHANGED_BY: "{{ .ChangedBy }}",

  // License key email
  LICENSE_KEY: "{{ .Key }}",
  CUSTOMER_EMAIL: "{{ .Email }}",
  LICENSE_EXPIRES: "{{ .ExpiresAt }}",
} as const;

/**
 * Type helper for template variables
 */
export type Config = typeof CONFIG;
export type Constants = typeof CONSTANTS;
