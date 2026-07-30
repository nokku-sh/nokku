import { env } from '$env/dynamic/public';

export const SupportEmail = env.PUBLIC_SUPPORT_EMAIL || 'mailto:support@mizuchi.dev';
export const DocsURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs';
export const DaemonURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs/daemon';
export const CLIURL = env.PUBLIC_DOCS_URL || 'https://nokku.sh/docs/cli';

export const APP_NAME = 'Nokku';
export const DEFAULT_LANGUAGE = 'en';
