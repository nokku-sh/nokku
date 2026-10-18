import { UpgradeURL } from '#lib/config.js';

type PlanCode = 'community' | 'pro' | 'enterprise';

const names: Record<PlanCode, string> = {
	community: 'Community',
	pro: 'Pro',
	enterprise: 'Enterprise'
};

/** Mirrors CatalogFeatures in internal/entitlement. */
export const catalog: { key: string; label: string; plan: PlanCode }[] = [
	{ key: 'oidc', label: 'OIDC single sign-on', plan: 'community' },
	{ key: 'enforce_sso', label: 'Enforced single sign-on', plan: 'pro' },
	{ key: 'audit_export', label: 'Audit log export', plan: 'pro' },
	{ key: 'expiring_access', label: 'Expiring access', plan: 'pro' },
	{ key: 'access_review', label: 'Access review report', plan: 'pro' },
	{ key: 'idle_timeout', label: 'Idle session timeout', plan: 'pro' },
	{ key: 'scim', label: 'SCIM provisioning', plan: 'enterprise' },
	{ key: 'access_requests', label: 'Access requests', plan: 'enterprise' },
	{ key: 'audit_streaming', label: 'Audit log streaming', plan: 'enterprise' },
	{ key: 'legal_hold', label: 'Legal hold', plan: 'enterprise' }
];

export function planName(code: string | undefined): string {
	return names[(code || 'community') as PlanCode] ?? code;
}

function planFor(feature: string): PlanCode {
	return catalog.find((f) => f.key === feature)?.plan ?? 'enterprise';
}

/** The plan to buy for a feature, the same hosted and self-hosted. */
export function requiredPlan(feature: string): string {
	return planName(planFor(feature));
}

/** Where to get a feature. Self-hosted activates a key in billing, hosted Pro is bought in billing, hosted Enterprise is sold outside. */
export function upgradeLink(feature: string, mode: string | undefined) {
	if (mode === 'saas' && planFor(feature) === 'enterprise') {
		return { href: UpgradeURL, label: 'See plans', external: true };
	}
	return {
		href: '/settings/billing',
		label: mode === 'saas' ? 'Upgrade' : 'Activate a license',
		external: false
	};
}
