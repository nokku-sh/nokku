import { UpgradeURL } from '#lib/config.js';

export type PlanCode = 'community' | 'pro' | 'enterprise';

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
	{ key: 'scim', label: 'SCIM provisioning', plan: 'enterprise' },
	{ key: 'external_kms', label: 'External key management', plan: 'enterprise' }
];

export function planName(code: string | undefined): string {
	return names[(code || 'community') as PlanCode] ?? code ?? names.community;
}

/** The plan to buy for a feature. Self-hosted licenses only come as Enterprise. */
export function requiredPlan(feature: string, mode: string | undefined): string {
	const plan = catalog.find((f) => f.key === feature)?.plan ?? 'enterprise';
	return planName(mode === 'saas' ? plan : plan === 'community' ? plan : 'enterprise');
}

/** Where to get a feature. Self-hosted activates a key in billing, hosted Pro is bought in billing, hosted Enterprise is sold outside. */
export function upgradeLink(feature: string, mode: string | undefined) {
	if (mode === 'saas' && requiredPlan(feature, mode) === names.enterprise) {
		return { href: UpgradeURL, label: 'See plans', external: true };
	}
	return {
		href: '/settings/billing',
		label: mode === 'saas' ? 'Upgrade' : 'Activate a license',
		external: false
	};
}
