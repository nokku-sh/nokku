import { UpgradeURL } from '#lib/config.js';
import { WorkspaceService } from '#lib/gen/nokku/v1/workspace_pb.js';
import { useQuery } from '#lib/query/index.js';

/** The plans and their features as the server names them. Every member reads it, the layout keeps it fresh. */
export function usePlans() {
	const ws = useQuery(
		WorkspaceService.method.getWorkspace,
		{},
		{
			select: (res) => ({ catalog: res.catalog, names: res.planNames }),
			staleTime: Infinity,
			refetchInterval: false
		}
	);

	const planFor = (feature: string) =>
		ws.data?.catalog.find((f) => f.key === feature)?.plan ?? 'enterprise';

	const planName = (code: string | undefined) => {
		const key = code || 'community';
		return ws.data?.names[key] ?? key;
	};

	return {
		get catalog() {
			return ws.data?.catalog ?? [];
		},
		planName,
		/** The plan to buy for a feature, the same hosted and self-hosted. */
		requiredPlan: (feature: string) => planName(planFor(feature)),
		/** Where to get a feature. Self-hosted activates a key in billing, hosted Pro is bought in billing, hosted Enterprise is sold outside. */
		upgradeLink: (feature: string, mode: string | undefined) => {
			if (mode === 'saas' && planFor(feature) === 'enterprise') {
				return { href: UpgradeURL, label: 'See plans', external: true };
			}
			return {
				href: '/settings/billing',
				label: mode === 'saas' ? 'Upgrade' : 'Activate a license',
				external: false
			};
		}
	};
}
