import { DashboardService } from '$lib/gen/nokku/v1/dashboard_pb';
import { useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';

export const dashboard = {
	// Polls, the status line should not go stale while the tab stays open.
	get: (enabled: () => boolean) =>
		useQuery(
			DashboardService.method.getDashboard,
			() => ({ workspaceId: workspaceID.current }),
			() => ({ enabled: !!workspaceID.current && enabled(), refetchInterval: 15_000 })
		)
};
