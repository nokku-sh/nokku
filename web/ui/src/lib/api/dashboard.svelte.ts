import { DashboardService } from '#lib/gen/nokku/v1/dashboard_pb.js';
import { useQuery } from '#lib/query/index.js';

export const dashboard = {
	// Polls, the status line should not go stale while the tab stays open.
	get: (enabled: () => boolean) =>
		useQuery(DashboardService.method.getDashboard, {}, () => ({
			enabled: enabled(),
			refetchInterval: 15_000
		}))
};
