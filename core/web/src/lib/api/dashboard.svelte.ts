import { DashboardService } from '#lib/gen/nokku/v1/dashboard_pb.js';
import { useQuery } from '#lib/query/index.js';
import { LIVE } from './client';

export const dashboard = {
	// The dashboard page passes live, the sidebar reads the same answer without asking again on its own.
	get: (enabled: () => boolean, live = false) =>
		useQuery(DashboardService.method.getDashboard, {}, () => ({
			enabled: enabled(),
			...(live && { refetchInterval: LIVE })
		}))
};
