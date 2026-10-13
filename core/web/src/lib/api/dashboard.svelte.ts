import { DashboardService } from '#lib/gen/nokku/v1/dashboard_pb.js';
import { useQuery } from '#lib/query/index.js';

export const dashboard = {
	get: (enabled: () => boolean) =>
		useQuery(DashboardService.method.getDashboard, {}, () => ({ enabled: enabled() }))
};
