import { UtilService } from '#lib/gen/nokku/v1/util_pb.js';
import { useQuery } from '#lib/query/index.js';

export const roles = {
	list: () =>
		useQuery(
			UtilService.method.listRoles,
			{},
			{
				select: (res) => res.roles
			}
		)
};
