import { UtilService } from '$lib/gen/nokku/v1/util_pb';
import { useQuery } from '$lib/query';

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
