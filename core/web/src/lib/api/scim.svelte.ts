import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { SCIMService } from '#lib/gen/nokku/v1/scim_pb.js';

export const scim = {
	listTokens: () =>
		useQuery(SCIMService.method.listSCIMTokens, {}, () => ({ select: (res) => res.tokens ?? [] })),
	baseUrl: () => useQuery(SCIMService.method.listSCIMTokens, {}, { select: (res) => res.baseUrl }),

	createToken: () =>
		useMutation(SCIMService.method.createSCIMToken, {
			onSuccess: () => toast.success('SCIM token created')
		}),
	deleteToken: () =>
		useMutation(SCIMService.method.deleteSCIMToken, {
			onSuccess: () => toast.success('SCIM token revoked')
		})
};
