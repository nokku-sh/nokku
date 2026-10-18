import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { LegalHoldService } from '#lib/gen/nokku/v1/legal_hold_pb.js';

export const legalHolds = {
	list: () => useQuery(LegalHoldService.method.listLegalHolds, {}, { select: (res) => res.holds }),

	create: () =>
		useMutation(LegalHoldService.method.createLegalHold, {
			onSuccess: () => toast.success('Legal hold placed')
		}),
	release: () =>
		useMutation(LegalHoldService.method.deleteLegalHold, {
			onSuccess: () => toast.success('Legal hold released')
		})
};
