import { accessRequests } from '#lib/api/access-requests.svelte.js';
import { user } from '#lib/api/user.svelte.js';
import { useFeatures } from '#lib/api/workspaces.svelte.js';
import { AccessRequestStatus, type AccessRequest } from '#lib/gen/nokku/v1/access_request_pb.js';
import { confirm } from '#lib/hooks/index.js';
import { enumLabel, formatHours } from '#lib/utils.js';
import { durationMs } from '@bufbuild/protobuf/wkt';

/** How long an approved request lasts, like "4 hours". */
export const lasting = (r: AccessRequest) =>
	formatHours(r.duration ? durationMs(r.duration) / 3_600_000 : 0);

export const requester = (r: AccessRequest) => r.requesterName || r.requesterEmail;

/** "Approved", "Pending" and so on. */
export const requestState = (r: AccessRequest) => enumLabel(AccessRequestStatus[r.status]);

// useRequestAnswers asks before approving or denying, the same on every page that answers requests.
export function useRequestAnswers() {
	const approve = accessRequests.approve();
	const deny = accessRequests.deny();

	return {
		get pending() {
			return approve.isPending || deny.isPending;
		},
		approve(r: AccessRequest) {
			void confirm({
				title: `Approve ${r.username} on ${r.targetName}?`,
				description: `${requester(r)} can log in for ${lasting(r)} from now. It ends by itself.`,
				confirmText: 'Approve',
				destructive: false,
				onConfirm: () => approve.mutateAsync({ id: r.id })
			});
		},
		deny(r: AccessRequest) {
			void confirm({
				title: 'Deny this request?',
				description: `${requester(r)} gets an email that it was denied.`,
				confirmText: 'Deny',
				onConfirm: () => deny.mutateAsync({ id: r.id })
			});
		}
	};
}

// useWaitingRequests is what admins still have to answer, on a plan that has requests.
export function useWaitingRequests(live = false) {
	const can = user.can();
	const has = useFeatures();
	const list = accessRequests.list(
		{ status: AccessRequestStatus.PENDING, limit: 100 },
		{ when: () => can.admin && has('access_requests') === true, live }
	);
	return {
		get list() {
			return list.data?.requests ?? [];
		},
		get count() {
			return list.data?.total ?? 0;
		}
	};
}
