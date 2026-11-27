import { MAX_PAGE_SIZE } from '#lib/config.js';
import { type Daemon, DaemonService } from '#lib/gen/nokku/v1/daemon_pb.js';
import { confirm } from '#lib/hooks/index.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { whenFresh } from './auth.svelte';
import { target } from './targets.svelte';
import { plural, useBulkMutation } from './bulk';
import { addSession, TerminalSession } from './terminal.svelte';
import { usePatch } from './mask';

export const daemon = {
	// Every daemon by name, for filters that pick one.
	list: () => useQuery(DaemonService.method.listDaemons, { limit: MAX_PAGE_SIZE, offset: 0 }),
	createSession: () =>
		useMutation(DaemonService.method.createSession, {
			onSuccess: (data, vars) => {
				if (!data.session || !vars.daemonId) return;
				addSession(
					new TerminalSession(
						data.session.id,
						vars.daemonId,
						data.daemonName,
						data.session.username
					)
				);
			}
		}),
	update: () => usePatch(DaemonService.method.updateDaemon),
	setSafeguards: () => useMutation(DaemonService.method.setDaemonSafeguards),
	approve: () => useMutation(DaemonService.method.approveDaemon),
	approveMany: () =>
		useBulkMutation(DaemonService.method.approveDaemon, (n) => `${plural(n, 'server')} approved`)
};

// useDaemonReview approves or rejects an enrolled daemon the same way everywhere. Reject takes its server along.
export function useDaemonReview() {
	const approve = daemon.approve();
	const remove = target.delete();
	return {
		get pending() {
			return approve.isPending || remove.isPending;
		},
		approving: (id: string) => approve.isPending && approve.variables?.id === id,
		approve: (d: Pick<Daemon, 'id'>) => approve.mutateAsync({ id: d.id }),
		reject(d: Pick<Daemon, 'id' | 'name'>, done?: () => void) {
			void whenFresh(() =>
				confirm({
					title: `Reject ${d.name}?`,
					description: 'The server and its daemon are removed. The host has to enroll again.',
					confirmText: 'Reject',
					onConfirm: async () => {
						await remove.mutateAsync({ id: d.id });
						done?.();
					}
				})
			);
		}
	};
}
