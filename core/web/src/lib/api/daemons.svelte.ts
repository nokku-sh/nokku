import { MAX_PAGE_SIZE } from '#lib/config.js';
import { DaemonService, DaemonStatus, type Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
import { confirm } from '#lib/hooks/index.js';
import { useMutation, useQuery } from '#lib/query/index.js';
import { whenFresh } from './auth.svelte';
import { plural, useBulkMutation } from './bulk';
import { addSession, TerminalSession } from './terminal.svelte';
import { usePatch, withMask } from './mask';

export const daemon = {
	// Every daemon by name, for filters that pick one.
	list: () => useQuery(DaemonService.method.listDaemons, { limit: MAX_PAGE_SIZE, offset: 0 }),
	createSession: () =>
		useMutation(DaemonService.method.createSession, {
			onSuccess: (data, vars) => {
				if (!data.session || !vars.daemonId) return;
				addSession(
					new TerminalSession(
						data.session.sessionId,
						vars.daemonId,
						data.daemonName,
						data.session.username
					)
				);
			}
		}),
	update: () => usePatch(DaemonService.method.updateDaemon),
	delete: () => useMutation(DaemonService.method.deleteDaemon),
	approveMany: () =>
		useBulkMutation(
			DaemonService.method.updateDaemon,
			(n) => `${plural(n, 'server')} approved`,
			withMask(DaemonService.method.updateDaemon.input)
		)
};

// useDaemonReview approves or rejects an enrolled daemon the same way everywhere. Reject takes its server along.
export function useDaemonReview() {
	const update = daemon.update();
	const remove = daemon.delete();
	return {
		get pending() {
			return update.isPending || remove.isPending;
		},
		approving: (id: string) => update.isPending && update.variables?.id === id,
		approve: (d: Pick<Daemon, 'id'>) =>
			update.mutateAsync({ id: d.id, status: DaemonStatus.ACCEPTED }),
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
