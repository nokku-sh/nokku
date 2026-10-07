import { MAX_PAGE_SIZE } from '#lib/config.js';
import { DaemonService, DaemonStatus } from '#lib/gen/nokku/v1/daemon_pb.js';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';
import { plural, useBulkMutation } from './bulk';
import { addSession, TerminalSession } from './terminal.svelte';

export const daemon = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			DaemonService.method.getDaemon,
			() => ({ id: extract(id) }),
			() => ({ enabled: !!extract(id) })
		),
	list: (
		opts?: () => {
			query?: string;
			status?: DaemonStatus;
			online?: boolean;
			limit?: number;
			offset?: number;
		}
	) =>
		useQuery(
			DaemonService.method.listDaemons,
			() => ({
				limit: MAX_PAGE_SIZE,
				offset: 0,
				...opts?.()
			}),
			() => ({ refetchInterval: 15000 })
		),
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
	update: () => useMutation(DaemonService.method.updateDaemon),
	delete: () => useMutation(DaemonService.method.deleteDaemon),
	approveMany: () =>
		useBulkMutation(DaemonService.method.updateDaemon, (n) => `${plural(n, 'daemon')} approved`),
	deleteMany: () =>
		useBulkMutation(DaemonService.method.deleteDaemon, (n) => `${plural(n, 'daemon')} deleted`)
};
