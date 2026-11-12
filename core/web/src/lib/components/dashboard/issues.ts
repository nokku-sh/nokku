import type { Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
import type { GetDashboardResponse } from '#lib/gen/nokku/v1/dashboard_pb.js';
import type { Tone } from '#lib/tone.js';
import { formatTs } from '#lib/utils.js';

export type Issue = {
	id: string;
	tone: Tone;
	title: string;
	detail: string;
	href: string;
	/** Pending daemons, approved inline. */
	approve?: Daemon[];
	/** The servers one issue stands for, each a link to its sheet. */
	servers?: { id: string; name: string }[];
	/** What to run on the host to look into it. */
	command?: string;
};

/** Sums up the issues and waiting requests. Undefined issues is still loading, fresh is nothing enrolled yet. */
export function headline(
	issues: Issue[] | undefined,
	fresh = false,
	requests = 0
): { mark: string; text: string; tone: Tone } {
	if (!issues) return { mark: '…', text: 'checking', tone: 'muted' };
	const n = issues.length + requests;
	if (!n && fresh) return { mark: '○', text: 'no servers yet', tone: 'info' };
	if (!n) return { mark: '●', text: 'all good', tone: 'success' };
	const bad = issues[0]?.tone === 'destructive';
	return {
		mark: bad ? '✖' : '▲',
		text: `${n} ${n === 1 ? 'thing needs' : 'things need'} you`,
		tone: bad ? 'destructive' : 'warning'
	};
}

/** Nothing enrolled yet, so there is nothing to be healthy about. */
export function isFresh(d: GetDashboardResponse | undefined): boolean {
	return !!d && d.targets === 0 && d.daemons === 0;
}

const toneRank: Record<Tone, number> = {
	destructive: 0,
	warning: 1,
	info: 2,
	success: 3,
	muted: 4
};

// Only things someone can act on. Healthy numbers belong in the status line.
export function issuesOf(d: GetDashboardResponse): Issue[] {
	const issues: Issue[] = [];

	if (d.pendingDaemons.length) {
		const n = d.pendingDaemons.length;
		issues.push({
			id: 'pending',
			tone: 'warning',
			title: `${n} ${n === 1 ? 'server waits' : 'servers wait'} for approval`,
			detail: 'Their daemons enrolled. Nobody can log in to them until someone approves them.',
			href: '/servers?status=pending',
			approve: d.pendingDaemons
		});
	}

	// One row however many are down, so a rack that loses power is one thing to look at, not forty.
	const offline = d.offlineServers;
	const never = offline.filter((s) => !s.daemon?.lastSeenAt).length;
	if (offline.length === 1) {
		const seen = offline[0].daemon?.lastSeenAt;
		issues.push({
			id: 'offline',
			tone: 'destructive',
			title: `${offline[0].name} is offline`,
			detail: seen
				? `Last seen ${formatTs(seen, 'relative')}. Nobody can log in through its daemon.`
				: 'It never connected. Check that nokkud runs on the host.',
			href: `/servers?id=${offline[0].id}`,
			command: seen ? undefined : 'systemctl status nokkud'
		});
	} else if (offline.length) {
		issues.push({
			id: 'offline',
			tone: 'destructive',
			title: `${offline.length} servers are offline`,
			detail:
				never === offline.length
					? 'They never connected. Check that nokkud runs on each host.'
					: `Nobody can log in through their daemons.${never ? ` ${never} never connected.` : ''}`,
			href: '/servers?status=offline',
			servers: offline,
			command: never ? 'systemctl status nokkud' : undefined
		});
	}

	const quota = Number(d.recordingQuotaBytes);
	const used = Number(d.recordingBytes);
	if (quota > 0 && used / quota >= 0.9) {
		issues.push({
			id: 'storage',
			tone: 'warning',
			title: `Recording storage is ${Math.round((used / quota) * 100)}% full`,
			detail:
				'Recordings older than a day are deleted to make room. If that is not enough, new ones wait on their server.',
			href: '/recordings'
		});
	}

	// A spike is at least 10 failures in the last hour and three times the daily rate.
	const lastHour = d.failures.at(-1) ?? 0;
	const hourly = d.failures.reduce((a, b) => a + b, 0) / Math.max(1, d.failures.length);
	if (lastHour >= 10 && lastHour >= 3 * hourly) {
		issues.push({
			id: 'failures',
			tone: 'warning',
			title: `${lastHour} failed calls in the last hour`,
			detail: 'More than usual. Someone may be locked out, or something is probing.',
			href: '/audit?outcome=failed'
		});
	}

	return issues.sort((a, b) => toneRank[a.tone] - toneRank[b.tone]);
}
