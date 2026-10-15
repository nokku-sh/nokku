import type { Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
import type { GetDashboardResponse } from '#lib/gen/nokku/v1/dashboard_pb.js';
import type { Tone } from '#lib/tone.js';
import { formatTs } from '#lib/utils.js';
import { timestampDate } from '@bufbuild/protobuf/wkt';

export type Issue = {
	id: string;
	tone: Tone;
	title: string;
	detail: string;
	href: string;
	/** Pending daemons, approved inline. */
	approve?: Daemon[];
};

/** The one line that sums the issues up. Undefined issues means still loading, fresh means nothing is enrolled yet. */
export function headline(
	issues: Issue[] | undefined,
	fresh = false
): { mark: string; text: string; tone: Tone } {
	if (!issues) return { mark: '…', text: 'checking', tone: 'muted' };
	if (!issues.length && fresh) return { mark: '○', text: 'no servers yet', tone: 'info' };
	if (!issues.length) return { mark: '●', text: 'all good', tone: 'success' };
	const n = issues.length;
	const bad = issues[0].tone === 'destructive';
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

const DAY = 24 * 3600_000;
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
			title: `${n} ${n === 1 ? 'daemon waits' : 'daemons wait'} for approval`,
			detail: 'They cannot serve targets until someone approves them.',
			href: '/infrastructure/daemons',
			approve: d.pendingDaemons
		});
	}

	for (const daemon of d.offlineDaemons) {
		issues.push({
			id: `offline-${daemon.id}`,
			tone: 'destructive',
			title: `${daemon.name} is offline`,
			detail: daemon.lastSeenAt
				? `Last seen ${formatTs(daemon.lastSeenAt, 'relative')}. Its targets are unreachable.`
				: 'It never connected. Check that nokkud runs on the host.',
			href: `/infrastructure/daemons?id=${daemon.id}`
		});
	}

	for (const ca of d.soonestCas) {
		const left = ca.notAfter ? timestampDate(ca.notAfter).getTime() - Date.now() : Infinity;
		if (left > 14 * DAY) continue;
		const urgent = left < 3 * DAY;
		issues.push({
			id: `ca-${ca.id}`,
			tone: urgent ? 'destructive' : 'warning',
			title: `${ca.name} expires ${formatTs(ca.notAfter, 'relative')}`,
			detail: urgent
				? 'Roll it over now. Logins signed by it stop working when it expires.'
				: 'Roll it over before then, or logins signed by it stop working.',
			href: `/certificates?id=${ca.id}`
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
