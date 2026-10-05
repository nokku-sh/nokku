export { cn } from 'cn';
import {
	durationFromMs,
	timestampDate,
	type Duration,
	type Timestamp
} from '@bufbuild/protobuf/wkt';
import { type DateValue, DateFormatter, getLocalTimeZone } from '@internationalized/date';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type WithoutChild<T> = T extends { child?: any } ? Omit<T, 'child'> : T;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type WithoutChildren<T> = T extends { children?: any } ? Omit<T, 'children'> : T;
export type WithoutChildrenOrChild<T> = WithoutChildren<WithoutChild<T>>;
export type WithElementRef<T, U extends HTMLElement = HTMLElement> = T & { ref?: U | null };

export function formatBytes(bytes: number): string {
	if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`;
	if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
	if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KiB`;
	return `${bytes} B`;
}

export const toDate = (ts: Timestamp | null | undefined): Date =>
	ts ? timestampDate(ts) : new Date();

export const DateValueFormat = (date: DateValue | null | undefined) => {
	const format = new DateFormatter('en-US', {
		dateStyle: 'long',
		timeStyle: 'short'
	});
	return date ? format.format(date.toDate(getLocalTimeZone())) : '';
};
type DateStyle =
	| 'long'
	| 'short'
	| 'relative'
	| 'relative-short'
	| 'withTime'
	| 'time'
	| 'precise'
	| 'precise-utc';

// Audit grade: 24h clock with seconds, so events line up with server logs.
const precise = {
	month: 'short',
	day: 'numeric',
	year: 'numeric',
	hour: '2-digit',
	minute: '2-digit',
	second: '2-digit',
	hour12: false
} as const;

const formatters = {
	long: new Intl.DateTimeFormat(undefined, {
		year: 'numeric',
		month: 'long',
		day: 'numeric'
	}),
	short: new Intl.DateTimeFormat(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric'
	}),
	withTime: new Intl.DateTimeFormat(undefined, {
		year: 'numeric',
		month: 'long',
		day: 'numeric',
		hour: 'numeric',
		minute: '2-digit'
	}),
	time: new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }),
	precise: new Intl.DateTimeFormat(undefined, precise),
	'precise-utc': new Intl.DateTimeFormat(undefined, {
		...precise,
		timeZone: 'UTC',
		timeZoneName: 'short'
	})
};

export function formatTs(
	ts: Timestamp | null | undefined,
	style: DateStyle = 'long',
	fallback = ''
): string {
	if (!ts) return fallback;

	if (style === 'relative' || style === 'relative-short') {
		return formatRelative(ts, style === 'relative-short');
	}

	return formatters[style].format(timestampDate(ts));
}

function formatRelative(ts: Timestamp, short = false): string {
	const diffMs = timestampDate(ts).getTime() - Date.now();
	const absDiff = Math.abs(diffMs);
	const isFuture = diffMs > 0;

	if (absDiff < 10_000) return 'just now';

	const sec = Math.floor(absDiff / 1000);
	const min = Math.floor(sec / 60);
	const hr = Math.floor(min / 60);
	const day = Math.floor(hr / 24);
	const month = Math.floor(day / 30);
	const year = Math.floor(day / 365);

	let str: string;
	if (sec < 60) str = short ? `${sec}s` : `${sec} second${sec !== 1 ? 's' : ''}`;
	else if (min < 60) str = short ? `${min}m` : `${min} minute${min !== 1 ? 's' : ''}`;
	else if (hr < 24) str = short ? `${hr}h` : `${hr} hour${hr !== 1 ? 's' : ''}`;
	else if (day < 30) str = short ? `${day}d` : `${day} day${day !== 1 ? 's' : ''}`;
	else if (year < 1) str = short ? `${month}mo` : `${month} month${month !== 1 ? 's' : ''}`;
	else str = short ? `${year}y` : `${year} year${year !== 1 ? 's' : ''}`;

	return isFuture ? `in ${str}` : `${str} ago`;
}

export const secToD = (sec: number): Duration => durationFromMs(sec * 1000);

/** Excludes 0/UNSPECIFIED. */
export function enumToArray<T extends object>(e: T): { name: string; value: number }[] {
	return Object.entries(e)
		.filter(([, v]) => typeof v === 'number' && v !== 0)
		.map(([name, value]) => ({ name, value: value as number }));
}

export function enumLabel(value: string | undefined): string {
	if (!value) return '';
	return value
		.toLowerCase()
		.split('_')
		.map((w) => w.charAt(0).toUpperCase() + w.slice(1))
		.join(' ');
}
