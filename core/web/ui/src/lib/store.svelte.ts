import { PersistedState } from 'runed';

const NS = 'nokku';

export const pageSize = new PersistedState<number>(`${NS}:page:size`, 10);

export const activeSessionID = new PersistedState<string>(`${NS}:session:active`, ``);

// Empty is null below. PersistedState skips writing undefined, so the stored value would never go away.

// pendingDeviceCode brings a signed-out user back to /device after login.
export const pendingDeviceCode = new PersistedState<string | null>(`${NS}:device:code`, null, {
	storage: `session`,
	syncTabs: false
});

// Where a session expired, so signing in again lands there. Not per tab, the mailed link opens a new one.
export const returnTo = new PersistedState<{ path: string; at: number } | null>(
	`${NS}:return`,
	null
);

// Targets this browser connected to last, so the dashboard lists them first.
export const recentTargets = new PersistedState<string[]>(`${NS}:targets:recent`, []);

// The setup card on the dashboard, once someone waved it away.
export const setupDismissed = new PersistedState<boolean>(`${NS}:setup:dismissed`, false);

// Auditors compare timestamps with other systems, so they can pin UTC.
export const auditUTC = new PersistedState<boolean>(`${NS}:audit:utc`, false);
