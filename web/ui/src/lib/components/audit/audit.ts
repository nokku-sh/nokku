import { goto } from '$app/navigation';
import { page } from '$app/state';
import { AuditOutcome, type EventLog } from '$lib/gen/nokku/v1/util_pb';
import { PAGE_PARAM } from '$lib/hooks';
import type { Timestamp } from '@bufbuild/protobuf/wkt';
import { timestampDate } from '@bufbuild/protobuf/wkt';
import {
	Bot,
	CircleCheck,
	CircleUser,
	CircleX,
	KeyRound,
	LogIn,
	Monitor,
	RefreshCw,
	Server,
	Settings,
	Shield,
	ShieldCheck,
	ShieldX,
	SquareTerminal,
	Terminal,
	Users,
	type LucideIcon
} from '@lucide/svelte';

export type Area = {
	value: string;
	label: string;
	icon: LucideIcon;
	/** Exact action names, matched on the server. */
	actions: string[];
};

export const areas: Area[] = [
	{
		value: 'access',
		label: 'Access',
		icon: ShieldCheck,
		actions: [
			'AddSubjectsToPrincipal',
			'RemoveSubjectsFromPrincipal',
			'RevokeAllAccess',
			'AddPrincipal',
			'RemovePrincipal'
		]
	},
	{
		value: 'people',
		label: 'People & roles',
		icon: Users,
		actions: [
			'UpdateWorkspaceMember',
			'RemoveWorkspaceMember',
			'UpdateWorkspaceOwner',
			'AcceptInvitation',
			'CreateTeam',
			'UpdateTeam',
			'DeleteTeam',
			'AddTeamMember',
			'RemoveTeamMember',
			'CreateServiceAccount',
			'UpdateServiceAccount',
			'DeleteServiceAccount',
			'CreateToken',
			'DeleteToken',
			'UserCreated',
			'UserDeleted',
			'UserDeactivated'
		]
	},
	{
		value: 'infrastructure',
		label: 'Infrastructure',
		icon: Server,
		actions: [
			'CreateTarget',
			'UpdateTarget',
			'DeleteTarget',
			'SyncTargetUsers',
			'EnrollDaemon',
			'UpdateDaemon',
			'DeleteDaemon'
		]
	},
	{
		value: 'certificates',
		label: 'Certificates',
		icon: Shield,
		actions: [
			'CreateCertificateAuthority',
			'UpdateCertificateAuthority',
			'DeleteCertificateAuthority',
			'RolloverCertificateAuthority',
			'SignSSHCertificate',
			'SignX509Certificate'
		]
	},
	{
		value: 'sessions',
		label: 'Sessions',
		icon: SquareTerminal,
		actions: [
			'CreateSession',
			'CloseSession',
			'RelayOpen',
			'RelayClose',
			'GetRecording',
			'RecordingScrubFailed'
		]
	},
	{
		value: 'signins',
		label: 'Sign-ins',
		icon: LogIn,
		actions: [
			'Login',
			'LoginDenied',
			'SessionIssued',
			'SessionRevoked',
			'PasswordSet',
			'CredentialAdded'
		]
	},
	{
		value: 'workspace',
		label: 'Workspace & SSO',
		icon: Settings,
		actions: [
			'CreateWorkspace',
			'UpdateWorkspace',
			'DeleteWorkspace',
			'UpdateSSOProvider',
			'CreateWorkspaceDomain',
			'DeleteWorkspaceDomain',
			'VerifyWorkspaceDomain',
			'RegenerateWorkspaceDomainToken',
			'CreateSCIMToken',
			'DeleteSCIMToken'
		]
	}
];

const areaByAction = new Map(areas.flatMap((a) => a.actions.map((action) => [action, a])));
export const areaOf = (action: string) => areaByAction.get(action);

export const outcomes = [
	{ value: 'failed', label: 'Failed', icon: CircleX, enum: AuditOutcome.FAILED },
	{ value: 'denied', label: 'Denied only', icon: ShieldX, enum: AuditOutcome.DENIED },
	{ value: 'succeeded', label: 'Succeeded', icon: CircleCheck, enum: AuditOutcome.SUCCEEDED }
];

export const actorKinds: { value: string; label: string; icon: LucideIcon }[] = [
	{ value: 'user', label: 'People', icon: CircleUser },
	{ value: 'cli', label: 'CLI', icon: Terminal },
	{ value: 'service_account', label: 'Service accounts', icon: Bot },
	{ value: 'daemon', label: 'Daemons', icon: Server },
	{ value: 'scim', label: 'SCIM', icon: RefreshCw },
	{ value: 'web_device', label: 'Remembered devices', icon: Monitor }
];
export const kindOf = (kind: string) => actorKinds.find((k) => k.value === kind);

/** Params owned by the quick views, clicking one replaces all of them. */
export const filterParams = ['q', 'area', 'outcome', 'kind', 'actor', 'target'];

export const quickViews: { label: string; params: Record<string, string> }[] = [
	{ label: 'Everything', params: {} },
	{ label: 'Access changes', params: { area: 'access' } },
	{ label: 'Failed & denied', params: { outcome: 'failed' } },
	{ label: 'People & roles', params: { area: 'people' } },
	{ label: 'Certificates', params: { area: 'certificates' } },
	{ label: 'Sign-ins', params: { area: 'signins' } }
];

// Auth and relay events aren't RPC names, so they read better spelled out.
const labels: Record<string, string> = {
	Login: 'Signed in',
	LoginDenied: 'Sign-in denied',
	SessionIssued: 'Session started',
	SessionRevoked: 'Session revoked',
	PasswordSet: 'Password set',
	CredentialAdded: 'Credential added',
	UserCreated: 'Account created',
	UserDeleted: 'Account deleted',
	UserDeactivated: 'Account deactivated',
	RelayOpen: 'Relay opened',
	RelayClose: 'Relay closed',
	GetRecording: 'Played a recording',
	RecordingScrubFailed: 'Recording scrub failed',
	AddSubjectsToPrincipal: 'Granted access',
	RemoveSubjectsFromPrincipal: 'Revoked access',
	RevokeAllAccess: 'Revoked all access',
	AddPrincipal: 'Added login account',
	RemovePrincipal: 'Removed login account'
};

/** "DeleteTarget" reads as "Delete target". */
export function eventLabel(action: string) {
	if (labels[action]) return labels[action];
	const words = action.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(' ');
	return words.map((w, i) => (i === 0 || /^[A-Z0-9]{2,}$/.test(w) ? w : w.toLowerCase())).join(' ');
}

export function outcomeOf(log: EventLog): 'succeeded' | 'failed' | 'denied' {
	if (log.ok) return 'succeeded';
	const code = log.details?.['code'];
	if (log.action === 'LoginDenied' || code === 'permission_denied' || code === 'unauthenticated') {
		return 'denied';
	}
	return 'failed';
}

export function formatTime(ts: Timestamp | undefined, utc: boolean) {
	if (!ts) return '';
	return new Intl.DateTimeFormat(undefined, {
		month: 'short',
		day: 'numeric',
		year: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: false,
		timeZone: utc ? 'UTC' : undefined,
		timeZoneName: utc ? 'short' : undefined
	}).format(timestampDate(ts));
}

export const csv = (param: string) =>
	page.url.searchParams.get(param)?.split(',').filter(Boolean) ?? [];

// setParams changes filters and goes back to page 1, since the result set moved.
export function setParams(params: Record<string, string | undefined>, replaceFilters = false) {
	const url = new URL(page.url);
	if (replaceFilters) filterParams.forEach((p) => url.searchParams.delete(p));
	for (const [key, value] of Object.entries(params)) {
		if (value) url.searchParams.set(key, value);
		else url.searchParams.delete(key);
	}
	url.searchParams.delete(PAGE_PARAM);
	void goto(url, { replaceState: true, keepFocus: true, noScroll: true });
}

export const kindIcon = (kind: string): LucideIcon => kindOf(kind)?.icon ?? KeyRound;
