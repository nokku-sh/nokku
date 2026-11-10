import { page } from '$app/state';
import { plural } from '#lib/api/bulk.js';
import { AuditOutcome, type EventLog } from '#lib/gen/nokku/v1/util_pb.js';
import { setFilters } from '#lib/hooks/index.js';
import { listNames } from '#lib/utils.js';
import { timestampDate, timestampFromDate, type Timestamp } from '@bufbuild/protobuf/wkt';
import {
	Bot,
	CircleCheck,
	CircleUser,
	CircleX,
	KeyRound,
	LogIn,
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
			'AddSubjects',
			'RemoveSubjects',
			'Grant',
			'Revoke',
			'RevokeAllAccess',
			'AddTargetAccount',
			'RemoveTargetAccount',
			'GrantExpired',
			'CreateAccessRequest',
			'ApproveAccessRequest',
			'DenyAccessRequest',
			'CancelAccessRequest',
			'AccessRequestExpired',
			'SetRequestableTags',
			'ExportAccessReport'
		]
	},
	{
		value: 'people',
		label: 'People & roles',
		icon: Users,
		actions: [
			'UpdateUserRole',
			'SetUserActive',
			'DeleteUser',
			'TransferOwnership',
			'AcceptInvitation',
			'CreateTeam',
			'UpdateTeam',
			'DeleteTeam',
			'AddTeamMember',
			'RemoveTeamMember',
			'CreateServiceAccount',
			'UpdateServiceAccount',
			'DeleteServiceAccount',
			'CreateServiceAccountToken',
			'RevokeServiceAccountToken',
			'AddServiceAccountFederation',
			'RemoveServiceAccountFederation',
			'ExchangeWorkloadToken',
			'CreateJoinToken',
			'DeleteJoinToken',
			'UserCreated',
			'UserDeleted',
			'UserActivated',
			'UserDeactivated'
		]
	},
	{
		value: 'infrastructure',
		label: 'Servers',
		icon: Server,
		actions: [
			'CreateTarget',
			'UpdateTarget',
			'DeleteTarget',
			'SyncTargetUsers',
			'EnrollDaemon',
			'UpdateDaemon',
			'DaemonBehind',
			'DeleteDaemon',
			'ApproveDaemon',
			'RejectDaemon',
			'UpdateDaemonDefaults'
		]
	},
	{
		value: 'certificates',
		label: 'Certificates',
		icon: Shield,
		actions: ['UpdateCertificateAuthority', 'RolloverCertificateAuthority', 'SignSSHCertificate']
	},
	{
		value: 'sessions',
		label: 'Sessions',
		icon: SquareTerminal,
		actions: [
			'ConnectionOpen',
			'ConnectionClose',
			'ConnectionReportsDropped',
			'CreateSession',
			'RelayOpen',
			'RelayClose',
			'GetRecording'
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
			'CredentialAdded',
			'EmailChanged'
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
			'PutSSOProvider',
			'DeleteSSOProvider',
			'CreateSCIMToken',
			'DeleteSCIMToken',
			'CreateAuditStream',
			'UpdateAuditStream',
			'DeleteAuditStream',
			'TestAuditStream'
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

/** `label` names the group in filters, `one` names a single actor in a row. */
export const actorKinds: { value: string; label: string; one: string; icon: LucideIcon }[] = [
	{ value: 'user', label: 'People', one: 'Person', icon: CircleUser },
	{ value: 'cli', label: 'CLI', one: 'CLI', icon: Terminal },
	{ value: 'service_account', label: 'Service accounts', one: 'Service account', icon: Bot },
	{ value: 'daemon', label: 'Daemons', one: 'Daemon', icon: Server },
	{ value: 'scim', label: 'SCIM', one: 'SCIM', icon: RefreshCw }
];
export const kindOf = (kind: string) => actorKinds.find((k) => k.value === kind);

/** Params owned by the quick views, clicking one replaces all of them. */
const filterParams = ['q', 'area', 'outcome', 'kind', 'actor', 'target'];

export const quickViews: { label: string; params: Record<string, string> }[] = [
	{ label: 'Everything', params: {} },
	{ label: 'Access changes', params: { area: 'access' } },
	{ label: 'Server logins', params: { area: 'sessions' } },
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
	CredentialAdded: 'Credential added',
	EmailChanged: 'Email changed',
	UserCreated: 'Account created',
	UserDeleted: 'Account deleted',
	UserActivated: 'Account activated',
	UserDeactivated: 'Account deactivated',
	RelayOpen: 'Relay opened',
	RelayClose: 'Relay closed',
	// What a daemon reported from its server.
	ConnectionOpen: 'Logged in to a server',
	ConnectionClose: 'Left a server',
	ConnectionReportsDropped: 'Login reports lost',
	GetRecording: 'Played a recording',
	AddSubjects: 'Granted access',
	RemoveSubjects: 'Revoked access',
	Grant: 'Granted access',
	Revoke: 'Revoked access',
	RevokeAllAccess: 'Revoked all access',
	AddTargetAccount: 'Added login account',
	RemoveTargetAccount: 'Removed login account',
	GrantExpired: 'Access expired',
	CreateAccessRequest: 'Asked for access',
	ApproveAccessRequest: 'Approved a request',
	DenyAccessRequest: 'Denied a request',
	CancelAccessRequest: 'Cancelled a request',
	AccessRequestExpired: 'Request expired',
	SetRequestableTags: 'Changed requestable servers',
	ExportAccessReport: 'Exported the access report',
	// The API still says target, the UI says server.
	CreateTarget: 'Added a server',
	UpdateTarget: 'Changed a server',
	DeleteTarget: 'Deleted a server',
	SyncTargetUsers: 'Synced a server',
	UpdateDaemon: 'Changed a daemon',
	ApproveDaemon: 'Approved a server',
	RejectDaemon: 'Rejected a server',
	DeleteDaemon: 'Deleted a daemon',
	CreateTeam: 'Created a team',
	UpdateTeam: 'Changed a team',
	DeleteTeam: 'Deleted a team',
	AddTeamMember: 'Added to a team',
	RemoveTeamMember: 'Removed from a team',
	UpdateUserRole: 'Changed a role',
	UpdateDaemonDefaults: 'Changed daemon defaults',
	DeleteUser: 'Removed a person'
};

const detail = (log: EventLog, key: string) => {
	const v = log.details?.[key];
	return typeof v === 'string' && v ? v : undefined;
};

const strings = (log: EventLog, key: string) => {
	const v = log.details?.[key];
	return (Array.isArray(v) ? v : []).filter((s): s is string => typeof s === 'string' && s !== '');
};

const subjectPrefix: Record<string, string> = { team: 'team:', service_account: 'sa:' };

// How a grant event joins the account and the subjects, like "deploy on web-1 to Mia".
const grantWords: Record<string, string> = {
	AddSubjects: 'to',
	RemoveSubjects: 'from',
	GrantExpired: 'for'
};

/** What an event touched, in words, from the names it stored. Older events only hold ids and get undefined. */
export function eventWhat(log: EventLog): string | undefined {
	const name = detail(log, 'name');
	const server = detail(log, 'target');
	const account = detail(log, 'username');
	const prefix = subjectPrefix[detail(log, 'subject_kind') ?? ''] ?? '';
	const who = strings(log, 'subjects')
		.map((s) => prefix + s)
		.join(', ');
	const on = account && server ? `${account} on ${server}` : undefined;

	if (grantWords[log.action]) return on && (who ? `${on} ${grantWords[log.action]} ${who}` : on);
	switch (log.action) {
		case 'ConnectionOpen':
		case 'ConnectionClose': {
			const person = detail(log, 'subject');
			return person && on ? `${person} as ${on}` : (on ?? server);
		}
		case 'ConnectionReportsDropped': {
			const count = log.details?.['count'];
			return typeof count === 'number' && name ? `${plural(count, 'event')} on ${name}` : name;
		}
		case 'Grant':
		case 'Revoke': {
			// One event for many servers. It names the tags and the servers picked by name, and counts the rest.
			const count = log.details?.['servers'];
			if (typeof count !== 'number') return undefined;
			const accounts = account ?? strings(log, 'usernames').join(', ');
			const where = [...strings(log, 'tags'), ...strings(log, 'targets')];
			const servers = `${plural(count, 'server')}${where.length ? ` (${listNames(where)})` : ''}`;
			return `${accounts} on ${servers} ${log.action === 'Grant' ? 'to' : 'from'} ${who}`;
		}
		case 'RevokeAllAccess':
			return name && prefix + name;
		case 'AddTeamMember':
		case 'RemoveTeamMember': {
			const member = detail(log, 'member');
			const to = log.action === 'AddTeamMember' ? 'to' : 'from';
			return member && name ? `${member} ${to} ${name}` : name;
		}
		case 'UpdateUserRole': {
			const role = detail(log, 'role');
			return name && role ? `${name} to ${role}` : name;
		}
	}
	return name ?? on;
}

/** Where an event came from. For a login that is the client the daemon saw, not the daemon that reported it. */
export function eventSource(log: EventLog): string {
	const remote = detail(log, 'remote');
	if (!remote || !log.action.startsWith('Connection')) return log.ip;
	// Without the port, "[::1]:22" and "10.0.0.1:22" alike.
	return remote.replace(/:\d+$/, '').replace(/^\[(.*)\]$/, '$1');
}

/** When a reported login happened by the daemon's clock, if the core only heard of it over a minute later. */
export function eventHappened(log: EventLog): Timestamp | undefined {
	const at = Date.parse(detail(log, 'at') ?? '');
	if (!log.timestamp || Number.isNaN(at)) return undefined;
	const late = timestampDate(log.timestamp).getTime() - at > 60_000;
	return late ? timestampFromDate(new Date(at)) : undefined;
}

/** "DeleteTarget" reads as "Delete target". */
export function eventLabel(action: string) {
	if (labels[action]) return labels[action];
	const words = action.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(' ');
	return words.map((w, i) => (i === 0 || /^[A-Z0-9]{2,}$/.test(w) ? w : w.toLowerCase())).join(' ');
}

export type Outcome = 'succeeded' | 'failed' | 'denied';

export function outcomeOf(log: EventLog): Outcome {
	if (log.ok) return 'succeeded';
	const code = log.details?.['code'];
	if (log.action === 'LoginDenied' || code === 'permission_denied' || code === 'unauthenticated') {
		return 'denied';
	}
	return 'failed';
}

export const csv = (param: string) =>
	page.url.searchParams.get(param)?.split(',').filter(Boolean) ?? [];

// setParams can also drop every quick-view filter first.
export function setParams(params: Record<string, string | undefined>, replaceFilters = false) {
	const cleared = replaceFilters ? Object.fromEntries(filterParams.map((p) => [p, undefined])) : {};
	setFilters({ ...cleared, ...params });
}

export const kindIcon = (kind: string): LucideIcon => kindOf(kind)?.icon ?? KeyRound;

/** Failures and denials read as destructive, successes stay quiet. */
export const outcomeLabel: Record<Outcome, string> = {
	succeeded: 'Succeeded',
	failed: 'Failed',
	denied: 'Denied'
};
