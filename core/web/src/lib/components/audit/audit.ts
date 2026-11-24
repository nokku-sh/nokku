import { page } from '$app/state';
import { plural } from '#lib/api/bulk.js';
import { sessionMethodLabel } from '#lib/api/session.svelte.js';
import { SignInMethod } from '#lib/gen/nokku/v1/account_pb.js';
import { ActorKind, type AuditEvent, AuditOutcome } from '#lib/gen/nokku/v1/audit_log_pb.js';
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
			'Grant',
			'Revoke',
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
			'SetUserRole',
			'DeactivateUser',
			'ReactivateUser',
			'DeleteUser',
			'TransferOwnership',
			'AcceptInvitation',
			'CreateTeam',
			'UpdateTeam',
			'OpenTeamToSCIM',
			'CloseTeamToSCIM',
			'DeleteTeam',
			'AddTeamMember',
			'RemoveTeamMember',
			'CreateServiceAccount',
			'UpdateServiceAccount',
			'SetServiceAccountRole',
			'SetServiceAccountLimits',
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
			'RenameTarget',
			'SetTargetEndpoints',
			'DeleteTarget',
			'SyncTargetUsers',
			'ForgetHostKey',
			'EnrollDaemon',
			'UpdateDaemon',
			'SetDaemonSafeguards',
			'SetDefaultSafeguards',
			'DaemonBehind',
			'DeleteDaemon',
			'ApproveDaemon',
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
			'SetEnforceSSO',
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

/** `value` is the URL param, `label` names the group in filters, `one` names a single actor in a row. */
export const actorKinds: {
	value: string;
	kind: ActorKind;
	label: string;
	one: string;
	icon: LucideIcon;
}[] = [
	{ value: 'user', kind: ActorKind.USER, label: 'People', one: 'Person', icon: CircleUser },
	{ value: 'cli', kind: ActorKind.CLI, label: 'CLI', one: 'CLI', icon: Terminal },
	{
		value: 'service_account',
		kind: ActorKind.SERVICE_ACCOUNT,
		label: 'Service accounts',
		one: 'Service account',
		icon: Bot
	},
	{ value: 'daemon', kind: ActorKind.DAEMON, label: 'Daemons', one: 'Daemon', icon: Server },
	{ value: 'scim', kind: ActorKind.SCIM, label: 'SCIM', one: 'SCIM', icon: RefreshCw }
];
const kindOf = (kind: ActorKind) => actorKinds.find((k) => k.kind === kind);
export const kindName = (kind: ActorKind) =>
	kindOf(kind)?.one ?? (kind === ActorKind.SYSTEM ? 'System' : 'Unknown');

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
	Grant: 'Granted access',
	Revoke: 'Revoked access',
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
	RenameTarget: 'Renamed a server',
	SetTargetEndpoints: "Changed a server's endpoints",
	DeleteTarget: 'Deleted a server',
	SyncTargetUsers: 'Synced a server',
	ForgetHostKey: 'Forgot the host key of a server',
	UpdateDaemon: 'Changed a daemon',
	SetDaemonSafeguards: "Changed a daemon's safeguards",
	SetDefaultSafeguards: 'Changed the default safeguards',
	ApproveDaemon: 'Approved a server',
	DeleteDaemon: 'Deleted a daemon',
	CreateTeam: 'Created a team',
	UpdateTeam: 'Changed a team',
	OpenTeamToSCIM: 'Opened a team to SCIM',
	CloseTeamToSCIM: 'Closed a team to SCIM',
	DeleteTeam: 'Deleted a team',
	AddTeamMember: 'Added to a team',
	RemoveTeamMember: 'Removed from a team',
	SetUserRole: 'Changed a role',
	UpdateDaemonDefaults: 'Changed daemon defaults',
	SetEnforceSSO: 'Changed required single sign-on',
	DeleteUser: 'Removed a person'
};

const detail = (log: AuditEvent, key: string) => {
	const v = log.details?.[key];
	return typeof v === 'string' && v ? v : undefined;
};

/** How an event signed in. The details name it like "magic_link". */
export function eventMethod(log: AuditEvent) {
	const name = detail(log, 'method');
	const method = name && SignInMethod[name.toUpperCase() as keyof typeof SignInMethod];
	return method ? sessionMethodLabel(method) : name;
}

const strings = (log: AuditEvent, key: string) => {
	const v = log.details?.[key];
	return (Array.isArray(v) ? v : []).filter((s): s is string => typeof s === 'string' && s !== '');
};

const subjectPrefix: Record<string, string> = { team: 'team:', service_account: 'sa:' };

/** What an event touched, in words, from the names it stored. Older events only hold ids and get undefined. */
export function eventWhat(log: AuditEvent): string | undefined {
	const name = detail(log, 'name');
	const server = detail(log, 'target');
	const account = detail(log, 'username');
	const prefix = subjectPrefix[detail(log, 'subject_kind') ?? ''] ?? '';
	const who = strings(log, 'subjects')
		.map((s) => prefix + s)
		.join(', ');
	const on = account && server ? `${account} on ${server}` : undefined;

	switch (log.action) {
		case 'GrantExpired':
			return on && (who ? `${on} for ${who}` : on);
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
			const accounts = (account ?? strings(log, 'usernames').join(', ')) || 'No grant';
			const where = log.details?.['everywhere']
				? ['everywhere']
				: [...strings(log, 'tags'), ...strings(log, 'targets')];
			const servers = `${plural(count, 'server')}${where.length ? ` (${listNames(where)})` : ''}`;
			return `${accounts} on ${servers} ${log.action === 'Grant' ? 'to' : 'from'} ${who}`;
		}
		case 'AddTeamMember':
		case 'RemoveTeamMember': {
			const member = detail(log, 'member');
			const to = log.action === 'AddTeamMember' ? 'to' : 'from';
			return member && name ? `${member} ${to} ${name}` : name;
		}
		case 'SetUserRole': {
			const role = detail(log, 'role');
			return name && role ? `${name} to ${role}` : name;
		}
	}
	return name ?? on;
}

/** Where an event came from. For a login that is the client the daemon saw, not the daemon that reported it. */
export function eventSource(log: AuditEvent): string {
	const remote = detail(log, 'remote');
	if (!remote || !log.action.startsWith('Connection')) return log.ip;
	// Without the port, "[::1]:22" and "10.0.0.1:22" alike.
	return remote.replace(/:\d+$/, '').replace(/^\[(.*)\]$/, '$1');
}

/** When a reported login happened by the daemon's clock, if the core only heard of it over a minute later. */
export function eventHappened(log: AuditEvent): Timestamp | undefined {
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

export function outcomeOf(log: AuditEvent): Outcome {
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

export const kindIcon = (kind: ActorKind): LucideIcon => kindOf(kind)?.icon ?? KeyRound;

/** Failures and denials read as destructive, successes stay quiet. */
export const outcomeLabel: Record<Outcome, string> = {
	succeeded: 'Succeeded',
	failed: 'Failed',
	denied: 'Denied'
};
