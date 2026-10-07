<script lang="ts">
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { team } from '#lib/api/team.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/principal_pb.js';
	import SubjectAvatar from './SubjectAvatar.svelte';
	import {
		fromUser,
		fromServiceAccount,
		fromTeam,
		kindLabels,
		subjectHref,
		type SubjectRef
	} from './subjects.svelte';

	interface Props {
		grant: SubjectRef;
		onRemove?: () => void;
		muted?: boolean;
	}

	let { grant, onRemove, muted = false }: Props = $props();

	// Each lookup is cached, so a subject granted on many accounts loads once.
	const idFor = (kind: SubjectKind) => () =>
		!grant.subject && grant.kind === kind ? grant.id : undefined;
	const person = users.get(idFor(SubjectKind.USER));
	const teamQuery = team.get(idFor(SubjectKind.TEAM));
	const sa = serviceAccount.get(idFor(SubjectKind.SERVICE_ACCOUNT));

	const subject = $derived.by(() => {
		if (grant.subject) return grant.subject;
		if (person.data) return fromUser(person.data);
		if (teamQuery.data) return fromTeam(teamQuery.data);
		if (sa.data) return fromServiceAccount(sa.data);
		const failed = person.isError || teamQuery.isError || sa.isError;
		return {
			id: grant.id,
			kind: grant.kind,
			name: failed ? `Deleted ${kindLabels[grant.kind].one}` : '…',
			detail: grant.id
		};
	});
</script>

<Chip
	label={subject.name}
	href={subjectHref(grant.kind, grant.id)}
	title={`${subject.name} · ${subject.detail}`}
	{muted}
	{onRemove}
	removeLabel={`Revoke ${subject.name}`}
>
	{#snippet leading()}
		<SubjectAvatar {subject} class="size-6" />
	{/snippet}
</Chip>
