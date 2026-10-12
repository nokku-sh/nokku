<script lang="ts">
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
	import SubjectChip from '#lib/components/access/SubjectChip.svelte';
	import { fromServiceAccount, fromUser } from '#lib/components/access/subjects.svelte.js';
	import Chip from '#lib/components/blocks/Chip.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';

	let { subjectId, name }: { subjectId: string; name: string } = $props();

	// The account gives the avatar and the link. The user is tried first and the service account on a miss.
	const person = users.get(() => subjectId || undefined);
	const sa = serviceAccount.get(() => (person.isError ? subjectId : undefined));
	const subject = $derived(
		person.data ? fromUser(person.data) : sa.data ? fromServiceAccount(sa.data) : undefined
	);
	// Both missed, so the account is gone and the name the recording kept stands in.
	const gone = $derived(person.isError && sa.isError);
</script>

{#if !subjectId}
	<span class="text-muted-foreground">-</span>
{:else if gone && name}
	<Chip label={name} title="This account no longer exists" muted />
{:else}
	<SubjectChip grant={{ id: subjectId, kind: subject?.kind ?? SubjectKind.USER, subject }} muted />
{/if}
