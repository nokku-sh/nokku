<script lang="ts">
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
	import SubjectChip from '#lib/components/access/SubjectChip.svelte';
	import { fromServiceAccount, fromUser } from '#lib/components/access/subjects.svelte.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';

	let { subjectId }: { subjectId: string } = $props();

	// A session is a user or a service account. The recording only holds the
	// id, so the user is tried first and the service account on a miss.
	const person = users.get(() => subjectId || undefined);
	const sa = serviceAccount.get(() => (person.isError ? subjectId : undefined));
	const subject = $derived(
		person.data ? fromUser(person.data) : sa.data ? fromServiceAccount(sa.data) : undefined
	);
</script>

{#if subjectId}
	<SubjectChip grant={{ id: subjectId, kind: subject?.kind ?? SubjectKind.USER, subject }} muted />
{:else}
	<span class="text-muted-foreground">-</span>
{/if}
