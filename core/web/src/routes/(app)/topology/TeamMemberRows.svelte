<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { team } from '#lib/api/team.svelte.js';
	import SubjectAvatar from '#lib/components/access/SubjectAvatar.svelte';
	import { fromUser, subjectHref } from '#lib/components/access/subjects.svelte.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import type { AccessMatrixRow } from '#lib/gen/nokku/v1/target_pb.js';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { cn } from '#lib/utils.js';

	let { row, tags }: { row: AccessMatrixRow; tags: string[] } = $props();

	const SHOWN = 20;

	const members = team.members(() => row.subjectId);
	// Deactivated people still count as members but can't log in, so they go last and get nothing.
	const people = $derived(
		[...(members.data ?? [])].sort((a, b) => Number(b.active) - Number(a.active))
	);
	const held = $derived(new Set(row.cells.map((c) => c.tag)));
</script>

{#if members.isLoading || !people.length}
	<Table.Row class="hover:bg-transparent">
		<Table.Cell
			class="sticky left-0 z-10 max-w-40 border-b bg-card py-2 pl-10 text-xs text-muted-foreground sm:max-w-64"
		>
			{#if members.isLoading}
				<Skeleton class="h-4 w-32" />
			{:else}
				No members yet, so nobody gets this.
			{/if}
		</Table.Cell>
		<Table.Cell colspan={tags.length} class="border-b"></Table.Cell>
	</Table.Row>
{:else}
	{#each people.slice(0, SHOWN) as u (u.id)}
		{@const m = fromUser(u)}
		<Table.Row class="hover:bg-transparent">
			<Table.Head
				scope="row"
				class="sticky left-0 z-10 max-w-40 border-b bg-card py-1.5 pl-10 font-normal sm:max-w-64"
			>
				<a
					href={`${subjectHref(SubjectKind.USER, m.id)}&tab=access`}
					class={cn(
						'flex min-w-0 items-center gap-2 rounded-sm hover:underline',
						!u.active && 'text-muted-foreground'
					)}
				>
					<SubjectAvatar subject={m} class={cn('size-5', !u.active && 'opacity-50')} />
					<span class="flex min-w-0 flex-col">
						<span class="truncate text-xs font-medium">{m.name}</span>
						{#if !u.active}
							<span class="text-2xs text-muted-foreground">deactivated</span>
						{:else if m.detail !== m.name}
							<span class="truncate text-2xs text-muted-foreground">{m.detail}</span>
						{/if}
					</span>
				</a>
			</Table.Head>
			{#each tags as tag (tag)}
				<Table.Cell class="border-b p-1 text-center text-2xs text-muted-foreground">
					{#if u.active && held.has(tag)}via team{/if}
				</Table.Cell>
			{/each}
		</Table.Row>
	{/each}
	{#if people.length > SHOWN}
		<Table.Row class="hover:bg-transparent">
			<Table.Cell
				class="sticky left-0 z-10 max-w-40 border-b bg-card py-2 pl-10 text-xs sm:max-w-64"
			>
				<a href={subjectHref(SubjectKind.TEAM, row.subjectId)} class="hover:underline">
					{plural(people.length - SHOWN, 'more member')} in the team
				</a>
			</Table.Cell>
			<Table.Cell colspan={tags.length} class="border-b"></Table.Cell>
		</Table.Row>
	{/if}
{/if}
