<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { openGrant, subjectLabel } from '#lib/components/access/grant.svelte.js';
	import SubjectAvatar from '#lib/components/access/SubjectAvatar.svelte';
	import { subjectHref, type Subject } from '#lib/components/access/subjects.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import type { EndingGrant } from '#lib/gen/nokku/v1/dashboard_pb.js';
	import { formatTs } from '#lib/utils.js';

	let { grants, total, canEdit }: { grants: EndingGrant[]; total: number; canEdit: boolean } =
		$props();

	// Past a day, so the row leaves this list once extended.
	const EXTEND_HOURS = 24 * 7;

	const has = useFeatures();
	const more = $derived(total - grants.length);
	// Without the plan the sheet only grants for good, which is no extend.
	const canExtend = $derived(canEdit && has('expiring_access') === true);

	const subjectOf = (g: EndingGrant): Subject => ({
		id: g.subjectId,
		kind: g.subjectKind,
		name: g.subjectName,
		detail: ''
	});
	const where = (g: EndingGrant) =>
		g.targetCount === 1 ? (g.targets[0]?.name ?? '') : plural(g.targetCount, 'server');

	function extend(g: EndingGrant) {
		openGrant({
			subjects: [subjectOf(g)],
			servers: g.targets,
			account: g.username,
			hours: EXTEND_HOURS,
			changeEnds: true
		});
	}
</script>

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title class="flex items-center gap-2">
			<h2>Ending soon</h2>
			<Badge variant="warning">{total}</Badge>
		</Card.Title>
		<Card.Description>Grants that end by themselves within a day.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-2">
		<Item.Group class="divide-y rounded-lg border">
			{#each grants as g (`${g.subjectId}:${g.username}:${g.expiresAt?.seconds}.${g.expiresAt?.nanos}`)}
				{@const subject = subjectOf(g)}
				<Item.Root size="xs" class="rounded-none">
					<Item.Media><SubjectAvatar {subject} class="size-6" /></Item.Media>
					<Item.Content class="min-w-0">
						<Item.Title class="w-full">
							<a href={subjectHref(g.subjectKind, g.subjectId)} class="truncate hover:underline">
								{subjectLabel(subject)}
							</a>
						</Item.Title>
						<Item.Description class="truncate text-xs">
							<span class="font-mono">{g.username}</span> on {where(g)}
						</Item.Description>
					</Item.Content>
					<Item.Actions>
						<span class="font-mono text-xs whitespace-nowrap text-warning">
							{formatTs(g.expiresAt, 'relative-short')}
						</span>
						{#if canExtend}
							<!-- The dashboard sends only the first servers, an extend from those would miss the rest. -->
							{#if g.targetCount > g.targets.length}
								<Button
									size="sm"
									variant="outline"
									href={`${subjectHref(g.subjectKind, g.subjectId)}&tab=access`}
									aria-label={`See all ${g.targetCount} servers of ${subjectLabel(subject)}`}
								>
									See all {g.targetCount}
								</Button>
							{:else}
								<Button
									size="sm"
									variant="outline"
									aria-label={`Extend ${g.username} for ${subjectLabel(subject)}`}
									onclick={() => extend(g)}
								>
									Extend
								</Button>
							{/if}
						{/if}
					</Item.Actions>
				</Item.Root>
			{/each}
		</Item.Group>
		{#if more > 0}
			<p class="text-xs text-muted-foreground">And {more} more within the day.</p>
		{/if}
	</Card.Content>
</Card.Root>
