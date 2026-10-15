<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { team } from '#lib/api/team.svelte.js';

	let { userId }: { userId: string } = $props();

	// The user list carries no team count, so each row asks. Fine at a page of rows.
	const teams = team.listForUser(() => userId);
	const count = $derived(teams.data?.length ?? 0);
</script>

<span class={['text-sm tabular-nums', !count && 'text-muted-foreground']}>
	{count ? plural(count, 'team') : 'No teams'}
</span>
