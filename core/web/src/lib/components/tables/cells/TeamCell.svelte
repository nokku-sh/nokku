<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { team } from '#lib/api/team.svelte.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Users } from '@lucide/svelte';

	let { userId }: { userId: string } = $props();

	const teams = team.listForUser(() => userId);
	const count = $derived(teams.data?.length ?? 0);
</script>

<Badge variant={count ? 'secondary' : 'outline'} class="gap-1.5 text-xs">
	<Users class="size-3" />
	{count ? plural(count, 'team') : 'No teams'}
</Badge>
