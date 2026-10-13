<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Users } from '@lucide/svelte';

	let { memberCount = 0 }: { memberCount?: number } = $props();
</script>

<Badge variant={memberCount ? 'secondary' : 'outline'} class="gap-1.5 text-xs">
	<Users class="size-3" />
	{memberCount ? plural(memberCount, 'member') : 'No members'}
</Badge>
