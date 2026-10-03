<script lang="ts">
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { statusTone } from '#lib/tone.js';

	let { status }: { status: string } = $props();
</script>

<Badge variant={statusTone(status)} class="capitalize">{status}</Badge>
