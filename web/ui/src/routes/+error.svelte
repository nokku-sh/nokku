<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';

	$effect(() => {
		if (page.status === 404) {
			goto('/');
		}
	});
</script>

{#if page.status !== 404}
	<div class="flex h-dvh flex-col items-center justify-center gap-4">
		<h1 class="text-4xl font-bold">{page.status}</h1>
		<p class="text-muted-foreground">{page.error?.message ?? 'Something went wrong'}</p>
	</div>
{/if}
