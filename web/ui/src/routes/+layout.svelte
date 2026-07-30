<script lang="ts">
	import { authTransport, queryClient } from '$lib/api/client';
	import { Toaster } from '$lib/components/ui/sonner';
	import { setTransport } from '$lib/query';
	import { QueryClientProvider } from '@tanstack/svelte-query';
	import { ModeWatcher } from 'mode-watcher';
	import './layout.css';

	let { children } = $props();
	setTransport(authTransport);
</script>

<ModeWatcher />
<Toaster />

<QueryClientProvider client={queryClient}>
	{@render children?.()}
</QueryClientProvider>
