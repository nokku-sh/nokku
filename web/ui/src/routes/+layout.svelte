<script lang="ts">
	import { authTransport, queryClient } from '$lib/api/client';
	import { Toaster } from '$lib/components/ui/sonner';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import ConfirmDialog from '$lib/components/blocks/ConfirmDialog.svelte';
	import { setTransport } from '$lib/query';
	import { QueryClientProvider } from '@tanstack/svelte-query';
	import { ModeWatcher } from 'mode-watcher';
	import './layout.css';

	let { children } = $props();
	setTransport(authTransport);
</script>

<ModeWatcher />
<Toaster />

<!-- App wide, so tooltips also work outside the sidebar, e.g. in ConfirmDialog. -->
<Tooltip.Provider>
	<ConfirmDialog />

	<QueryClientProvider client={queryClient}>
		{@render children?.()}
	</QueryClientProvider>
</Tooltip.Provider>
