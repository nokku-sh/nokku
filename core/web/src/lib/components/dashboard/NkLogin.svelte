<script lang="ts">
	import { util } from '#lib/api/workspaces.svelte.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import { DocsURL } from '#lib/config.js';
	import { nkLoginCommand } from '#lib/utils.js';

	const info = util.instanceInfo();
	const login = $derived(nkLoginCommand(info.data?.caPin));
</script>

<p class="text-sm text-muted-foreground">
	Sign the CLI in once. After that plain <code class="font-mono">ssh</code> just works.
</p>
<CodeSnippet code={login} language="bash" />
<a
	href={DocsURL}
	target="_blank"
	rel="noopener"
	class="self-start text-sm text-primary hover:underline"
>
	Install nk
</a>
