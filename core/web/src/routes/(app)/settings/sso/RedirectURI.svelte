<script lang="ts">
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';

	let { id }: { id: string } = $props();

	const baseUrl = workspace.baseUrl();
</script>

<Field.Field>
	{#if baseUrl.data}
		<InputGroupVariants
			variant="copy-input"
			value={`${baseUrl.data}/oidc/callback`}
			readonly
			class="font-mono text-xs"
			copyLabel="redirect URI"
			inputProps={{ id, 'aria-label': 'Redirect URI' }}
		/>
	{:else if baseUrl.isError}
		<p class="flex flex-wrap items-center gap-2 text-sm text-destructive" role="alert">
			The workspace address did not load.
			<Button variant="outline" size="sm" onclick={() => baseUrl.refetch()}>Try again</Button>
		</p>
	{:else}
		<Skeleton class="h-8 w-full" />
	{/if}
	<Field.Description>
		Okta calls it the sign-in redirect URI, Entra ID a web redirect URI, Google an authorized
		redirect URI.
	</Field.Description>
</Field.Field>
