<script lang="ts">
	import { sso } from '#lib/api/sso.svelte.js';
	import InputGroupVariants from '#lib/components/blocks/InputGroupVariants.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';

	let { id }: { id: string } = $props();

	const uri = sso.redirectUri();
</script>

<Field.Field>
	<Field.Label for={id}>Redirect URI</Field.Label>
	{#if uri.data}
		<InputGroupVariants
			variant="copy-input"
			value={uri.data}
			readonly
			class="font-mono text-xs"
			copyLabel="redirect URI"
			inputProps={{ id }}
		/>
	{:else if uri.isError}
		<p class="flex flex-wrap items-center gap-2 text-sm text-destructive" role="alert">
			The redirect URI did not load.
			<Button variant="outline" size="sm" onclick={() => uri.refetch()}>Try again</Button>
		</p>
	{:else}
		<Skeleton class="h-8 w-full" />
	{/if}
	<Field.Description>
		Register it with the provider. Okta calls it the sign-in redirect URI, Entra ID a web redirect
		URI, Google an authorized redirect URI.
	</Field.Description>
</Field.Field>
