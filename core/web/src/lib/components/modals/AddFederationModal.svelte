<script lang="ts" module>
	export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
	export const GITLAB_ISSUER = 'https://gitlab.com';

	type Claim = { name: string; placeholder?: string };

	const presets: { value: string; label: string; issuer: string; claims: Claim[]; hint: string }[] =
		[
			{
				value: 'github',
				label: 'GitHub Actions',
				issuer: GITHUB_ISSUER,
				claims: [
					{ name: 'repository_id', placeholder: '123456789' },
					{ name: 'environment', placeholder: 'production' }
				],
				hint: 'Needs repository_id plus environment or ref, like refs/heads/main. repository_id alone covers every branch and pull request, and a repository name can be registered again by someone else. An environment only limits a job if it is protected in GitHub.'
			},
			{
				value: 'gitlab',
				label: 'GitLab',
				issuer: GITLAB_ISSUER,
				claims: [
					{ name: 'project_id', placeholder: '123456' },
					{ name: 'environment', placeholder: 'production' }
				],
				hint: 'Needs project_id plus environment, ref_path like refs/heads/main, or ref with ref_type. project_id alone covers every branch and merge request, and a ref alone also matches a tag of that name. An environment only limits a job if it is protected in GitLab.'
			},
			{
				value: 'custom',
				label: 'Custom',
				issuer: '',
				claims: [{ name: 'sub', placeholder: 'the subject of the job' }],
				hint: 'Needs sub. Every claim you list has to match exactly, as a string. The issuer must serve OpenID discovery over https.'
			}
		];
</script>

<script lang="ts">
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import { Plus, Trash2, Workflow } from '@lucide/svelte';

	let {
		open = $bindable(false),
		serviceAccountId,
		name
	}: { open?: boolean; serviceAccountId: string; name: string } = $props();

	const add = saApi.federations.add();

	let rowId = 0;
	const row = (claim: Partial<Claim> = {}) => ({
		id: rowId++,
		name: claim.name ?? '',
		value: '',
		placeholder: claim.placeholder
	});

	let preset = $state(presets[0]);
	let issuer = $state(presets[0].issuer);
	let rows = $state(presets[0].claims.map(row));

	const names = $derived(rows.map((r) => r.name.trim()));
	const ready = $derived(
		!!issuer.trim() &&
			rows.every((r) => r.name.trim() && r.value.trim()) &&
			new Set(names).size === names.length
	);

	function pick(value: string) {
		const next = presets.find((p) => p.value === value);
		if (!next) return;
		preset = next;
		issuer = next.issuer;
		rows = next.claims.map(row);
	}

	async function onSubmit() {
		await add.mutateAsync({
			serviceAccountId,
			issuer: issuer.trim(),
			claims: Object.fromEntries(rows.map((r) => [r.name.trim(), r.value.trim()]))
		});
		pick(presets[0].value);
	}
</script>

<FormModal
	bind:open
	title={`New rule for ${name}`}
	description="A job that matches signs in as this account with its platform's own token. Nothing is stored in CI."
	icon={Workflow}
	submitLabel="Add rule"
	submitDisabled={!ready}
	{onSubmit}
>
	<Field.Set>
		<Field.Legend variant="label">Platform</Field.Legend>
		<ToggleGroup.Root
			type="single"
			variant="outline"
			size="sm"
			value={preset.value}
			onValueChange={(v) => v && pick(v)}
			class="w-full flex-wrap"
		>
			{#each presets as p (p.value)}
				<ToggleGroup.Item value={p.value} class="flex-1">{p.label}</ToggleGroup.Item>
			{/each}
		</ToggleGroup.Root>
		<Field.Description>{preset.hint}</Field.Description>
	</Field.Set>

	<Field.Field>
		<Field.Label for="new-rule-issuer">Issuer</Field.Label>
		<Input
			id="new-rule-issuer"
			class="font-mono"
			bind:value={issuer}
			readonly={preset.value !== 'custom'}
			placeholder="https://ci.example.com"
			maxlength={512}
			required
		/>
	</Field.Field>

	<Field.Set>
		<Field.Legend variant="label">Claims</Field.Legend>
		<Field.Group class="gap-2">
			{#each rows as r, i (r.id)}
				<div class="flex items-center gap-2">
					<Input
						class="flex-1 font-mono"
						aria-label={`Claim ${i + 1} name`}
						bind:value={r.name}
						placeholder="claim"
						maxlength={128}
					/>
					<Input
						class="flex-1 font-mono"
						aria-label={`Claim ${i + 1} value`}
						bind:value={r.value}
						placeholder={r.placeholder ?? 'value'}
						maxlength={512}
					/>
					<Button
						variant="ghost"
						size="icon-sm"
						aria-label={`Remove claim ${i + 1}`}
						disabled={rows.length === 1}
						onclick={() => (rows = rows.filter((other) => other.id !== r.id))}
					>
						<Trash2 />
					</Button>
				</div>
			{/each}
		</Field.Group>
		<Button
			class="self-start"
			variant="outline"
			size="sm"
			onclick={() => (rows = [...rows, row()])}
		>
			<Plus data-icon="inline-start" />
			Add a claim
		</Button>
	</Field.Set>
</FormModal>
