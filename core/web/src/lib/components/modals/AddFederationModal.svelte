<script lang="ts" module>
	export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
	export const GITLAB_ISSUER = 'https://gitlab.com';

	type Platform = 'github' | 'gitlab' | 'other';

	const platforms: { value: Platform; label: string }[] = [
		{ value: 'github', label: 'GitHub' },
		{ value: 'gitlab', label: 'GitLab' },
		{ value: 'other', label: 'Other' }
	];

	const refOf = (branch: string) => (branch.startsWith('refs/') ? branch : `refs/heads/${branch}`);
</script>

<script lang="ts">
	import { serviceAccount as saApi } from '#lib/api/service_account.svelte.js';
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import CodeSnippet from '#lib/components/blocks/CodeSnippet.svelte';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
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
	const baseUrl = workspace.baseUrl();

	let rowId = 0;
	const row = (claimName = '') => ({ id: rowId++, name: claimName, value: '' });

	let platform = $state<Platform>('github');
	let projectId = $state('');
	let scope = $state<'branch' | 'environment'>('branch');
	let branch = $state('main');
	let environment = $state('');
	let issuer = $state('');
	let rows = $state([row('sub')]);

	const github = $derived(platform === 'github');
	const platformLabel = $derived(github ? 'GitHub' : 'GitLab');
	const scopeValue = $derived((scope === 'branch' ? branch : environment).trim());
	const names = $derived(rows.map((r) => r.name.trim()));

	const ready = $derived(
		platform === 'other'
			? !!issuer.trim() &&
					rows.every((r) => r.name.trim() && r.value.trim()) &&
					new Set(names).size === names.length
			: /^\d+$/.test(projectId.trim()) && !!scopeValue
	);

	const claims = $derived.by((): Record<string, string> => {
		if (platform === 'other') {
			return Object.fromEntries(rows.map((r) => [r.name.trim(), r.value.trim()]));
		}
		const id = { [github ? 'repository_id' : 'project_id']: projectId.trim() };
		if (scope === 'environment') return { ...id, environment: scopeValue };
		return { ...id, [github ? 'ref' : 'ref_path']: refOf(scopeValue) };
	});

	const snippet = $derived.by(() => {
		const url = baseUrl.data;
		if (!url) return undefined;
		const env = scope === 'environment' && scopeValue ? `environment: ${scopeValue}\n` : '';
		const install = 'curl -fsSL https://get.nokku.sh/nk | sh';
		const login = `nk login --ci ${name}`;
		if (platform === 'github') {
			return {
				language: 'yaml',
				code: `${env}permissions:\n  contents: read\n  id-token: write\nenv:\n  NK_API_URL: ${url}\nsteps:\n  - run: ${install}\n  - run: ${login}`
			};
		}
		if (platform === 'gitlab') {
			return {
				language: 'yaml',
				code: `${env}variables:\n  NK_API_URL: ${url}\nid_tokens:\n  NK_ID_TOKEN:\n    aud: ${url}\nscript:\n  - ${install}\n  - ${login}`
			};
		}
		return {
			language: 'bash',
			code: `export NK_API_URL=${url}\nexport NK_ID_TOKEN=<the job's token, with ${url} as aud>\n${login}`
		};
	});

	function reset() {
		platform = 'github';
		projectId = '';
		scope = 'branch';
		branch = 'main';
		environment = '';
		issuer = '';
		rows = [row('sub')];
	}

	async function onSubmit() {
		await add.mutateAsync({
			serviceAccountId,
			issuer:
				platform === 'github'
					? GITHUB_ISSUER
					: platform === 'gitlab'
						? GITLAB_ISSUER
						: issuer.trim(),
			claims
		});
		reset();
	}
</script>

<FormModal
	bind:open
	title={`New rule for ${name}`}
	classModal="sm:max-w-lg"
	description="Lets a CI job sign in as this account. No secret goes into CI."
	icon={Workflow}
	submitLabel="Add rule"
	submitDisabled={!ready}
	{onSubmit}
>
	<ToggleGroup.Root
		type="single"
		variant="outline"
		size="sm"
		value={platform}
		onValueChange={(v) => v && (platform = v as Platform)}
		class="w-full"
		aria-label="Platform"
	>
		{#each platforms as p (p.value)}
			<ToggleGroup.Item value={p.value} class="flex-1">{p.label}</ToggleGroup.Item>
		{/each}
	</ToggleGroup.Root>

	{#if platform === 'other'}
		<Field.Field>
			<Field.Label for="new-rule-issuer">Issuer</Field.Label>
			<Input
				id="new-rule-issuer"
				class="font-mono"
				bind:value={issuer}
				placeholder="https://ci.example.com"
				maxlength={512}
				required
			/>
		</Field.Field>

		<Field.Set>
			<Field.Legend variant="label">Claims</Field.Legend>
			<Field.Description>The job's token must match each one exactly.</Field.Description>
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
							placeholder="value"
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
	{:else}
		<Field.Field>
			<Field.Label for="new-rule-project">{github ? 'Repository ID' : 'Project ID'}</Field.Label>
			<Input
				id="new-rule-project"
				class="font-mono"
				bind:value={projectId}
				inputmode="numeric"
				placeholder={github ? '123456789' : '123456'}
				maxlength={32}
				required
			/>
			<Field.Description>
				{#if github}
					Run <CopyText value="gh api repos/OWNER/REPO --jq .id" mono />, or in a job
					<CopyText value="echo $GITHUB_REPOSITORY_ID" mono />
				{:else}
					In a job, run <CopyText value="echo $CI_PROJECT_ID" mono />
				{/if}
			</Field.Description>
		</Field.Field>

		<Field.Set>
			<Field.Legend variant="label">Jobs from</Field.Legend>
			<ToggleGroup.Root
				type="single"
				variant="outline"
				size="sm"
				value={scope}
				onValueChange={(v) => v && (scope = v as typeof scope)}
				class="w-full"
				aria-label="Jobs from"
			>
				<ToggleGroup.Item value="branch" class="flex-1">A branch</ToggleGroup.Item>
				<ToggleGroup.Item value="environment" class="flex-1">An environment</ToggleGroup.Item>
			</ToggleGroup.Root>
			{#if scope === 'branch'}
				<Input
					class="font-mono"
					aria-label="Branch"
					bind:value={branch}
					placeholder="main"
					maxlength={256}
				/>
			{:else}
				<Input
					class="font-mono"
					aria-label="Environment"
					bind:value={environment}
					placeholder="production"
					maxlength={256}
				/>
				<Field.Description>
					Protect it in {platformLabel}, or any branch can use it.
				</Field.Description>
			{/if}
		</Field.Set>
	{/if}

	{#if snippet}
		<!-- A fieldset is min-content wide by default, so the code would widen the dialog instead of scrolling. -->
		<Field.Set class="min-w-0">
			<Field.Legend variant="label">Add to the job</Field.Legend>
			<CodeSnippet language={snippet.language} code={snippet.code} />
		</Field.Set>
	{/if}
</FormModal>
