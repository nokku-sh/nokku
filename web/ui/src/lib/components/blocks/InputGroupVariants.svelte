<script lang="ts">
	import * as InputGroup from '#lib/components/ui/input-group/index.js';
	import {
		CheckIcon,
		CopyIcon,
		SearchIcon,
		DeleteIcon,
		CodeIcon,
		EyeOffIcon,
		EyeIcon,
		DownloadIcon,
		type LucideIcon
	} from '@lucide/svelte';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import type { ComponentProps } from 'svelte';
	import type { Input } from '#lib/components/ui/input/index.js';

	type Variant = 'copy-input' | 'code-area' | 'search' | 'password';

	interface Props {
		variant: Variant;
		value?: string;
		placeholder?: string;
		readonly?: boolean;
		/** Header icon of the code area. */
		icon?: LucideIcon;
		codeHeader?: string;
		class?: string;
		searchResults?: number;
		downloadFilename?: string;
		inputProps?: ComponentProps<typeof Input>;
	}

	let {
		variant,
		value = $bindable(''),
		placeholder = '',
		readonly = false,
		icon: Icon = CodeIcon,
		codeHeader = 'bash',
		class: className = '',
		searchResults,
		downloadFilename,
		inputProps = {}
	}: Props = $props();

	const clipboard = new UseClipboard();

	let showPassword = $state(false);

	function handleDownload() {
		if (!downloadFilename || !value) return;

		const blob = new Blob([value], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = downloadFilename;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}
</script>

{#if variant === 'copy-input'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value class="truncate" {placeholder} {readonly} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label="Copy"
				title="Copy"
				size="icon-xs"
				onclick={() => clipboard.copy(value)}
			>
				{#if clipboard.copied}
					<CheckIcon />
				{:else}
					<CopyIcon />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'code-area'}
	<InputGroup.Root>
		<InputGroup.Addon align="block-start" class="flex h-10 items-center justify-between border-b">
			<InputGroup.Text class="font-sm font-mono">
				<Icon />
				{codeHeader}
			</InputGroup.Text>
			<div class="flex items-center gap-2">
				<InputGroup.Button
					aria-label="Copy"
					title="Copy"
					size="icon-xs"
					onclick={() => clipboard.copy(value)}
				>
					{#if clipboard.copied}
						<CheckIcon />
					{:else}
						<CopyIcon />
					{/if}
				</InputGroup.Button>
				{#if downloadFilename}
					<InputGroup.Button
						aria-label="Download"
						title="Download"
						size="icon-xs"
						onclick={handleDownload}
					>
						<DownloadIcon />
					</InputGroup.Button>
				{/if}
			</div>
		</InputGroup.Addon>
		<InputGroup.Textarea
			bind:value
			class="max-w-full overflow-x-hidden pb-8 font-mono break-all whitespace-pre-wrap"
			{placeholder}
			{readonly}
		/>
	</InputGroup.Root>
{:else if variant === 'search'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value placeholder={placeholder || 'Search...'} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			{#if value}
				{#if searchResults}
					<span class="text-xs text-muted-foreground">
						{searchResults}
						{searchResults === 1 ? 'result' : 'results'}
					</span>
				{/if}
				<InputGroup.Button variant="ghost" size="icon-xs" onclick={() => (value = '')}>
					<DeleteIcon />
				</InputGroup.Button>
			{/if}
		</InputGroup.Addon>
		<InputGroup.Addon>
			<SearchIcon />
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'password'}
	<InputGroup.Root class={className}>
		<InputGroup.Input
			type={showPassword ? 'text' : 'password'}
			bind:value
			placeholder={placeholder || 'Enter your password'}
			{...inputProps}
		/>
		<InputGroup.Addon align="inline-end">
			<InputGroup.Button
				aria-label="Show password"
				title="Show password"
				variant="ghost"
				size="icon-xs"
				class="h-7 w-7"
				onclick={() => (showPassword = !showPassword)}
			>
				{#if showPassword}
					<EyeIcon size={16} />
				{:else}
					<EyeOffIcon size={16} />
				{/if}
			</InputGroup.Button>
		</InputGroup.Addon>
	</InputGroup.Root>
{/if}
