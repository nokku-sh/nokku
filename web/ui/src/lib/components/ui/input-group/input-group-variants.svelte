<script lang="ts">
	import * as InputGroup from '$lib/components/ui/input-group';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import * as ButtonGroup from '$lib/components/ui/button-group';
	import {
		CheckIcon,
		CopyIcon,
		SearchIcon,
		MailIcon,
		DeleteIcon,
		CircleQuestionMarkIcon,
		CodeIcon,
		type IconProps,
		EyeOffIcon,
		EyeIcon,
		XIcon,
		Tags,
		DownloadIcon
	} from '@lucide/svelte';
	import { UseClipboard } from '$lib/hooks/use-clipboard.svelte.js';
	import type { Component, ComponentProps } from 'svelte';
	import type { Textarea } from '../textarea';
	import Button from '../button/button.svelte';
	import Input from '../input/input.svelte';

	type Variant =
		| 'copy-input'
		| 'code-area'
		| 'search'
		| 'email'
		| 'tooltip'
		| 'url'
		| 'password'
		| 'tags';

	type IconComponent = Component<IconProps, Record<string, never>, ''>;
	interface Props {
		variant: Variant;
		value?: string;
		placeholder?: string;
		readonly?: boolean;
		icon?: {
			copy?: IconComponent;
			code?: IconComponent;
			tags?: IconComponent;
		};
		codeHeader?: string;
		truncate?: number;
		domain?: string;
		protocol?: string;
		tooltip?: string;
		class?: string;
		searchResults?: number;
		tags?: string[];
		downloadFilename?: string;
		onSearchClear?: () => void;
		onTagChange?: (tags: string[]) => void;
		inputProps?: ComponentProps<typeof Input>;
		areaProps?: ComponentProps<typeof Textarea>;
	}

	let {
		variant,
		value = $bindable(''),
		placeholder = '',
		readonly = false,
		icon = { code: CodeIcon, tags: Tags },
		codeHeader = 'bash',
		truncate = 0,
		domain = '',
		protocol = 'https://',
		tooltip = '',
		class: className = '',
		searchResults,
		tags = $bindable([]),
		downloadFilename,
		onSearchClear = () => (value = ''),
		onTagChange,
		inputProps = {},
		areaProps = {}
	}: Props = $props();

	const clipboard = new UseClipboard();

	function handleSearchClear() {
		onSearchClear?.();
		value = '';
	}
	let showPassword = $state(false);
	let tagInput = $state('');

	function addTag() {
		const trimmed = tagInput.trim();
		if (!trimmed) return;
		if (tags.includes(trimmed)) return;

		tags = [...tags, trimmed];
		tagInput = '';
		onTagChange?.(tags);
	}

	function removeTag(index: number) {
		tags = tags.filter((_, i) => i !== index);
		onTagChange?.(tags);
	}

	function handleTagKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') {
			e.preventDefault();
			addTag();
		} else if (e.key === 'Backspace' && !tagInput && tags.length > 0) {
			removeTag(tags.length - 1);
		}
	}

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
		{#if icon.copy}
			<InputGroup.Addon>
				<InputGroup.Text class="text-accent-foreground" title={placeholder}>
					<icon.copy />
				</InputGroup.Text>
			</InputGroup.Addon>
		{/if}
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
				<icon.code />
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
		{#if truncate > 0}
			<InputGroup.Textarea
				value={value.slice(0, truncate) + '...'}
				class="max-w-full overflow-x-hidden font-mono break-all whitespace-pre-wrap"
				{placeholder}
				{readonly}
				{...areaProps}
			/>
		{:else}
			<InputGroup.Textarea
				bind:value
				class="max-w-full overflow-x-hidden pb-8 font-mono break-all whitespace-pre-wrap"
				{placeholder}
				{readonly}
				{...areaProps}
			/>
		{/if}
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
				<InputGroup.Button variant="ghost" size="icon-xs" onclick={handleSearchClear}>
					<DeleteIcon />
				</InputGroup.Button>
			{/if}
		</InputGroup.Addon>
		<InputGroup.Addon>
			<SearchIcon />
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'email'}
	<InputGroup.Root class={className}>
		<InputGroup.Input
			type="email"
			bind:value
			placeholder={placeholder || 'Enter your email'}
			{...inputProps}
		/>
		<InputGroup.Addon>
			<MailIcon />
		</InputGroup.Addon>
	</InputGroup.Root>
{:else if variant === 'tooltip'}
	<InputGroup.Root class={className}>
		<InputGroup.Input bind:value {placeholder} {...inputProps} />
		<InputGroup.Addon align="inline-end">
			<Tooltip.Root>
				<Tooltip.Trigger>
					{#snippet child({ props })}
						<InputGroup.Button {...props} variant="ghost" aria-label="Info" size="icon-xs">
							<CircleQuestionMarkIcon />
						</InputGroup.Button>
					{/snippet}
				</Tooltip.Trigger>
				<Tooltip.Content>
					<p>{tooltip}</p>
				</Tooltip.Content>
			</Tooltip.Root>
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
{:else if variant === 'url'}
	<InputGroup.Root class={className}>
		<InputGroup.Addon class="pl-1.5 text-muted-foreground">
			<InputGroup.Text>{protocol}</InputGroup.Text>
		</InputGroup.Addon>
		<InputGroup.Input
			bind:value
			placeholder={placeholder || 'example.com'}
			class="pl-0.5!"
			{...inputProps}
		/>
		{#if domain}
			<InputGroup.Addon align="inline-end">
				<InputGroup.Text>{domain}</InputGroup.Text>
			</InputGroup.Addon>
		{/if}
	</InputGroup.Root>
{:else if variant === 'tags'}
	<div
		class="flex min-h-8 w-full flex-wrap items-center gap-1.5 rounded-md border border-input bg-transparent px-3 dark:bg-input/30"
	>
		<icon.tags class="mr-1 h-4 w-4 shrink-0 text-muted-foreground" />

		{#each tags as tag, i (tag)}
			<ButtonGroup.Root>
				<Button variant="secondary" class="h-6 px-2">{tag}</Button>
				<Button
					class="h-6 bg-accent px-1 text-sm"
					size="icon-xs"
					disabled={readonly}
					onclick={() => removeTag(i)}
				>
					<XIcon class="text-muted-foreground" />
				</Button>
			</ButtonGroup.Root>
		{/each}

		<input
			type="text"
			bind:value={tagInput}
			onkeydown={handleTagKeydown}
			placeholder={tags.length === 0 ? placeholder || 'Add tags...' : ''}
			disabled={readonly}
			class="h-6 flex-1 rounded-md bg-transparent text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
			{...inputProps}
		/>
	</div>
{/if}
