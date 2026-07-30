<script lang="ts">
	import { Button } from '$lib/components/ui/button/index.js';
	import { ArrowLeft, Calendar } from '@lucide/svelte';
	import TermsOfService from './terms-of-service.md';

	const lastUpdated = 'March 6, 2026';
</script>

<svelte:head>
	<title>Terms of Service - Nokku</title>
	<meta
		name="description"
		content="Terms of Service for Nokku - Read our terms and conditions for using our service."
	/>
</svelte:head>

<div class="w-full bg-muted/30 pt-8 pb-16">
	<div class="container mx-auto max-w-3xl px-4">
		<div class="flex items-center justify-between">
			<div class="mb-8 space-y-4">
				<h1 class="text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
					Terms of Service
				</h1>
				<div class="flex items-center text-sm text-muted-foreground">
					<Calendar class="mr-2 size-4" />
					Last updated: {lastUpdated}
				</div>
			</div>

			<Button onclick={() => history.back()} variant="ghost">
				<ArrowLeft />
				Back to App
			</Button>
		</div>

		<div class="rounded-xl border bg-card px-6 py-8 shadow-sm sm:px-10 sm:py-12">
			<div
				class="prose max-w-none prose-neutral dark:prose-invert
				prose-headings:font-semibold prose-headings:tracking-tight prose-headings:text-foreground
				prose-p:leading-relaxed prose-p:text-muted-foreground
				prose-a:font-medium prose-a:text-primary prose-a:underline-offset-4 hover:prose-a:underline
				prose-strong:text-foreground
				prose-li:text-muted-foreground"
			>
				<TermsOfService />
			</div>
		</div>
	</div>
</div>
