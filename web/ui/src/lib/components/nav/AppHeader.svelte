<script lang="ts">
	import { page } from '$app/state';
	import * as Breadcrumb from '$lib/components/ui/breadcrumb';
	import { Separator } from '$lib/components/ui/separator';
	import * as Sidebar from '$lib/components/ui/sidebar';
	import { AppRoutes } from './routes';

	type Crumb = {
		title: string;
		url: string;
		isLast: boolean;
	};
	const flatRoutes = $derived(Object.values(AppRoutes).flat());

	const breadcrumbs = $derived.by(() => {
		const path = page.url.pathname;

		if (path === '/') {
			const root = flatRoutes.find((r) => r.url === '/');
			return [{ title: root?.title || 'Home', url: '/', isLast: true }];
		}

		const segments = path.split('/').filter(Boolean);
		const crumbs: Crumb[] = [{ title: 'Home', url: '/', isLast: false }];

		const fullMatch = flatRoutes.find((r) => r.url.replace(/\/$/, '') === path.replace(/\/$/, ''));

		if (fullMatch) {
			crumbs.push({ title: fullMatch.title, url: fullMatch.url, isLast: true });
		} else {
			let currentPath = '';
			for (let i = 0; i < segments.length; i++) {
				currentPath += `/${segments[i]}`;
				const isLast = i === segments.length - 1;
				const match = flatRoutes.find((r) => r.url.replace(/\/$/, '') === currentPath);

				crumbs.push({
					title: match?.title || segments[i].charAt(0).toUpperCase() + segments[i].slice(1),
					url: currentPath,
					isLast
				});
			}
		}

		return crumbs;
	});
</script>

<header
	class="flex h-16 shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-16"
>
	<div class="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
		<Sidebar.Trigger class="-ml-1" />
		<Separator orientation="vertical" class="mx-2 data-[orientation=vertical]:h-4" />

		<Breadcrumb.Root>
			<Breadcrumb.List>
				{#each breadcrumbs as crumb, i (i)}
					<Breadcrumb.Item>
						{#if !crumb.isLast}
							<Breadcrumb.Link href={crumb.url}>{crumb.title}</Breadcrumb.Link>
						{:else}
							<Breadcrumb.Page>{crumb.title}</Breadcrumb.Page>
						{/if}
					</Breadcrumb.Item>
					{#if i < breadcrumbs.length - 1}
						<Breadcrumb.Separator />
					{/if}
				{/each}
			</Breadcrumb.List>
		</Breadcrumb.Root>
	</div>
</header>
