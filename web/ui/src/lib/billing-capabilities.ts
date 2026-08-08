export type BillingMode = 'self_hosted' | 'saas' | (string & {});

export interface BillingLimit {
	included: number;
	hard: number;
}

export interface BillingCapabilities {
	plan: string;
	billingMode: BillingMode;
	features: Record<string, boolean>;
	limits: Record<string, BillingLimit>;
	values: Record<string, number>;
	hasFeature(feature: string): boolean;
	limit(resource: string): BillingLimit | undefined;
}

function parseNumber(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Number(value);
	return Number.isFinite(parsed) ? parsed : undefined;
}

function parseBoolean(value: string | undefined): boolean | undefined {
	if (value === 'true' || value === '1') return true;
	if (value === 'false' || value === '0') return false;
	return undefined;
}

/** Parse the capability metadata returned by GetBilling. */
export function parseBillingCapabilities(
	metadata: Record<string, string> | undefined
): BillingCapabilities {
	const features: Record<string, boolean> = {};
	const limits: Record<string, BillingLimit> = {};
	const values: Record<string, number> = {};

	for (const [key, value] of Object.entries(metadata ?? {})) {
		if (key.startsWith('feature.')) {
			const feature = parseBoolean(value);
			if (feature !== undefined) features[key.slice('feature.'.length)] = feature;
			continue;
		}

		const limitMatch = /^limit\.([^.]+)\.(included|hard)$/.exec(key);
		if (limitMatch) {
			const parsed = parseNumber(value);
			if (parsed !== undefined) {
				const resource = limitMatch[1];
				const current = limits[resource] ?? { included: -1, hard: -1 };
				limits[resource] = { ...current, [limitMatch[2]]: parsed };
			}
			continue;
		}

		if (key === 'plan' || key === 'billing_mode') continue;
		const parsed = parseNumber(value);
		if (parsed !== undefined && !key.startsWith('max_') && !key.startsWith('credit_')) {
			values[key] = parsed;
		}
	}

	// Keep compatibility with metadata produced before the typed limit keys.
	for (const key of Object.keys(metadata ?? {})) {
		if (!key.startsWith('max_') && !key.startsWith('credit_')) continue;
		const resource = key.slice(key.indexOf('_') + 1);
		const parsed = parseNumber(metadata?.[key]);
		if (parsed === undefined) continue;
		const current = limits[resource] ?? { included: -1, hard: -1 };
		limits[resource] = key.startsWith('max_')
			? { ...current, hard: parsed }
			: { ...current, included: parsed };
	}

	return {
		plan: metadata?.plan ?? '',
		billingMode: metadata?.billing_mode ?? 'self_hosted',
		features,
		limits,
		values,
		hasFeature: (feature) => features[feature] === true,
		limit: (resource) => limits[resource]
	};
}
