const browsers: [RegExp, string][] = [
	[/Edg\//, 'Edge'],
	[/Firefox\//, 'Firefox'],
	[/Chrome\//, 'Chrome'],
	[/Safari\//, 'Safari']
];

const systems: [RegExp, string][] = [
	[/iPhone|iPad/, 'iOS'],
	[/Android/, 'Android'],
	[/Windows/, 'Windows'],
	[/Mac OS X|Macintosh/, 'macOS'],
	[/Linux/, 'Linux']
];

/** A readable device for a user agent, e.g. "Firefox on Linux" or "nk CLI on darwin/arm64". */
export function describeAgent(ua: string | undefined): string {
	if (!ua) return 'Unknown device';
	// Nokku's own tools send "name/version (os/arch)".
	const tool = ua.match(/^(nk|nokkud)\/\S+ \(([^)]+)\)/);
	if (tool) return `${tool[1] === 'nk' ? 'nk CLI' : 'nokkud'} on ${tool[2]}`;
	const browser = browsers.find(([re]) => re.test(ua))?.[1];
	const system = systems.find(([re]) => re.test(ua))?.[1];
	if (browser && system) return `${browser} on ${system}`;
	return browser ?? system ?? ua.split(' ')[0];
}
