interface PublicKeyCredentialUserEntity {
	id: string;
	name: string;
	displayName: string;
}

interface CredentialDescriptorJSON {
	type: 'public-key';
	id: string;
	transports?: AuthenticatorTransport[];
}

interface PublicKeyCredentialCreationOptionsJSON {
	challenge: string;
	rp: {
		id: string;
		name: string;
	};
	user: PublicKeyCredentialUserEntity;
	pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
	timeout?: number;
	excludeCredentials?: CredentialDescriptorJSON[];
	authenticatorSelection?: AuthenticatorSelectionCriteria;
	attestation?: AttestationConveyancePreference;
}

interface PublicKeyCredentialRequestOptionsJSON {
	challenge: string;
	timeout?: number;
	rpId?: string;
	allowCredentials?: CredentialDescriptorJSON[];
	userVerification?: UserVerificationRequirement;
}

interface BeginRegistrationResponse {
	publicKey: PublicKeyCredentialCreationOptionsJSON;
}

interface BeginLoginResponse {
	options: {
		publicKey: PublicKeyCredentialRequestOptionsJSON;
	};
	sessionId: string;
}

/**
 * Try to get authenticator info from extensions
 */
function getAuthenticatorName(credential: PublicKeyCredential): string {
	const extensions = credential.getClientExtensionResults();
	if (extensions && extensions.credProps) {
		const credProps = extensions.credProps as { authenticatorDisplayName?: string };
		if (credProps.authenticatorDisplayName) {
			return credProps.authenticatorDisplayName;
		}
	}
	return '';
}

/**
 * Converts a base64url string to ArrayBuffer
 */
function base64urlToBuffer(base64url: string): ArrayBuffer {
	const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

/**
 * Converts ArrayBuffer to base64url string
 */
function bufferToBase64url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Registers a new user with a passkey (signup flow)
 */
export async function signupWithPasskey(params: {
	email: string;
	username: string;
	name?: string;
}): Promise<void> {
	const beginResponse = await fetch('/passkey/signup/begin', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(params)
	});

	if (!beginResponse.ok) {
		const error = await beginResponse.text();
		throw new Error(error || 'Failed to begin passkey signup');
	}

	const beginData = await beginResponse.json();
	const userId = beginData.userId as string;

	// Convert server response to WebAuthn format
	const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
		...beginData.publicKey,
		challenge: base64urlToBuffer(beginData.publicKey.challenge),
		user: {
			...beginData.publicKey.user,
			id: base64urlToBuffer(beginData.publicKey.user.id)
		},
		excludeCredentials: beginData.publicKey.excludeCredentials?.map(
			(cred: { id: string; type: string; transports?: AuthenticatorTransport[] }) => ({
				...cred,
				id: base64urlToBuffer(cred.id)
			})
		)
	};

	const credential = (await navigator.credentials.create({
		publicKey: publicKeyCredentialCreationOptions
	})) as PublicKeyCredential;

	if (!credential) {
		throw new Error('Failed to create credential');
	}

	const attestationResponse = credential.response as AuthenticatorAttestationResponse;

	const credentialData = {
		userId,
		id: credential.id,
		rawId: bufferToBase64url(credential.rawId),
		type: credential.type,
		response: {
			attestationObject: bufferToBase64url(attestationResponse.attestationObject),
			clientDataJSON: bufferToBase64url(attestationResponse.clientDataJSON)
		},
		name: getAuthenticatorName(credential)
	};

	const finishResponse = await fetch('/passkey/signup/finish', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(credentialData)
	});

	if (!finishResponse.ok) {
		const error = await finishResponse.text();
		throw new Error(error || 'Failed to finish passkey signup');
	}
}

/**
 * Registers a new passkey for the current user
 */
export async function registerPasskey(): Promise<void> {
	const beginResponse = await fetch('/passkey/register/begin', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({})
	});

	if (!beginResponse.ok) {
		const error = await beginResponse.text();
		throw new Error(`Failed to begin registration: ${error}`);
	}

	const credentialCreationOptions: BeginRegistrationResponse = await beginResponse.json();

	// convert server response to WebAuthn format
	const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
		...credentialCreationOptions.publicKey,
		challenge: base64urlToBuffer(credentialCreationOptions.publicKey.challenge),
		user: {
			...credentialCreationOptions.publicKey.user,
			id: base64urlToBuffer(credentialCreationOptions.publicKey.user.id)
		},
		excludeCredentials: credentialCreationOptions.publicKey.excludeCredentials?.map((cred) => ({
			...cred,
			id: base64urlToBuffer(cred.id)
		}))
	};

	// create credential using browser WebAuthn API
	const credential = (await navigator.credentials.create({
		publicKey: publicKeyCredentialCreationOptions
	})) as PublicKeyCredential;

	if (!credential) {
		throw new Error('Failed to create credential');
	}

	const attestationResponse = credential.response as AuthenticatorAttestationResponse;

	// prepare credential data for server
	const credentialData = {
		id: credential.id,
		rawId: bufferToBase64url(credential.rawId),
		type: credential.type,
		response: {
			attestationObject: bufferToBase64url(attestationResponse.attestationObject),
			clientDataJSON: bufferToBase64url(attestationResponse.clientDataJSON)
		},
		name: getAuthenticatorName(credential)
	};

	const finishResponse = await fetch('/passkey/register/finish', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(credentialData)
	});

	if (!finishResponse.ok) {
		const error = await finishResponse.text();
		throw new Error(`Failed to finish registration: ${error}`);
	}
}

/**
 * Authenticates user with a passkey
 */
export async function loginWithPasskey(): Promise<void> {
	const beginResponse = await fetch('/passkey/login/begin', {
		method: 'POST',
		credentials: 'include'
	});

	if (!beginResponse.ok) {
		const error = await beginResponse.text();
		throw new Error(`Failed to begin passkey login: ${error}`);
	}

	const loginData: BeginLoginResponse = await beginResponse.json();

	// convert server response to WebAuthn format
	const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
		...loginData.options.publicKey,
		challenge: base64urlToBuffer(loginData.options.publicKey.challenge),
		allowCredentials: loginData.options.publicKey.allowCredentials?.map((cred) => ({
			...cred,
			id: base64urlToBuffer(cred.id)
		}))
	};

	// get credential using browser WebAuthn API
	const credential = (await navigator.credentials.get({
		publicKey: publicKeyCredentialRequestOptions
	})) as PublicKeyCredential;

	if (!credential) {
		throw new Error('No passkey selected');
	}

	const assertionResponse = credential.response as AuthenticatorAssertionResponse;

	// prepare credential data for server
	const credentialData = {
		id: credential.id,
		rawId: bufferToBase64url(credential.rawId),
		type: credential.type,
		response: {
			authenticatorData: bufferToBase64url(assertionResponse.authenticatorData),
			clientDataJSON: bufferToBase64url(assertionResponse.clientDataJSON),
			signature: bufferToBase64url(assertionResponse.signature),
			userHandle: assertionResponse.userHandle
				? bufferToBase64url(assertionResponse.userHandle)
				: undefined
		}
	};

	const finishResponse = await fetch(`/passkey/login/finish?sessionId=${loginData.sessionId}`, {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(credentialData)
	});

	if (!finishResponse.ok) {
		const error = await finishResponse.text();
		throw new Error(`Failed to finish passkey login: ${error}`);
	}
}
