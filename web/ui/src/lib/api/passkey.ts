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
	publicKey: PublicKeyCredentialRequestOptionsJSON;
}

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

function base64urlToBuffer(base64url: string): ArrayBuffer {
	const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// The endpoints answer errors as {code, message} JSON.
async function fail(response: Response, fallback: string): Promise<never> {
	const body = (await response.json().catch(() => null)) as { message?: string } | null;
	throw new Error(body?.message || fallback);
}

export async function signupWithPasskey(params: {
	invite: string;
	email: string;
	name?: string;
}): Promise<void> {
	// Begin reads the invite, email and name as form values. Finish reads the ceremony cookie.
	const form = new URLSearchParams({ invite: params.invite, email: params.email });
	if (params.name) form.set('name', params.name);

	const beginResponse = await fetch('/passkey/signup/begin', {
		method: 'POST',
		credentials: 'include',
		body: form
	});

	if (!beginResponse.ok) {
		await fail(beginResponse, 'Failed to begin passkey signup');
	}

	const beginData = await beginResponse.json();

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
		await fail(finishResponse, 'Failed to finish passkey signup');
	}
}

export async function registerPasskey(): Promise<void> {
	const beginResponse = await fetch('/passkey/register/begin', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({})
	});

	if (!beginResponse.ok) {
		await fail(beginResponse, 'Failed to begin registration');
	}

	const credentialCreationOptions: BeginRegistrationResponse = await beginResponse.json();

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

	const credential = (await navigator.credentials.create({
		publicKey: publicKeyCredentialCreationOptions
	})) as PublicKeyCredential;

	if (!credential) {
		throw new Error('Failed to create credential');
	}

	const attestationResponse = credential.response as AuthenticatorAttestationResponse;

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
		await fail(finishResponse, 'Failed to finish registration');
	}
}

export async function loginWithPasskey(): Promise<void> {
	const beginResponse = await fetch('/passkey/login/begin', {
		method: 'POST',
		credentials: 'include'
	});

	if (!beginResponse.ok) {
		await fail(beginResponse, 'Failed to begin passkey login');
	}

	const loginData: BeginLoginResponse = await beginResponse.json();

	const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
		...loginData.publicKey,
		challenge: base64urlToBuffer(loginData.publicKey.challenge),
		allowCredentials: loginData.publicKey.allowCredentials?.map((cred) => ({
			...cred,
			id: base64urlToBuffer(cred.id)
		}))
	};

	const credential = (await navigator.credentials.get({
		publicKey: publicKeyCredentialRequestOptions
	})) as PublicKeyCredential;

	if (!credential) {
		throw new Error('No passkey selected');
	}

	const assertionResponse = credential.response as AuthenticatorAssertionResponse;

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

	const finishResponse = await fetch('/passkey/login/finish', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(credentialData)
	});

	if (!finishResponse.ok) {
		await fail(finishResponse, 'Failed to finish passkey login');
	}
}
