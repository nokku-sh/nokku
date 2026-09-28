import { Code, ConnectError } from '@connectrpc/connect';

// Must match the rawMessage of api.ErrEmailUnverified.
export const emailUnverifiedMessage = 'verify your email address before signing in';

export const isEmailUnverifiedError = (error: unknown): boolean =>
	error instanceof ConnectError && error.rawMessage === emailUnverifiedMessage;

type HTTPErrorBody = {
	code?: number;
	message?: string;
};

type ValidationError = {
	field: string;
	message: string;
	constraint?: string;
};

const parseValidationErrors = (message: string): ValidationError[] => {
	const errors: ValidationError[] = [];

	// Match pattern: "- field: message [constraint]"
	const validationPattern = /- ([^:]+): ([^[]+)(?:\[([^\]]+)\])?/g;
	let match;

	while ((match = validationPattern.exec(message)) !== null) {
		errors.push({
			field: match[1].trim(),
			message: match[2].trim(),
			constraint: match[3]?.trim()
		});
	}

	return errors;
};

const formatFieldName = (field: string): string => {
	return field
		.replace(/([A-Z])/g, ' $1')
		.replace(/_/g, ' ')
		.split(' ')
		.map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
		.join(' ')
		.trim();
};

const getErrorTitle = (code: Code): string => {
	switch (code) {
		case Code.Canceled:
			return 'Request Canceled';
		case Code.Unknown:
			return 'Unknown Error';
		case Code.InvalidArgument:
			return 'Invalid Input';
		case Code.DeadlineExceeded:
			return 'Request Timeout';
		case Code.NotFound:
			return 'Not Found';
		case Code.AlreadyExists:
			return 'Already Exists';
		case Code.PermissionDenied:
			return 'Permission Denied';
		case Code.ResourceExhausted:
			return 'Quota Exceeded';
		case Code.FailedPrecondition:
			return 'Action Not Allowed';
		case Code.Aborted:
			return 'Request Aborted';
		case Code.OutOfRange:
			return 'Out of Range';
		case Code.Unimplemented:
			return 'Not Implemented';
		case Code.Internal:
			return 'Server Error';
		case Code.Unavailable:
			return 'Service Unavailable';
		case Code.DataLoss:
			return 'Data Loss';
		case Code.Unauthenticated:
			return 'Authentication Required';
		default:
			return 'Error';
	}
};

const getDefaultDescription = (code: Code): string | undefined => {
	switch (code) {
		case Code.Canceled:
			return 'The request was canceled.';
		case Code.Unknown:
			return 'An unexpected error occurred.';
		case Code.DeadlineExceeded:
			return 'The request took too long to complete.';
		case Code.ResourceExhausted:
			return 'Too many requests. Please try again later.';
		case Code.Internal:
			return 'An unexpected error occurred. Please try again.';
		case Code.Unavailable:
			return 'The service is temporarily unavailable. Please try again later.';
		case Code.PermissionDenied:
			return 'You do not have permission to perform this action.';
		case Code.Unauthenticated:
			return 'Please log in to continue.';
		case Code.NotFound:
			return 'The requested resource could not be found.';
		case Code.AlreadyExists:
			return 'A resource with this identifier already exists.';
		case Code.Aborted:
			return 'The request was aborted. Please try again.';
		case Code.Unimplemented:
			return 'This feature is not yet available.';
		case Code.DataLoss:
			return 'Data was lost or corrupted.';
		default:
			return undefined;
	}
};

export const parseHTTPError = async (response: Response): Promise<ConnectError> => {
	try {
		const body: HTTPErrorBody = await response.json();
		const code =
			typeof body.code === 'number'
				? httpStatusToCode(body.code)
				: httpStatusToCode(response.status);
		return new ConnectError(body.message ?? response.statusText, code);
	} catch {
		return new ConnectError(response.statusText, httpStatusToCode(response.status));
	}
};

const httpStatusToCode = (status: number): Code => {
	switch (status) {
		case 400:
			return Code.InvalidArgument;
		case 401:
			return Code.Unauthenticated;
		case 403:
			return Code.PermissionDenied;
		case 404:
			return Code.NotFound;
		case 409:
			return Code.AlreadyExists;
		case 429:
			return Code.ResourceExhausted;
		case 499:
			return Code.Canceled;
		case 501:
			return Code.Unimplemented;
		case 503:
			return Code.Unavailable;
		case 504:
			return Code.DeadlineExceeded;
		default:
			return Code.Internal;
	}
};

export const formatConnectError = (
	error: ConnectError
): { title: string; description?: string } => {
	const title = getErrorTitle(error.code);

	if (error.code === Code.InvalidArgument && error.rawMessage.includes('validation error:')) {
		const validationErrors = parseValidationErrors(error.rawMessage);

		if (validationErrors.length === 1) {
			const { field, message } = validationErrors[0];
			return {
				title: formatFieldName(field),
				description: message
			};
		} else if (validationErrors.length > 1) {
			const description = validationErrors
				.map(({ field, message }) => `${formatFieldName(field)}: ${message}`)
				.join('\n');

			return {
				title: 'Validation Failed',
				description
			};
		}
	}

	// rawMessage has no [code] prefix.
	let description = error.rawMessage.trim();

	if (!description || description.length < 3 || description.toLowerCase() === title.toLowerCase()) {
		description = getDefaultDescription(error.code) || '';
	}

	return {
		title,
		description: description || undefined
	};
};
