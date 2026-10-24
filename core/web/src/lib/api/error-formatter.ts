import { Code, ConnectError } from '@connectrpc/connect';

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

// displayName and display_name both read "Display name".
const formatFieldName = (field: string): string => {
	const words = field
		.replace(/([A-Z])/g, ' $1')
		.replace(/_/g, ' ')
		.trim()
		.toLowerCase();
	return words.charAt(0).toUpperCase() + words.slice(1);
};

const getErrorTitle = (code: Code): string => {
	switch (code) {
		case Code.Canceled:
			return 'Request canceled';
		case Code.Unknown:
			return 'Something went wrong';
		case Code.InvalidArgument:
			return 'Invalid input';
		case Code.DeadlineExceeded:
			return 'Timed out';
		case Code.NotFound:
			return 'Not found';
		case Code.AlreadyExists:
			return 'Already exists';
		case Code.PermissionDenied:
			return 'Not allowed';
		case Code.ResourceExhausted:
			return 'Limit reached';
		case Code.FailedPrecondition:
			return 'Not possible right now';
		case Code.Aborted:
			return 'Request aborted';
		case Code.OutOfRange:
			return 'Out of range';
		case Code.Unimplemented:
			return 'Not available';
		case Code.Internal:
			return 'Server error';
		case Code.Unavailable:
			return "Can't reach Nokku";
		case Code.DataLoss:
			return 'Data loss';
		case Code.Unauthenticated:
			return 'Signed out';
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
			return 'Too many requests. Try again in a moment.';
		case Code.Internal:
			return 'An unexpected error occurred. Try again.';
		case Code.Unavailable:
			return 'The control plane does not answer. Try again in a moment.';
		case Code.PermissionDenied:
			return 'Your role cannot do this.';
		case Code.Unauthenticated:
			return 'Sign in to continue.';
		case Code.NotFound:
			return 'The requested resource could not be found.';
		case Code.AlreadyExists:
			return 'A resource with this identifier already exists.';
		case Code.Aborted:
			return 'The request was aborted. Try again.';
		case Code.Unimplemented:
			return 'This feature is not yet available.';
		case Code.DataLoss:
			return 'Data was lost or corrupted.';
		default:
			return undefined;
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
				title: 'Invalid input',
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
