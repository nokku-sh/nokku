package email

type welcomeTemplateData struct {
	Operator Operator

	UserName        string
	VerificationURL string
	Expiration      string
}

type verificationTemplateData struct {
	Operator Operator

	VerificationURL string
	Expiration      string
}

type recoveryTemplateData struct {
	Operator Operator

	RecoveryURL string
	Expiration  string
}

type changeNoticeTemplateData struct {
	Operator Operator

	NewEmail   string
	CancelURL  string
	Expiration string
}

type newLoginTemplateData struct {
	Operator Operator

	ProfileURL string
	DeviceID   string
	DeviceName string
	IPAddress  string
	EventTime  string
}
