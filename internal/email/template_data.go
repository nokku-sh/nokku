package email

type WelcomeTemplateData struct {
	Operator Operator

	UserName        string
	VerificationURL string
	Expiration      string
}

type VerificationTemplateData struct {
	Operator Operator

	VerificationURL string
	Expiration      string
}

type RecoveryTemplateData struct {
	Operator Operator

	RecoveryURL string
	Expiration  string
}

type ChangeNoticeTemplateData struct {
	Operator Operator

	NewEmail   string
	CancelURL  string
	Expiration string
}

type NewLoginTemplateData struct {
	Operator Operator

	ProfileURL string
	DeviceID   string
	DeviceName string
	IPAddress  string
	EventTime  string
}
