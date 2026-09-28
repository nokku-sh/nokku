package email

type WelcomeTemplateData struct {
	UserName        string
	VerificationURL string
	Expiration      string
}

type VerificationTemplateData struct {
	VerificationURL string
	Expiration      string
}

type RecoveryTemplateData struct {
	RecoveryURL string
	Expiration  string
}

type NewLoginTemplateData struct {
	ProfileURL string
	DeviceID   string
	DeviceName string
	IPAddress  string
	EventTime  string
}
