package email

type linkTemplateData struct {
	Operator Operator

	LinkURL    string
	Expiration string
}

type signupTemplateData struct {
	Operator Operator

	UserName   string
	Workspace  string
	LinkURL    string
	Expiration string
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
