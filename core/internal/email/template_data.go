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

type trialTemplateData struct {
	Operator Operator

	Workspace  string
	Left       string // "3 days"
	EndDate    string
	DeleteDate string
	BillingURL string
	Next       string // when the next reminder comes, empty for none
}

type deletionTemplateData struct {
	Operator Operator

	Workspace  string
	Slug       string
	Trial      bool
	EndDate    string
	DeleteDate string
	BillingURL string
	Next       string // when the next warning comes, empty for none
}
