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

type accessRequestTemplateData struct {
	Operator Operator

	Requester  string
	Target     string
	Account    string
	Duration   string // "2 hours"
	Reason     string
	RequestURL string
	RequestID  string
}

type accessDecisionTemplateData struct {
	Operator Operator

	Decision   string // "approved" or "denied"
	Decider    string
	Target     string
	Account    string
	Until      string // empty when denied
	RequestURL string
	RequestID  string
}
