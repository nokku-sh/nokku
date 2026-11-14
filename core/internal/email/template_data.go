package email

type linkTemplateData struct {
	Operator Operator

	LinkURL    string
	Expiration string
}

type workspacesTemplateData struct {
	Operator Operator

	Workspaces []WorkspaceLink
}

type inviteTemplateData struct {
	Operator Operator

	Workspace  string
	Role       string
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

type newWayInTemplateData struct {
	Operator Operator

	ProfileURL string
	What       string
	IPAddress  string
	EventTime  string
}

type trialTemplateData struct {
	Operator Operator

	Workspace  string
	Left       string
	EndDate    string
	DeleteDate string
	BillingURL string
	Next       string
}

type streamFailingTemplateData struct {
	Operator Operator

	Workspace string
	Kind      string
	Host      string
	Since     string
	Error     string
	URL       string
}

type deletionTemplateData struct {
	Operator Operator

	Workspace  string
	Slug       string
	Trial      bool
	EndDate    string
	DeleteDate string
	BillingURL string
	Next       string
}

type accessRequestTemplateData struct {
	Operator Operator

	Requester  string
	Target     string
	Account    string
	Duration   string
	Reason     string
	RequestURL string
	RequestID  string
}

type accessDecisionTemplateData struct {
	Operator Operator

	Decision   string
	Decider    string
	Target     string
	Account    string
	Until      string
	RequestURL string
	RequestID  string
}
