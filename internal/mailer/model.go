package mailer

type MailerSetting struct {
	Host     string
	Port     int
	Username string
	Sender   string
	Password string
}

type MailHeader struct {
	Type     string
	Contents []string
}
