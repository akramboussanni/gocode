package mailer

func InitMailer() {

}

func SendMail(name, subject, receiver string, data any) error {
	tmpl, err := GetTemplate(name)
	if err != nil {
		return err
	}

	return nil
}
