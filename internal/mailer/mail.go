package mailer

import (
	"gopkg.in/gomail.v2"
)

var dialer gomail.Dialer
var fromHeader MailHeader

func Init(setting MailerSetting) {
	dialer = *gomail.NewDialer(setting.Host, setting.Port, setting.Sender, setting.Password)
	fromHeader = MailHeader{Type: "From", Contents: []string{setting.Sender}}
}

func Send(name string, headers []MailHeader, data any) error {
	body, err := LoadTemplate(name, data)
	if err != nil {
		return err
	}

	msg := gomail.NewMessage()
	msg.SetHeader(fromHeader.Type, fromHeader.Contents...)
	for i := range headers {
		header := headers[i]
		msg.SetHeader(header.Type, header.Contents...)
	}

	msg.SetBody("text/html", body)

	if err := dialer.DialAndSend(msg); err != nil {
		return err
	}

	return nil
}

func MakeHeader(headerType string, contents ...string) MailHeader {
	return MailHeader{headerType, contents}
}
