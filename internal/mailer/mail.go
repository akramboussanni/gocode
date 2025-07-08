package mailer

import (
	"log"

	"gopkg.in/gomail.v2"
)

var dialer gomail.Dialer
var fromHeader MailHeader

func Init(setting MailerSetting) {
	dialer = *gomail.NewDialer(setting.Host, setting.Port, setting.Sender, setting.Password)
	fromHeader = MailHeader{Type: "From", Contents: []string{setting.Sender}}
}

func Send(name string, headers []MailHeader, data any) error {
	log.Println("[Mailer] Preparing to send email")
	log.Printf("[Mailer] Template name: %s\n", name)
	log.Printf("[Mailer] Headers: %+v\n", headers)
	log.Printf("[Mailer] Data: %+v\n", data)

	body, err := LoadTemplate(name, data)
	if err != nil {
		log.Println("[Mailer] Failed to load template:", err)
		return err
	}

	msg := gomail.NewMessage()
	msg.SetHeader(fromHeader.Type, fromHeader.Contents...)
	for i := range headers {
		header := headers[i]
		msg.SetHeader(header.Type, header.Contents...)
	}

	msg.SetBody("text/html", body)

	log.Println("[Mailer] Sending email...")
	if err := dialer.DialAndSend(msg); err != nil {
		log.Println("[Mailer] Failed to send email:", err)
		return err
	}

	log.Println("[Mailer] Email sent successfully")
	return nil
}

func MakeHeader(headerType string, contents ...string) MailHeader {
	return MailHeader{headerType, contents}
}
