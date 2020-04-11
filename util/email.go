package util

import (
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func SendMail(name, address, template string, context TemplateContext) error {

	key := viper.GetString("email.api_key")

	to := mail.NewEmail(name, address)
	from := mail.NewEmail(viper.GetString("email.sender.name"), viper.GetString("email.sender.address"))

	subject, plainTextContent, htmlContent, err := RenderEmailTemplate(template, context)

	if err != nil {
		return err
	}

	message := mail.NewSingleEmail(from, string(subject), to, string(plainTextContent), string(htmlContent))

	client := sendgrid.NewSendClient(key)

	log.Printf("SENDING %+v", message)

	response, err := client.Send(message)
	if err != nil {
		log.Error(err)
	} else {
		log.Info(response.StatusCode)
		log.Info(response.Body)
		log.Info(response.Headers)
	}
	return err
}
