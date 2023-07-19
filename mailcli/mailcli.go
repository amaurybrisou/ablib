package mailcli

import (
	"context"
	"fmt"
	"net/mail"
	"net/smtp"
)

// NOTE: https://serverfault.com/questions/635139/how-to-fix-send-mail-authorization-failed-534-5-7-14
// MailClientOption represents a configuration option for the MailClient.
type MailClientOption func(*MailClient)

// MailClient represents a client for sending emails using Gmail.
type MailClient struct {
	senderEmail      string
	smtpAuthUsername string
	smtpDisplayName  string
	smtpAuthPassword string
	template         string
	smtpServer       string
	smtpServerPort   int
	smtpServerAuth   smtp.Auth
	smtpServerPlain  bool
}

// NewMailClient creates a new MailClient with the provided options.
func NewMailClient(ctx context.Context, options ...MailClientOption) (*MailClient, error) {
	client := &MailClient{
		senderEmail:      "your-email@gmail.com",
		smtpAuthUsername: "your-email@gmail.com",
		smtpDisplayName:  "Admin",
		smtpAuthPassword: "default-password",
		template:         "Hello, %s!\n\nYour purchased password is: %s\n\nBest regards,\nThe Password Generator",
		smtpServer:       "smtp.gmail.com",
		smtpServerPort:   587,
		smtpServerAuth:   nil,
		smtpServerPlain:  false,
	}

	// Apply options
	for _, opt := range options {
		opt(client)
	}

	// Configure SMTP server settings if not already configured
	// if client.smtpServer == "" || client.smtpServerPort == 0 {
	if err := configureSMTPServer(client); err != nil {
		return nil, err
	}
	// }

	return client, nil
}

// configureSMTPServer sets up the SMTP server settings based on the Gmail server settings.
func configureSMTPServer(client *MailClient) error {
	auth := smtp.PlainAuth("", client.smtpAuthUsername, client.smtpAuthPassword, client.smtpServer)
	client.smtpServerAuth = auth
	client.smtpServerPlain = true

	return nil
}

// WithMailClientOptionSenderDisplayname sets the sender's email address.
func WithMailClientOptionSenderDisplayname(name string) MailClientOption {
	return func(c *MailClient) {
		c.smtpDisplayName = name
	}
}

// WithMailClientOptionSmtpAuthEmail sets the sender's email address.
func WithMailClientOptionSmtpAuthEmail(email string) MailClientOption {
	return func(c *MailClient) {
		c.smtpAuthUsername = email
	}
}

// WithMailClientOptionSenderEmail sets the sender's email address.
func WithMailClientOptionSenderEmail(email string) MailClientOption {
	return func(c *MailClient) {
		c.senderEmail = email
	}
}

// WithMailClientOptionSmtpAuthPassword sets the sender's password address.
func WithMailClientOptionSmtpAuthPassword(password string) MailClientOption {
	return func(c *MailClient) {
		c.smtpAuthPassword = password
	}
}

// WithMailClientOptionTemplate sets the email template.
func WithMailClientOptionTemplate(template string) MailClientOption {
	return func(c *MailClient) {
		c.template = template
	}
}

// WithClientOptionSMTPServer sets the SMTP server address and port.
func WithClientOptionSMTPServer(server string, port int) MailClientOption {
	return func(c *MailClient) {
		c.smtpServer = server
		c.smtpServerPort = port
	}
}

// SendPasswordEmail sends an email with an automatically generated password to the recipient.
func (c *MailClient) SendPasswordEmail(recipientEmail, password string) error {
	to := mail.Address{Name: "", Address: recipientEmail}
	from := mail.Address{Name: c.smtpDisplayName, Address: c.senderEmail}
	subject := "New Password"

	body := fmt.Sprintf(c.template, to.Address, password)
	msg := []byte("To: " + to.String() + "\r\n" +
		"From: " + from.String() + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", c.smtpServer, c.smtpServerPort),
		c.smtpServerAuth, c.senderEmail, []string{recipientEmail}, msg)
	if err != nil {
		return err
	}

	return nil
}
