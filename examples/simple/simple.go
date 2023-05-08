package simple

import (
	"context"
	"fmt"
	"strings"

	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mproxy/pkg/session"
)

var _ session.Handler = (*Handler)(nil)

// Handler implements mqtt.Handler interface
type Handler struct {
	logger logger.Logger
}

// New creates new Event entity
func New(logger logger.Logger) *Handler {
	return &Handler{
		logger: logger,
	}
}

// AuthConnect is called on device connection,
// prior forwarding to the MQTT broker
func (h *Handler) AuthConnect(ctx context.Context) error {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return err
	}
	h.logger.Info(fmt.Sprintf("AuthConnect() - clientID: %s, username: %s, password: %s, client_CN: %s", c.ID, c.Username, string(c.Password), c.Cert.Subject.CommonName))
	return nil
}

// AuthPublish is called on device publish,
// prior forwarding to the MQTT broker
func (h *Handler) AuthPublish(ctx context.Context, topic *string, payload *[]byte) error {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return err
	}
	h.logger.Info(fmt.Sprintf("AuthPublish() - clientID: %s, topic: %s, payload: %s", c.ID, *topic, string(*payload)))

	return nil
}

// AuthSubscribe is called on device publish,
// prior forwarding to the MQTT broker
func (h *Handler) AuthSubscribe(ctx context.Context, topics *[]string) error {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return err
	}
	h.logger.Info(fmt.Sprintf("AuthSubscribe() - clientID: %s, topics: %s", c.ID, strings.Join(*topics, ",")))
	return nil
}

// Connect - after client successfully connected
func (h *Handler) Connect(ctx context.Context) {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return
	}
	h.logger.Info(fmt.Sprintf("Connect() - username: %s, clientID: %s", c.Username, c.ID))
}

// Publish - after client successfully published
func (h *Handler) Publish(ctx context.Context, topic *string, payload *[]byte) {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return
	}
	h.logger.Info(fmt.Sprintf("Publish() - username: %s, clientID: %s, topic: %s, payload: %s", c.Username, c.ID, *topic, string(*payload)))
}

// Subscribe - after client successfully subscribed
func (h *Handler) Subscribe(ctx context.Context, topics *[]string) {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return
	}
	h.logger.Info(fmt.Sprintf("Subscribe() - username: %s, clientID: %s, topics: %s", c.Username, c.ID, strings.Join(*topics, ",")))
}

// Unsubscribe - after client unsubscribed
func (h *Handler) Unsubscribe(ctx context.Context, topics *[]string) {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return
	}
	h.logger.Info(fmt.Sprintf("Unsubscribe() - username: %s, clientID: %s, topics: %s", c.Username, c.ID, strings.Join(*topics, ",")))
}

// Disconnect on conection lost
func (h *Handler) Disconnect(ctx context.Context) {
	c, err := session.FromContext(ctx)
	if err != nil {
		h.logger.Error("client is missing: " + err.Error())
		return
	}
	h.logger.Info(fmt.Sprintf("Disconnect() - client with username: %s and ID: %s disconenected", c.Username, c.ID))
}
