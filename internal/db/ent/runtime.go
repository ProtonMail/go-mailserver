// Code generated by ent, DO NOT EDIT.

package ent

import (
	"github.com/ProtonMail/gluon/imap"
	"github.com/ProtonMail/gluon/internal/db/ent/mailbox"
	"github.com/ProtonMail/gluon/internal/db/ent/message"
	"github.com/ProtonMail/gluon/internal/db/ent/schema"
	"github.com/ProtonMail/gluon/internal/db/ent/uid"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	mailboxFields := schema.Mailbox{}.Fields()
	_ = mailboxFields
	// mailboxDescUIDNext is the schema descriptor for UIDNext field.
	mailboxDescUIDNext := mailboxFields[3].Descriptor()
	// mailbox.DefaultUIDNext holds the default value on creation for the UIDNext field.
	mailbox.DefaultUIDNext = imap.UID(mailboxDescUIDNext.Default.(uint32))
	// mailboxDescUIDValidity is the schema descriptor for UIDValidity field.
	mailboxDescUIDValidity := mailboxFields[4].Descriptor()
	// mailbox.DefaultUIDValidity holds the default value on creation for the UIDValidity field.
	mailbox.DefaultUIDValidity = imap.UID(mailboxDescUIDValidity.Default.(uint32))
	messageFields := schema.Message{}.Fields()
	_ = messageFields
	// messageDescDeleted is the schema descriptor for Deleted field.
	messageDescDeleted := messageFields[7].Descriptor()
	// message.DefaultDeleted holds the default value on creation for the Deleted field.
	message.DefaultDeleted = messageDescDeleted.Default.(bool)
	uidFields := schema.UID{}.Fields()
	_ = uidFields
	// uidDescDeleted is the schema descriptor for Deleted field.
	uidDescDeleted := uidFields[1].Descriptor()
	// uid.DefaultDeleted holds the default value on creation for the Deleted field.
	uid.DefaultDeleted = uidDescDeleted.Default.(bool)
	// uidDescRecent is the schema descriptor for Recent field.
	uidDescRecent := uidFields[2].Descriptor()
	// uid.DefaultRecent holds the default value on creation for the Recent field.
	uid.DefaultRecent = uidDescRecent.Default.(bool)
}
