package imap

import (
	"fmt"
)

type MailboxDeleted struct {
	updateBase

	*updateWaiter

	MailboxID LabelID
}

func NewMailboxDeleted(mailboxID LabelID) *MailboxDeleted {
	return &MailboxDeleted{
		updateWaiter: newUpdateWaiter(),
		MailboxID:    mailboxID,
	}
}

func (u *MailboxDeleted) String() string {
	return fmt.Sprintf("MailboxDeleted: MailboxID = %v", u.MailboxID.ShortID())
}
