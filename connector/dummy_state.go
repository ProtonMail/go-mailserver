package connector

import (
	"context"
	"sync"
	"time"

	"github.com/ProtonMail/gluon/imap"
	"github.com/bradenaw/juniper/xslices"
	"github.com/google/uuid"
	"golang.org/x/exp/maps"
)

type dummyState struct {
	flags, permFlags, attrs imap.FlagSet

	messages   map[imap.MessageID]*dummyMessage
	labels     map[imap.LabelID]*dummyLabel
	lastIMAPID imap.IMAPID

	lock sync.RWMutex
}

type dummyLabel struct {
	labelName []string
	exclusive bool
}

type dummyMessage struct {
	literal       []byte
	parsedMessage *imap.ParsedMessage
	seen          bool
	flagged       bool
	date          time.Time
	flags         imap.FlagSet

	labelIDs map[imap.LabelID]struct{}
}

func newDummyState(flags, permFlags, attrs imap.FlagSet) *dummyState {
	return &dummyState{
		flags:      flags,
		permFlags:  permFlags,
		attrs:      attrs,
		messages:   make(map[imap.MessageID]*dummyMessage),
		labels:     make(map[imap.LabelID]*dummyLabel),
		lastIMAPID: imap.NewIMAPID(),
	}
}

func (state *dummyState) recordIMAPID(ctx context.Context) {
	if id, ok := imap.GetIMAPIDFromContext(ctx); ok {
		state.lock.Lock()
		defer state.lock.Unlock()
		state.lastIMAPID = id
	}
}

func (state *dummyState) getLabels() []imap.Mailbox {
	state.lock.Lock()
	defer state.lock.Unlock()

	return xslices.Map(maps.Keys(state.labels), func(labelID imap.LabelID) imap.Mailbox {
		return state.toMailbox(labelID)
	})
}

func (state *dummyState) getLabel(labelID imap.LabelID) (imap.Mailbox, error) {
	state.lock.Lock()
	defer state.lock.Unlock()

	if _, ok := state.labels[labelID]; !ok {
		return imap.Mailbox{}, ErrNoSuchLabel
	}

	return state.toMailbox(labelID), nil
}

func (state *dummyState) createLabel(name []string, exclusive bool) imap.Mailbox {
	state.lock.Lock()
	defer state.lock.Unlock()

	labelID := imap.LabelID(uuid.NewString())

	state.labels[labelID] = &dummyLabel{
		labelName: name,
		exclusive: exclusive,
	}

	return state.toMailbox(labelID)
}

func (state *dummyState) createLabelWithID(name []string, id imap.LabelID, exclusive bool) imap.Mailbox {
	state.lock.Lock()
	defer state.lock.Unlock()

	state.labels[id] = &dummyLabel{
		labelName: name,
		exclusive: exclusive,
	}

	return state.toMailbox(id)
}

func (state *dummyState) updateLabel(labelID imap.LabelID, name []string) {
	state.lock.Lock()
	defer state.lock.Unlock()

	state.labels[labelID].labelName = name
}

func (state *dummyState) deleteLabel(labelID imap.LabelID) {
	state.lock.Lock()
	defer state.lock.Unlock()

	delete(state.labels, labelID)

	for _, message := range state.messages {
		delete(message.labelIDs, labelID)
	}
}

func (state *dummyState) getMessages() []imap.Message {
	state.lock.Lock()
	defer state.lock.Unlock()

	return xslices.Map(maps.Keys(state.messages), func(messageID imap.MessageID) imap.Message {
		return state.toMessage(messageID)
	})
}

func (state *dummyState) getMessageCreatedUpdate(id imap.MessageID) (*imap.MessageCreated, error) {
	state.lock.Lock()
	defer state.lock.Unlock()

	msg, ok := state.messages[id]
	if !ok {
		return nil, ErrNoSuchMessage
	}

	return &imap.MessageCreated{
		Message:       state.toMessage(id),
		Literal:       msg.literal,
		LabelIDs:      maps.Keys(msg.labelIDs),
		ParsedMessage: msg.parsedMessage,
	}, nil
}

func (state *dummyState) getMessage(messageID imap.MessageID) (imap.Message, error) {
	state.lock.Lock()
	defer state.lock.Unlock()

	if _, ok := state.messages[messageID]; !ok {
		return imap.Message{}, ErrNoSuchMessage
	}

	return state.toMessage(messageID), nil
}

func (state *dummyState) getLabelIDs(messageID imap.MessageID) []imap.LabelID {
	state.lock.Lock()
	defer state.lock.Unlock()

	return maps.Keys(state.messages[messageID].labelIDs)
}

func (state *dummyState) getLiteral(messageID imap.MessageID) []byte {
	state.lock.Lock()
	defer state.lock.Unlock()

	return state.messages[messageID].literal
}

func (state *dummyState) createMessage(mboxID imap.LabelID, literal []byte, parsedMessage *imap.ParsedMessage, seen, flagged bool, otherFlags imap.FlagSet, date time.Time) imap.Message {
	state.lock.Lock()
	defer state.lock.Unlock()

	messageID := imap.MessageID(uuid.NewString())

	if seen {
		otherFlags.RemoveFromSelf(imap.FlagSeen)
	}

	if flagged {
		otherFlags.RemoveFromSelf(imap.FlagFlagged)
	}

	state.messages[messageID] = &dummyMessage{
		literal:       literal,
		seen:          seen,
		parsedMessage: parsedMessage,
		flagged:       flagged,
		flags:         otherFlags,
		date:          date,
		labelIDs:      map[imap.LabelID]struct{}{mboxID: {}},
	}

	return state.toMessage(messageID)
}

func (state *dummyState) labelMessage(messageID imap.MessageID, labelID imap.LabelID) {
	state.lock.Lock()
	defer state.lock.Unlock()

	if state.labels[labelID].exclusive {
		state.messages[messageID].labelIDs = make(map[imap.LabelID]struct{})
	}

	state.messages[messageID].labelIDs[labelID] = struct{}{}
}

func (state *dummyState) unlabelMessage(messageID imap.MessageID, labelID imap.LabelID) {
	state.lock.Lock()
	defer state.lock.Unlock()

	delete(state.messages[messageID].labelIDs, labelID)
}

func (state *dummyState) setSeen(messageID imap.MessageID, seen bool) {
	state.lock.Lock()
	defer state.lock.Unlock()

	state.messages[messageID].seen = seen
}

func (state *dummyState) setFlagged(messageID imap.MessageID, flagged bool) {
	state.lock.Lock()
	defer state.lock.Unlock()

	state.messages[messageID].flagged = flagged
}

func (state *dummyState) isSeen(messageID imap.MessageID) bool {
	state.lock.Lock()
	defer state.lock.Unlock()

	return state.messages[messageID].seen
}

func (state *dummyState) isFlagged(messageID imap.MessageID) bool {
	state.lock.Lock()
	defer state.lock.Unlock()

	return state.messages[messageID].flagged
}

func (state *dummyState) toMailbox(labelID imap.LabelID) imap.Mailbox {
	return imap.Mailbox{
		ID:             labelID,
		Name:           state.labels[labelID].labelName,
		Flags:          state.flags,
		PermanentFlags: state.permFlags,
		Attributes:     state.attrs,
	}
}

func (state *dummyState) toMessage(messageID imap.MessageID) imap.Message {
	flags := imap.NewFlagSet()

	if state.messages[messageID].seen {
		flags.AddToSelf(imap.FlagSeen)
	}

	if state.messages[messageID].flagged {
		flags.AddToSelf(imap.FlagFlagged)
	}

	flags.AddFlagSetToSelf(state.messages[messageID].flags)

	return imap.Message{
		ID:    messageID,
		Flags: flags,
		Date:  state.messages[messageID].date,
	}
}
