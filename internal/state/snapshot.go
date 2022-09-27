package state

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ProtonMail/gluon/imap"
	"github.com/ProtonMail/gluon/internal/contexts"
	"github.com/ProtonMail/gluon/internal/db"
	"github.com/ProtonMail/gluon/internal/db/ent"
	"github.com/ProtonMail/gluon/internal/ids"
	"github.com/ProtonMail/gluon/internal/parser/proto"
	"github.com/bradenaw/juniper/xslices"
)

type snapshot struct {
	mboxID ids.MailboxIDPair

	state    *State
	messages *snapMsgList
}

func newSnapshot(ctx context.Context, state *State, client *ent.Client, mbox *ent.Mailbox) (*snapshot, error) {
	snapshotMessages, err := db.GetMailboxMessagesForNewSnapshot(ctx, client, mbox.ID)
	if err != nil {
		return nil, err
	}

	snap := &snapshot{
		mboxID:   ids.NewMailboxIDPair(mbox),
		state:    state,
		messages: newMsgList(len(snapshotMessages)),
	}

	for _, snapshotMessage := range snapshotMessages {
		snap.messages.insert(
			ids.MessageIDPair{InternalID: snapshotMessage.InternalID, RemoteID: snapshotMessage.RemoteID},
			snapshotMessage.UID,
			snapshotMessage.GetFlagSet(),
		)
	}

	return snap, nil
}

func newEmptySnapshot(state *State, mbox *ent.Mailbox) *snapshot {
	return &snapshot{
		mboxID:   ids.NewMailboxIDPair(mbox),
		state:    state,
		messages: newMsgList(0),
	}
}

func (snap *snapshot) len() int {
	return snap.messages.len()
}

func (snap *snapshot) hasMessage(messageID imap.InternalMessageID) bool {
	return snap.messages.has(messageID)
}

func (snap *snapshot) getMessageSeq(messageID imap.InternalMessageID) (imap.SeqID, error) {
	msg, ok := snap.messages.get(messageID)
	if !ok {
		return 0, ErrNoSuchMessage
	}

	return msg.Seq, nil
}

func (snap *snapshot) getMessageUID(messageID imap.InternalMessageID) (imap.UID, error) {
	msg, ok := snap.messages.get(messageID)
	if !ok {
		return 0, ErrNoSuchMessage
	}

	return msg.UID, nil
}

func (snap *snapshot) getMessageFlags(messageID imap.InternalMessageID) (imap.FlagSet, error) {
	msg, ok := snap.messages.get(messageID)
	if !ok {
		return nil, ErrNoSuchMessage
	}

	return msg.flags, nil
}

func (snap *snapshot) setMessageFlags(messageID imap.InternalMessageID, flags imap.FlagSet) error {
	msg, ok := snap.messages.get(messageID)
	if !ok {
		return ErrNoSuchMessage
	}

	if recent := msg.flags.ContainsUnchecked(imap.FlagRecentLowerCase); recent {
		flags = flags.Add(imap.FlagRecent)
	}

	msg.toExpunge = flags.ContainsUnchecked(imap.FlagDeletedLowerCase)

	msg.flags = flags

	return nil
}

func (snap *snapshot) getAllMessages() []snapMsgWithSeq {
	allMessages := snap.messages.all()
	result := make([]snapMsgWithSeq, len(allMessages))

	for i, v := range allMessages {
		result[i] = snapMsgWithSeq{
			Seq:     imap.SeqID(i + 1),
			snapMsg: v,
		}
	}

	return result
}

func (snap *snapshot) getAllMessageIDs() []ids.MessageIDPair {
	return xslices.Map(snap.messages.all(), func(msg *snapMsg) ids.MessageIDPair {
		return msg.ID
	})
}

func (snap *snapshot) getAllMessagesIDsMarkedDelete() []ids.MessageIDPair {
	var msgs []ids.MessageIDPair

	for _, v := range snap.messages.all() {
		if v.toExpunge {
			msgs = append(msgs, v.ID)
		}
	}

	return msgs
}

func (snap *snapshot) getMessagesInRange(ctx context.Context, seq *proto.SequenceSet) ([]snapMsgWithSeq, error) {
	switch {
	case contexts.IsUID(ctx):
		return snap.getMessagesInUIDRange(seq)

	default:
		return snap.getMessagesInSeqRange(seq)
	}
}

func (snap *snapshot) getMessagesInSeqRange(seq *proto.SequenceSet) ([]snapMsgWithSeq, error) {
	var res []snapMsgWithSeq

	seqSet, err := toSeqSet(seq)
	if err != nil {
		return nil, err
	}

	for _, seqRange := range seqSet {
		switch len(seqRange) {
		case 1:
			msg, err := snap.resolveSeq(seqRange[0])
			if err != nil {
				return nil, err
			}

			res = append(res, msg)

		case 2:
			begin, err := snap.resolveSeq(seqRange[0])
			if err != nil {
				return nil, err
			}

			end, err := snap.resolveSeq(seqRange[1])
			if err != nil {
				return nil, err
			}

			if begin.Seq > end.Seq {
				begin, end = end, begin
			}

			res = append(res, snap.messages.seqRange(begin.Seq, end.Seq)...)

		default:
			return nil, fmt.Errorf("bad sequence range")
		}
	}

	return res, nil
}

func (snap *snapshot) getMessagesInUIDRange(seq *proto.SequenceSet) ([]snapMsgWithSeq, error) {
	var res []snapMsgWithSeq

	// If there are no messages in the mailbox, we still resolve without error.
	if snap.messages.len() == 0 {
		return nil, nil
	}

	seqSet, err := toSeqSet(seq)
	if err != nil {
		return nil, err
	}

	for _, uidRange := range seqSet {
		switch len(uidRange) {
		case 1:
			uid, err := snap.resolveUID(uidRange[0])
			if err != nil {
				return nil, err
			}

			msg, ok := snap.messages.getWithUID(uid)
			if !ok {
				continue
			}

			res = append(res, msg)

		case 2:
			begin, err := snap.resolveUID(uidRange[0])
			if err != nil {
				return nil, err
			}

			end, err := snap.resolveUID(uidRange[1])
			if err != nil {
				return nil, err
			}

			if begin > end {
				begin, end = end, begin
			}

			res = append(res, snap.messages.uidRange(begin, end)...)

		default:
			return nil, fmt.Errorf("bad sequence range")
		}
	}

	return res, nil
}

func (snap *snapshot) firstMessageWithFlag(flag string) (snapMsgWithSeq, bool) {
	flagLower := strings.ToLower(flag)

	for i, msg := range snap.messages.msg {
		if msg.flags.ContainsUnchecked(flagLower) {
			return snapMsgWithSeq{Seq: imap.SeqID(i + 1), snapMsg: msg}, true
		}
	}

	return snapMsgWithSeq{}, false
}

func (snap *snapshot) firstMessageWithoutFlag(flag string) (snapMsgWithSeq, bool) {
	flagLower := strings.ToLower(flag)

	for i, msg := range snap.messages.msg {
		if !msg.flags.ContainsUnchecked(flagLower) {
			return snapMsgWithSeq{Seq: imap.SeqID(i + 1), snapMsg: msg}, true
		}
	}

	return snapMsgWithSeq{}, false
}

func (snap *snapshot) getMessagesWithFlag(flag string) []snapMsgWithSeq {
	flagLower := strings.ToLower(flag)

	return snap.messages.where(func(msg snapMsgWithSeq) bool {
		return msg.flags.ContainsUnchecked(flagLower)
	})
}

func (snap *snapshot) getMessagesWithFlagCount(flag string) int {
	flagLower := strings.ToLower(flag)

	return snap.messages.whereCount(func(msg snapMsgWithSeq) bool {
		return msg.flags.ContainsUnchecked(flagLower)
	})
}

func (snap *snapshot) getMessagesWithoutFlag(flag string) []snapMsgWithSeq {
	flagLower := strings.ToLower(flag)

	return snap.messages.where(func(msg snapMsgWithSeq) bool {
		return !msg.flags.ContainsUnchecked(flagLower)
	})
}

func (snap *snapshot) getMessagesWithoutFlagCount(flag string) int {
	flagLower := strings.ToLower(flag)

	return snap.messages.whereCount(func(msg snapMsgWithSeq) bool {
		return !msg.flags.ContainsUnchecked(flagLower)
	})
}

func (snap *snapshot) appendMessage(messageID ids.MessageIDPair, uid imap.UID, flags imap.FlagSet) error {
	snap.messages.insert(
		messageID,
		uid,
		flags,
	)

	return nil
}

func (snap *snapshot) expungeMessage(messageID imap.InternalMessageID) error {
	if ok := snap.messages.remove(messageID); !ok {
		return ErrNoSuchMessage
	}

	return nil
}

func (snap *snapshot) updateMailboxRemoteID(internalID imap.InternalMailboxID, remoteID imap.LabelID) error {
	if snap.mboxID.InternalID != internalID {
		return ErrNoSuchMailbox
	}

	snap.mboxID.RemoteID = remoteID

	return nil
}

func (snap *snapshot) updateMessageRemoteID(internalID imap.InternalMessageID, remoteID imap.MessageID) error {
	if ok := snap.messages.update(internalID, remoteID); !ok {
		return ErrNoSuchMessage
	}

	return nil
}

// resolveSeq converts a textual sequence number into an integer.
// According to RFC 3501, the definition of seq-number, page 89, for message sequence numbers
// - No sequence number is valid if mailbox is empty, not even "*"
// - "*" is converted to the number of messages in the mailbox
// - when used in a range, the order of the indexes in irrelevant.
func (snap *snapshot) resolveSeq(number string) (snapMsgWithSeq, error) {
	if snap.messages.len() == 0 {
		return snapMsgWithSeq{}, ErrNoSuchMessage
	}

	if number == "*" {
		return snap.messages.last(), nil
	}

	num, err := strconv.ParseUint(number, 10, 32)
	if err != nil {
		return snapMsgWithSeq{}, fmt.Errorf("failed to parse sequence number: %w", err)
	}

	msg, ok := snap.messages.seq(imap.SeqID(num))
	if !ok {
		return snapMsgWithSeq{}, ErrNoSuchMessage
	}

	return msg, nil
}

// resolveUID converts a textual message UID into an integer.
func (snap *snapshot) resolveUID(number string) (imap.UID, error) {
	if snap.messages.len() == 0 {
		return 0, ErrNoSuchMessage
	}

	if number == "*" {
		return snap.messages.last().UID, nil
	}

	num, err := strconv.ParseUint(number, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse UID number: %w", err)
	}

	return imap.UID(num), nil
}
