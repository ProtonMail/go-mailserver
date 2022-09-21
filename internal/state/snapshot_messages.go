package state

import (
	"github.com/ProtonMail/gluon/imap"
	"github.com/ProtonMail/gluon/internal/ids"
	"github.com/bradenaw/juniper/xslices"
)

// snapMsg is a single message inside a snapshot.
type snapMsg struct {
	ID    ids.MessageIDPair
	UID   imap.UID
	Seq   imap.SeqID
	flags imap.FlagSet
}

// snapMsgList is an ordered list of messages inside a snapshot.
type snapMsgList struct {
	msg []*snapMsg
	idx map[imap.InternalMessageID]int
}

func newMsgList(capacity int) *snapMsgList {
	return &snapMsgList{
		idx: make(map[imap.InternalMessageID]int, capacity),
		msg: make([]*snapMsg, 0, capacity),
	}
}

func (list *snapMsgList) insert(msgID ids.MessageIDPair, msgUID imap.UID, flags imap.FlagSet) {
	if len(list.msg) > 0 && list.msg[len(list.msg)-1].UID >= msgUID {
		panic("UIDs must be strictly ascending")
	}

	list.msg = append(list.msg, &snapMsg{
		ID:    msgID,
		UID:   msgUID,
		Seq:   imap.SeqID(len(list.msg) + 1),
		flags: flags,
	})

	list.idx[msgID.InternalID] = len(list.idx)
}

func (list *snapMsgList) remove(msgID imap.InternalMessageID) bool {
	idx, ok := list.idx[msgID]
	if !ok {
		return false
	}

	delete(list.idx, msgID)

	list.msg = append(
		list.msg[:idx],
		list.msg[idx+1:]...,
	)

	if len(list.msg) > 0 {
		for _, message := range list.msg[idx:] {
			if message.Seq -= 1; message.Seq < 1 {
				panic("sequence number must be positive")
			}

			if list.idx[message.ID.InternalID] -= 1; list.idx[message.ID.InternalID] < 0 {
				panic("index must be non-negative")
			}
		}
	}

	return true
}

func (list *snapMsgList) update(internalID imap.InternalMessageID, remoteID imap.MessageID) bool {
	idx, ok := list.idx[internalID]
	if !ok {
		return false
	}

	list.msg[idx].ID.RemoteID = remoteID

	return true
}

func (list *snapMsgList) all() []*snapMsg {
	return list.msg
}

func (list *snapMsgList) len() int {
	return len(list.msg)
}

func (list *snapMsgList) where(fn func(*snapMsg) bool) []*snapMsg {
	return xslices.Filter(list.msg, fn)
}

func (list *snapMsgList) has(msgID imap.InternalMessageID) bool {
	_, ok := list.idx[msgID]

	return ok
}

func (list *snapMsgList) get(msgID imap.InternalMessageID) (*snapMsg, bool) {
	idx, ok := list.idx[msgID]
	if !ok {
		return nil, false
	}

	return list.msg[idx], true
}

func (list *snapMsgList) seq(seq imap.SeqID) (*snapMsg, bool) {
	if imap.SeqID(len(list.msg)) < seq {
		return nil, false
	}

	return list.msg[seq-1], true
}

func (list *snapMsgList) last() *snapMsg {
	return list.msg[len(list.msg)-1]
}

func (list *snapMsgList) seqRange(seqLo, seqHi imap.SeqID) []*snapMsg {
	return list.msg[seqLo-1 : seqHi]
}

func (list *snapMsgList) uidRange(uidLo, uidHi imap.UID) []*snapMsg {
	var index int

	len := len(list.msg)

	// find first UID
	for ; index < len && list.msg[index].UID < uidLo; index++ {
	}

	start := index

	// find last UID
	for ; index < len && list.msg[index].UID <= uidHi; index++ {
	}

	return list.msg[start:index]
}

func (list *snapMsgList) getWithUID(uid imap.UID) (*snapMsg, bool) {
	var index int

	len := len(list.msg)

	// find first UID
	for ; index < len && list.msg[index].UID < uid; index++ {
	}

	if index >= len || list.msg[index].UID > uid {
		return nil, false
	}

	return list.msg[index], true
}
