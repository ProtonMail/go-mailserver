// Code generated by entc, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/ProtonMail/gluon/internal/backend/ent/mailbox"
	"github.com/ProtonMail/gluon/internal/backend/ent/message"
	"github.com/ProtonMail/gluon/internal/backend/ent/uid"
)

// UID is the model entity for the UID schema.
type UID struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// UID holds the value of the "UID" field.
	UID int `json:"UID,omitempty"`
	// Deleted holds the value of the "Deleted" field.
	Deleted bool `json:"Deleted,omitempty"`
	// Recent holds the value of the "Recent" field.
	Recent bool `json:"Recent,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the UIDQuery when eager-loading is set.
	Edges         UIDEdges `json:"edges"`
	mailbox_ui_ds *int
	uid_message   *int
}

// UIDEdges holds the relations/edges for other nodes in the graph.
type UIDEdges struct {
	// Message holds the value of the message edge.
	Message *Message `json:"message,omitempty"`
	// Mailbox holds the value of the mailbox edge.
	Mailbox *Mailbox `json:"mailbox,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// MessageOrErr returns the Message value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UIDEdges) MessageOrErr() (*Message, error) {
	if e.loadedTypes[0] {
		if e.Message == nil {
			// The edge message was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: message.Label}
		}
		return e.Message, nil
	}
	return nil, &NotLoadedError{edge: "message"}
}

// MailboxOrErr returns the Mailbox value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UIDEdges) MailboxOrErr() (*Mailbox, error) {
	if e.loadedTypes[1] {
		if e.Mailbox == nil {
			// The edge mailbox was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: mailbox.Label}
		}
		return e.Mailbox, nil
	}
	return nil, &NotLoadedError{edge: "mailbox"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*UID) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case uid.FieldDeleted, uid.FieldRecent:
			values[i] = new(sql.NullBool)
		case uid.FieldID, uid.FieldUID:
			values[i] = new(sql.NullInt64)
		case uid.ForeignKeys[0]: // mailbox_ui_ds
			values[i] = new(sql.NullInt64)
		case uid.ForeignKeys[1]: // uid_message
			values[i] = new(sql.NullInt64)
		default:
			return nil, fmt.Errorf("unexpected column %q for type UID", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the UID fields.
func (u *UID) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case uid.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			u.ID = int(value.Int64)
		case uid.FieldUID:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field UID", values[i])
			} else if value.Valid {
				u.UID = int(value.Int64)
			}
		case uid.FieldDeleted:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field Deleted", values[i])
			} else if value.Valid {
				u.Deleted = value.Bool
			}
		case uid.FieldRecent:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field Recent", values[i])
			} else if value.Valid {
				u.Recent = value.Bool
			}
		case uid.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field mailbox_ui_ds", value)
			} else if value.Valid {
				u.mailbox_ui_ds = new(int)
				*u.mailbox_ui_ds = int(value.Int64)
			}
		case uid.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field uid_message", value)
			} else if value.Valid {
				u.uid_message = new(int)
				*u.uid_message = int(value.Int64)
			}
		}
	}
	return nil
}

// QueryMessage queries the "message" edge of the UID entity.
func (u *UID) QueryMessage() *MessageQuery {
	return (&UIDClient{config: u.config}).QueryMessage(u)
}

// QueryMailbox queries the "mailbox" edge of the UID entity.
func (u *UID) QueryMailbox() *MailboxQuery {
	return (&UIDClient{config: u.config}).QueryMailbox(u)
}

// Update returns a builder for updating this UID.
// Note that you need to call UID.Unwrap() before calling this method if this UID
// was returned from a transaction, and the transaction was committed or rolled back.
func (u *UID) Update() *UIDUpdateOne {
	return (&UIDClient{config: u.config}).UpdateOne(u)
}

// Unwrap unwraps the UID entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (u *UID) Unwrap() *UID {
	tx, ok := u.config.driver.(*txDriver)
	if !ok {
		panic("ent: UID is not a transactional entity")
	}
	u.config.driver = tx.drv
	return u
}

// String implements the fmt.Stringer.
func (u *UID) String() string {
	var builder strings.Builder
	builder.WriteString("UID(")
	builder.WriteString(fmt.Sprintf("id=%v", u.ID))
	builder.WriteString(", UID=")
	builder.WriteString(fmt.Sprintf("%v", u.UID))
	builder.WriteString(", Deleted=")
	builder.WriteString(fmt.Sprintf("%v", u.Deleted))
	builder.WriteString(", Recent=")
	builder.WriteString(fmt.Sprintf("%v", u.Recent))
	builder.WriteByte(')')
	return builder.String()
}

// UIDs is a parsable slice of UID.
type UIDs []*UID

func (u UIDs) config(cfg config) {
	for _i := range u {
		u[_i].config = cfg
	}
}
