// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/ProtonMail/gluon/imap"
	"github.com/ProtonMail/gluon/internal/db/ent/mailbox"
	"github.com/ProtonMail/gluon/internal/db/ent/message"
	"github.com/ProtonMail/gluon/internal/db/ent/predicate"
	"github.com/ProtonMail/gluon/internal/db/ent/uid"
)

// UIDUpdate is the builder for updating UID entities.
type UIDUpdate struct {
	config
	hooks    []Hook
	mutation *UIDMutation
}

// Where appends a list predicates to the UIDUpdate builder.
func (uu *UIDUpdate) Where(ps ...predicate.UID) *UIDUpdate {
	uu.mutation.Where(ps...)
	return uu
}

// SetUID sets the "UID" field.
func (uu *UIDUpdate) SetUID(i imap.UID) *UIDUpdate {
	uu.mutation.ResetUID()
	uu.mutation.SetUID(i)
	return uu
}

// AddUID adds i to the "UID" field.
func (uu *UIDUpdate) AddUID(i imap.UID) *UIDUpdate {
	uu.mutation.AddUID(i)
	return uu
}

// SetDeleted sets the "Deleted" field.
func (uu *UIDUpdate) SetDeleted(b bool) *UIDUpdate {
	uu.mutation.SetDeleted(b)
	return uu
}

// SetNillableDeleted sets the "Deleted" field if the given value is not nil.
func (uu *UIDUpdate) SetNillableDeleted(b *bool) *UIDUpdate {
	if b != nil {
		uu.SetDeleted(*b)
	}
	return uu
}

// SetRecent sets the "Recent" field.
func (uu *UIDUpdate) SetRecent(b bool) *UIDUpdate {
	uu.mutation.SetRecent(b)
	return uu
}

// SetNillableRecent sets the "Recent" field if the given value is not nil.
func (uu *UIDUpdate) SetNillableRecent(b *bool) *UIDUpdate {
	if b != nil {
		uu.SetRecent(*b)
	}
	return uu
}

// SetMessageID sets the "message" edge to the Message entity by ID.
func (uu *UIDUpdate) SetMessageID(id imap.InternalMessageID) *UIDUpdate {
	uu.mutation.SetMessageID(id)
	return uu
}

// SetNillableMessageID sets the "message" edge to the Message entity by ID if the given value is not nil.
func (uu *UIDUpdate) SetNillableMessageID(id *imap.InternalMessageID) *UIDUpdate {
	if id != nil {
		uu = uu.SetMessageID(*id)
	}
	return uu
}

// SetMessage sets the "message" edge to the Message entity.
func (uu *UIDUpdate) SetMessage(m *Message) *UIDUpdate {
	return uu.SetMessageID(m.ID)
}

// SetMailboxID sets the "mailbox" edge to the Mailbox entity by ID.
func (uu *UIDUpdate) SetMailboxID(id imap.InternalMailboxID) *UIDUpdate {
	uu.mutation.SetMailboxID(id)
	return uu
}

// SetNillableMailboxID sets the "mailbox" edge to the Mailbox entity by ID if the given value is not nil.
func (uu *UIDUpdate) SetNillableMailboxID(id *imap.InternalMailboxID) *UIDUpdate {
	if id != nil {
		uu = uu.SetMailboxID(*id)
	}
	return uu
}

// SetMailbox sets the "mailbox" edge to the Mailbox entity.
func (uu *UIDUpdate) SetMailbox(m *Mailbox) *UIDUpdate {
	return uu.SetMailboxID(m.ID)
}

// Mutation returns the UIDMutation object of the builder.
func (uu *UIDUpdate) Mutation() *UIDMutation {
	return uu.mutation
}

// ClearMessage clears the "message" edge to the Message entity.
func (uu *UIDUpdate) ClearMessage() *UIDUpdate {
	uu.mutation.ClearMessage()
	return uu
}

// ClearMailbox clears the "mailbox" edge to the Mailbox entity.
func (uu *UIDUpdate) ClearMailbox() *UIDUpdate {
	uu.mutation.ClearMailbox()
	return uu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (uu *UIDUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(uu.hooks) == 0 {
		affected, err = uu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*UIDMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			uu.mutation = mutation
			affected, err = uu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(uu.hooks) - 1; i >= 0; i-- {
			if uu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = uu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, uu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (uu *UIDUpdate) SaveX(ctx context.Context) int {
	affected, err := uu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (uu *UIDUpdate) Exec(ctx context.Context) error {
	_, err := uu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uu *UIDUpdate) ExecX(ctx context.Context) {
	if err := uu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (uu *UIDUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   uid.Table,
			Columns: uid.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: uid.FieldID,
			},
		},
	}
	if ps := uu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := uu.mutation.UID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeUint32,
			Value:  value,
			Column: uid.FieldUID,
		})
	}
	if value, ok := uu.mutation.AddedUID(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeUint32,
			Value:  value,
			Column: uid.FieldUID,
		})
	}
	if value, ok := uu.mutation.Deleted(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: uid.FieldDeleted,
		})
	}
	if value, ok := uu.mutation.Recent(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: uid.FieldRecent,
		})
	}
	if uu.mutation.MessageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   uid.MessageTable,
			Columns: []string{uid.MessageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: message.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.MessageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   uid.MessageTable,
			Columns: []string{uid.MessageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: message.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uu.mutation.MailboxCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   uid.MailboxTable,
			Columns: []string{uid.MailboxColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUint64,
					Column: mailbox.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uu.mutation.MailboxIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   uid.MailboxTable,
			Columns: []string{uid.MailboxColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUint64,
					Column: mailbox.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, uu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{uid.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// UIDUpdateOne is the builder for updating a single UID entity.
type UIDUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *UIDMutation
}

// SetUID sets the "UID" field.
func (uuo *UIDUpdateOne) SetUID(i imap.UID) *UIDUpdateOne {
	uuo.mutation.ResetUID()
	uuo.mutation.SetUID(i)
	return uuo
}

// AddUID adds i to the "UID" field.
func (uuo *UIDUpdateOne) AddUID(i imap.UID) *UIDUpdateOne {
	uuo.mutation.AddUID(i)
	return uuo
}

// SetDeleted sets the "Deleted" field.
func (uuo *UIDUpdateOne) SetDeleted(b bool) *UIDUpdateOne {
	uuo.mutation.SetDeleted(b)
	return uuo
}

// SetNillableDeleted sets the "Deleted" field if the given value is not nil.
func (uuo *UIDUpdateOne) SetNillableDeleted(b *bool) *UIDUpdateOne {
	if b != nil {
		uuo.SetDeleted(*b)
	}
	return uuo
}

// SetRecent sets the "Recent" field.
func (uuo *UIDUpdateOne) SetRecent(b bool) *UIDUpdateOne {
	uuo.mutation.SetRecent(b)
	return uuo
}

// SetNillableRecent sets the "Recent" field if the given value is not nil.
func (uuo *UIDUpdateOne) SetNillableRecent(b *bool) *UIDUpdateOne {
	if b != nil {
		uuo.SetRecent(*b)
	}
	return uuo
}

// SetMessageID sets the "message" edge to the Message entity by ID.
func (uuo *UIDUpdateOne) SetMessageID(id imap.InternalMessageID) *UIDUpdateOne {
	uuo.mutation.SetMessageID(id)
	return uuo
}

// SetNillableMessageID sets the "message" edge to the Message entity by ID if the given value is not nil.
func (uuo *UIDUpdateOne) SetNillableMessageID(id *imap.InternalMessageID) *UIDUpdateOne {
	if id != nil {
		uuo = uuo.SetMessageID(*id)
	}
	return uuo
}

// SetMessage sets the "message" edge to the Message entity.
func (uuo *UIDUpdateOne) SetMessage(m *Message) *UIDUpdateOne {
	return uuo.SetMessageID(m.ID)
}

// SetMailboxID sets the "mailbox" edge to the Mailbox entity by ID.
func (uuo *UIDUpdateOne) SetMailboxID(id imap.InternalMailboxID) *UIDUpdateOne {
	uuo.mutation.SetMailboxID(id)
	return uuo
}

// SetNillableMailboxID sets the "mailbox" edge to the Mailbox entity by ID if the given value is not nil.
func (uuo *UIDUpdateOne) SetNillableMailboxID(id *imap.InternalMailboxID) *UIDUpdateOne {
	if id != nil {
		uuo = uuo.SetMailboxID(*id)
	}
	return uuo
}

// SetMailbox sets the "mailbox" edge to the Mailbox entity.
func (uuo *UIDUpdateOne) SetMailbox(m *Mailbox) *UIDUpdateOne {
	return uuo.SetMailboxID(m.ID)
}

// Mutation returns the UIDMutation object of the builder.
func (uuo *UIDUpdateOne) Mutation() *UIDMutation {
	return uuo.mutation
}

// ClearMessage clears the "message" edge to the Message entity.
func (uuo *UIDUpdateOne) ClearMessage() *UIDUpdateOne {
	uuo.mutation.ClearMessage()
	return uuo
}

// ClearMailbox clears the "mailbox" edge to the Mailbox entity.
func (uuo *UIDUpdateOne) ClearMailbox() *UIDUpdateOne {
	uuo.mutation.ClearMailbox()
	return uuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (uuo *UIDUpdateOne) Select(field string, fields ...string) *UIDUpdateOne {
	uuo.fields = append([]string{field}, fields...)
	return uuo
}

// Save executes the query and returns the updated UID entity.
func (uuo *UIDUpdateOne) Save(ctx context.Context) (*UID, error) {
	var (
		err  error
		node *UID
	)
	if len(uuo.hooks) == 0 {
		node, err = uuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*UIDMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			uuo.mutation = mutation
			node, err = uuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(uuo.hooks) - 1; i >= 0; i-- {
			if uuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = uuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, uuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*UID)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from UIDMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (uuo *UIDUpdateOne) SaveX(ctx context.Context) *UID {
	node, err := uuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (uuo *UIDUpdateOne) Exec(ctx context.Context) error {
	_, err := uuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uuo *UIDUpdateOne) ExecX(ctx context.Context) {
	if err := uuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (uuo *UIDUpdateOne) sqlSave(ctx context.Context) (_node *UID, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   uid.Table,
			Columns: uid.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: uid.FieldID,
			},
		},
	}
	id, ok := uuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "UID.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := uuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, uid.FieldID)
		for _, f := range fields {
			if !uid.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != uid.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := uuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := uuo.mutation.UID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeUint32,
			Value:  value,
			Column: uid.FieldUID,
		})
	}
	if value, ok := uuo.mutation.AddedUID(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeUint32,
			Value:  value,
			Column: uid.FieldUID,
		})
	}
	if value, ok := uuo.mutation.Deleted(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: uid.FieldDeleted,
		})
	}
	if value, ok := uuo.mutation.Recent(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: uid.FieldRecent,
		})
	}
	if uuo.mutation.MessageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   uid.MessageTable,
			Columns: []string{uid.MessageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: message.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.MessageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   uid.MessageTable,
			Columns: []string{uid.MessageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: message.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uuo.mutation.MailboxCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   uid.MailboxTable,
			Columns: []string{uid.MailboxColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUint64,
					Column: mailbox.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uuo.mutation.MailboxIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   uid.MailboxTable,
			Columns: []string{uid.MailboxColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUint64,
					Column: mailbox.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &UID{config: uuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, uuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{uid.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
