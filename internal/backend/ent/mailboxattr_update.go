// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/ProtonMail/gluon/internal/backend/ent/mailboxattr"
	"github.com/ProtonMail/gluon/internal/backend/ent/predicate"
)

// MailboxAttrUpdate is the builder for updating MailboxAttr entities.
type MailboxAttrUpdate struct {
	config
	hooks    []Hook
	mutation *MailboxAttrMutation
}

// Where appends a list predicates to the MailboxAttrUpdate builder.
func (mau *MailboxAttrUpdate) Where(ps ...predicate.MailboxAttr) *MailboxAttrUpdate {
	mau.mutation.Where(ps...)
	return mau
}

// SetValue sets the "Value" field.
func (mau *MailboxAttrUpdate) SetValue(s string) *MailboxAttrUpdate {
	mau.mutation.SetValue(s)
	return mau
}

// Mutation returns the MailboxAttrMutation object of the builder.
func (mau *MailboxAttrUpdate) Mutation() *MailboxAttrMutation {
	return mau.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (mau *MailboxAttrUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(mau.hooks) == 0 {
		affected, err = mau.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*MailboxAttrMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			mau.mutation = mutation
			affected, err = mau.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(mau.hooks) - 1; i >= 0; i-- {
			if mau.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = mau.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, mau.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (mau *MailboxAttrUpdate) SaveX(ctx context.Context) int {
	affected, err := mau.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (mau *MailboxAttrUpdate) Exec(ctx context.Context) error {
	_, err := mau.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mau *MailboxAttrUpdate) ExecX(ctx context.Context) {
	if err := mau.Exec(ctx); err != nil {
		panic(err)
	}
}

func (mau *MailboxAttrUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   mailboxattr.Table,
			Columns: mailboxattr.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: mailboxattr.FieldID,
			},
		},
	}
	if ps := mau.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := mau.mutation.Value(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: mailboxattr.FieldValue,
		})
	}
	if n, err = sqlgraph.UpdateNodes(ctx, mau.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{mailboxattr.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// MailboxAttrUpdateOne is the builder for updating a single MailboxAttr entity.
type MailboxAttrUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *MailboxAttrMutation
}

// SetValue sets the "Value" field.
func (mauo *MailboxAttrUpdateOne) SetValue(s string) *MailboxAttrUpdateOne {
	mauo.mutation.SetValue(s)
	return mauo
}

// Mutation returns the MailboxAttrMutation object of the builder.
func (mauo *MailboxAttrUpdateOne) Mutation() *MailboxAttrMutation {
	return mauo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (mauo *MailboxAttrUpdateOne) Select(field string, fields ...string) *MailboxAttrUpdateOne {
	mauo.fields = append([]string{field}, fields...)
	return mauo
}

// Save executes the query and returns the updated MailboxAttr entity.
func (mauo *MailboxAttrUpdateOne) Save(ctx context.Context) (*MailboxAttr, error) {
	var (
		err  error
		node *MailboxAttr
	)
	if len(mauo.hooks) == 0 {
		node, err = mauo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*MailboxAttrMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			mauo.mutation = mutation
			node, err = mauo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(mauo.hooks) - 1; i >= 0; i-- {
			if mauo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = mauo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, mauo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*MailboxAttr)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from MailboxAttrMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (mauo *MailboxAttrUpdateOne) SaveX(ctx context.Context) *MailboxAttr {
	node, err := mauo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (mauo *MailboxAttrUpdateOne) Exec(ctx context.Context) error {
	_, err := mauo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mauo *MailboxAttrUpdateOne) ExecX(ctx context.Context) {
	if err := mauo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (mauo *MailboxAttrUpdateOne) sqlSave(ctx context.Context) (_node *MailboxAttr, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   mailboxattr.Table,
			Columns: mailboxattr.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: mailboxattr.FieldID,
			},
		},
	}
	id, ok := mauo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "MailboxAttr.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := mauo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, mailboxattr.FieldID)
		for _, f := range fields {
			if !mailboxattr.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != mailboxattr.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := mauo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := mauo.mutation.Value(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: mailboxattr.FieldValue,
		})
	}
	_node = &MailboxAttr{config: mauo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, mauo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{mailboxattr.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
