// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/ProtonMail/gluon/internal/db/ent/deletedsubscription"
	"github.com/ProtonMail/gluon/internal/db/ent/predicate"
)

// DeletedSubscriptionQuery is the builder for querying DeletedSubscription entities.
type DeletedSubscriptionQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.DeletedSubscription
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DeletedSubscriptionQuery builder.
func (dsq *DeletedSubscriptionQuery) Where(ps ...predicate.DeletedSubscription) *DeletedSubscriptionQuery {
	dsq.predicates = append(dsq.predicates, ps...)
	return dsq
}

// Limit adds a limit step to the query.
func (dsq *DeletedSubscriptionQuery) Limit(limit int) *DeletedSubscriptionQuery {
	dsq.limit = &limit
	return dsq
}

// Offset adds an offset step to the query.
func (dsq *DeletedSubscriptionQuery) Offset(offset int) *DeletedSubscriptionQuery {
	dsq.offset = &offset
	return dsq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dsq *DeletedSubscriptionQuery) Unique(unique bool) *DeletedSubscriptionQuery {
	dsq.unique = &unique
	return dsq
}

// Order adds an order step to the query.
func (dsq *DeletedSubscriptionQuery) Order(o ...OrderFunc) *DeletedSubscriptionQuery {
	dsq.order = append(dsq.order, o...)
	return dsq
}

// First returns the first DeletedSubscription entity from the query.
// Returns a *NotFoundError when no DeletedSubscription was found.
func (dsq *DeletedSubscriptionQuery) First(ctx context.Context) (*DeletedSubscription, error) {
	nodes, err := dsq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{deletedsubscription.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) FirstX(ctx context.Context) *DeletedSubscription {
	node, err := dsq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DeletedSubscription ID from the query.
// Returns a *NotFoundError when no DeletedSubscription ID was found.
func (dsq *DeletedSubscriptionQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dsq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{deletedsubscription.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) FirstIDX(ctx context.Context) int {
	id, err := dsq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DeletedSubscription entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DeletedSubscription entity is found.
// Returns a *NotFoundError when no DeletedSubscription entities are found.
func (dsq *DeletedSubscriptionQuery) Only(ctx context.Context) (*DeletedSubscription, error) {
	nodes, err := dsq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{deletedsubscription.Label}
	default:
		return nil, &NotSingularError{deletedsubscription.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) OnlyX(ctx context.Context) *DeletedSubscription {
	node, err := dsq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DeletedSubscription ID in the query.
// Returns a *NotSingularError when more than one DeletedSubscription ID is found.
// Returns a *NotFoundError when no entities are found.
func (dsq *DeletedSubscriptionQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dsq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{deletedsubscription.Label}
	default:
		err = &NotSingularError{deletedsubscription.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) OnlyIDX(ctx context.Context) int {
	id, err := dsq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DeletedSubscriptions.
func (dsq *DeletedSubscriptionQuery) All(ctx context.Context) ([]*DeletedSubscription, error) {
	if err := dsq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return dsq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) AllX(ctx context.Context) []*DeletedSubscription {
	nodes, err := dsq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DeletedSubscription IDs.
func (dsq *DeletedSubscriptionQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := dsq.Select(deletedsubscription.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) IDsX(ctx context.Context) []int {
	ids, err := dsq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dsq *DeletedSubscriptionQuery) Count(ctx context.Context) (int, error) {
	if err := dsq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return dsq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) CountX(ctx context.Context) int {
	count, err := dsq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dsq *DeletedSubscriptionQuery) Exist(ctx context.Context) (bool, error) {
	if err := dsq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return dsq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (dsq *DeletedSubscriptionQuery) ExistX(ctx context.Context) bool {
	exist, err := dsq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DeletedSubscriptionQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dsq *DeletedSubscriptionQuery) Clone() *DeletedSubscriptionQuery {
	if dsq == nil {
		return nil
	}
	return &DeletedSubscriptionQuery{
		config:     dsq.config,
		limit:      dsq.limit,
		offset:     dsq.offset,
		order:      append([]OrderFunc{}, dsq.order...),
		predicates: append([]predicate.DeletedSubscription{}, dsq.predicates...),
		// clone intermediate query.
		sql:    dsq.sql.Clone(),
		path:   dsq.path,
		unique: dsq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"Name,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.DeletedSubscription.Query().
//		GroupBy(deletedsubscription.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dsq *DeletedSubscriptionQuery) GroupBy(field string, fields ...string) *DeletedSubscriptionGroupBy {
	grbuild := &DeletedSubscriptionGroupBy{config: dsq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := dsq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return dsq.sqlQuery(ctx), nil
	}
	grbuild.label = deletedsubscription.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"Name,omitempty"`
//	}
//
//	client.DeletedSubscription.Query().
//		Select(deletedsubscription.FieldName).
//		Scan(ctx, &v)
func (dsq *DeletedSubscriptionQuery) Select(fields ...string) *DeletedSubscriptionSelect {
	dsq.fields = append(dsq.fields, fields...)
	selbuild := &DeletedSubscriptionSelect{DeletedSubscriptionQuery: dsq}
	selbuild.label = deletedsubscription.Label
	selbuild.flds, selbuild.scan = &dsq.fields, selbuild.Scan
	return selbuild
}

func (dsq *DeletedSubscriptionQuery) prepareQuery(ctx context.Context) error {
	for _, f := range dsq.fields {
		if !deletedsubscription.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dsq.path != nil {
		prev, err := dsq.path(ctx)
		if err != nil {
			return err
		}
		dsq.sql = prev
	}
	return nil
}

func (dsq *DeletedSubscriptionQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DeletedSubscription, error) {
	var (
		nodes = []*DeletedSubscription{}
		_spec = dsq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*DeletedSubscription).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &DeletedSubscription{config: dsq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dsq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (dsq *DeletedSubscriptionQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dsq.querySpec()
	_spec.Node.Columns = dsq.fields
	if len(dsq.fields) > 0 {
		_spec.Unique = dsq.unique != nil && *dsq.unique
	}
	return sqlgraph.CountNodes(ctx, dsq.driver, _spec)
}

func (dsq *DeletedSubscriptionQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := dsq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (dsq *DeletedSubscriptionQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   deletedsubscription.Table,
			Columns: deletedsubscription.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: deletedsubscription.FieldID,
			},
		},
		From:   dsq.sql,
		Unique: true,
	}
	if unique := dsq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := dsq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, deletedsubscription.FieldID)
		for i := range fields {
			if fields[i] != deletedsubscription.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := dsq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dsq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dsq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dsq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dsq *DeletedSubscriptionQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dsq.driver.Dialect())
	t1 := builder.Table(deletedsubscription.Table)
	columns := dsq.fields
	if len(columns) == 0 {
		columns = deletedsubscription.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dsq.sql != nil {
		selector = dsq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dsq.unique != nil && *dsq.unique {
		selector.Distinct()
	}
	for _, p := range dsq.predicates {
		p(selector)
	}
	for _, p := range dsq.order {
		p(selector)
	}
	if offset := dsq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dsq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// DeletedSubscriptionGroupBy is the group-by builder for DeletedSubscription entities.
type DeletedSubscriptionGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dsgb *DeletedSubscriptionGroupBy) Aggregate(fns ...AggregateFunc) *DeletedSubscriptionGroupBy {
	dsgb.fns = append(dsgb.fns, fns...)
	return dsgb
}

// Scan applies the group-by query and scans the result into the given value.
func (dsgb *DeletedSubscriptionGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := dsgb.path(ctx)
	if err != nil {
		return err
	}
	dsgb.sql = query
	return dsgb.sqlScan(ctx, v)
}

func (dsgb *DeletedSubscriptionGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range dsgb.fields {
		if !deletedsubscription.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := dsgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dsgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (dsgb *DeletedSubscriptionGroupBy) sqlQuery() *sql.Selector {
	selector := dsgb.sql.Select()
	aggregation := make([]string, 0, len(dsgb.fns))
	for _, fn := range dsgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(dsgb.fields)+len(dsgb.fns))
		for _, f := range dsgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(dsgb.fields...)...)
}

// DeletedSubscriptionSelect is the builder for selecting fields of DeletedSubscription entities.
type DeletedSubscriptionSelect struct {
	*DeletedSubscriptionQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (dss *DeletedSubscriptionSelect) Scan(ctx context.Context, v interface{}) error {
	if err := dss.prepareQuery(ctx); err != nil {
		return err
	}
	dss.sql = dss.DeletedSubscriptionQuery.sqlQuery(ctx)
	return dss.sqlScan(ctx, v)
}

func (dss *DeletedSubscriptionSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := dss.sql.Query()
	if err := dss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
