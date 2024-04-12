// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/Ponprasath75/QkartGoBackend/internal/ent/predicate"
	"github.com/Ponprasath75/QkartGoBackend/internal/ent/product"
)

// ProductUpdate is the builder for updating Product entities.
type ProductUpdate struct {
	config
	hooks    []Hook
	mutation *ProductMutation
}

// Where appends a list predicates to the ProductUpdate builder.
func (pu *ProductUpdate) Where(ps ...predicate.Product) *ProductUpdate {
	pu.mutation.Where(ps...)
	return pu
}

// SetName sets the "name" field.
func (pu *ProductUpdate) SetName(s string) *ProductUpdate {
	pu.mutation.SetName(s)
	return pu
}

// SetNillableName sets the "name" field if the given value is not nil.
func (pu *ProductUpdate) SetNillableName(s *string) *ProductUpdate {
	if s != nil {
		pu.SetName(*s)
	}
	return pu
}

// SetCategory sets the "category" field.
func (pu *ProductUpdate) SetCategory(s string) *ProductUpdate {
	pu.mutation.SetCategory(s)
	return pu
}

// SetNillableCategory sets the "category" field if the given value is not nil.
func (pu *ProductUpdate) SetNillableCategory(s *string) *ProductUpdate {
	if s != nil {
		pu.SetCategory(*s)
	}
	return pu
}

// SetImage sets the "image" field.
func (pu *ProductUpdate) SetImage(s string) *ProductUpdate {
	pu.mutation.SetImage(s)
	return pu
}

// SetNillableImage sets the "image" field if the given value is not nil.
func (pu *ProductUpdate) SetNillableImage(s *string) *ProductUpdate {
	if s != nil {
		pu.SetImage(*s)
	}
	return pu
}

// SetCost sets the "cost" field.
func (pu *ProductUpdate) SetCost(i int) *ProductUpdate {
	pu.mutation.ResetCost()
	pu.mutation.SetCost(i)
	return pu
}

// SetNillableCost sets the "cost" field if the given value is not nil.
func (pu *ProductUpdate) SetNillableCost(i *int) *ProductUpdate {
	if i != nil {
		pu.SetCost(*i)
	}
	return pu
}

// AddCost adds i to the "cost" field.
func (pu *ProductUpdate) AddCost(i int) *ProductUpdate {
	pu.mutation.AddCost(i)
	return pu
}

// SetRating sets the "rating" field.
func (pu *ProductUpdate) SetRating(i int) *ProductUpdate {
	pu.mutation.ResetRating()
	pu.mutation.SetRating(i)
	return pu
}

// SetNillableRating sets the "rating" field if the given value is not nil.
func (pu *ProductUpdate) SetNillableRating(i *int) *ProductUpdate {
	if i != nil {
		pu.SetRating(*i)
	}
	return pu
}

// AddRating adds i to the "rating" field.
func (pu *ProductUpdate) AddRating(i int) *ProductUpdate {
	pu.mutation.AddRating(i)
	return pu
}

// Mutation returns the ProductMutation object of the builder.
func (pu *ProductUpdate) Mutation() *ProductMutation {
	return pu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (pu *ProductUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, pu.sqlSave, pu.mutation, pu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pu *ProductUpdate) SaveX(ctx context.Context) int {
	affected, err := pu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (pu *ProductUpdate) Exec(ctx context.Context) error {
	_, err := pu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pu *ProductUpdate) ExecX(ctx context.Context) {
	if err := pu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pu *ProductUpdate) check() error {
	if v, ok := pu.mutation.Cost(); ok {
		if err := product.CostValidator(v); err != nil {
			return &ValidationError{Name: "cost", err: fmt.Errorf(`ent: validator failed for field "Product.cost": %w`, err)}
		}
	}
	if v, ok := pu.mutation.Rating(); ok {
		if err := product.RatingValidator(v); err != nil {
			return &ValidationError{Name: "rating", err: fmt.Errorf(`ent: validator failed for field "Product.rating": %w`, err)}
		}
	}
	return nil
}

func (pu *ProductUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := pu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(product.Table, product.Columns, sqlgraph.NewFieldSpec(product.FieldID, field.TypeString))
	if ps := pu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pu.mutation.Name(); ok {
		_spec.SetField(product.FieldName, field.TypeString, value)
	}
	if value, ok := pu.mutation.Category(); ok {
		_spec.SetField(product.FieldCategory, field.TypeString, value)
	}
	if value, ok := pu.mutation.Image(); ok {
		_spec.SetField(product.FieldImage, field.TypeString, value)
	}
	if value, ok := pu.mutation.Cost(); ok {
		_spec.SetField(product.FieldCost, field.TypeInt, value)
	}
	if value, ok := pu.mutation.AddedCost(); ok {
		_spec.AddField(product.FieldCost, field.TypeInt, value)
	}
	if value, ok := pu.mutation.Rating(); ok {
		_spec.SetField(product.FieldRating, field.TypeInt, value)
	}
	if value, ok := pu.mutation.AddedRating(); ok {
		_spec.AddField(product.FieldRating, field.TypeInt, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, pu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{product.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	pu.mutation.done = true
	return n, nil
}

// ProductUpdateOne is the builder for updating a single Product entity.
type ProductUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ProductMutation
}

// SetName sets the "name" field.
func (puo *ProductUpdateOne) SetName(s string) *ProductUpdateOne {
	puo.mutation.SetName(s)
	return puo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (puo *ProductUpdateOne) SetNillableName(s *string) *ProductUpdateOne {
	if s != nil {
		puo.SetName(*s)
	}
	return puo
}

// SetCategory sets the "category" field.
func (puo *ProductUpdateOne) SetCategory(s string) *ProductUpdateOne {
	puo.mutation.SetCategory(s)
	return puo
}

// SetNillableCategory sets the "category" field if the given value is not nil.
func (puo *ProductUpdateOne) SetNillableCategory(s *string) *ProductUpdateOne {
	if s != nil {
		puo.SetCategory(*s)
	}
	return puo
}

// SetImage sets the "image" field.
func (puo *ProductUpdateOne) SetImage(s string) *ProductUpdateOne {
	puo.mutation.SetImage(s)
	return puo
}

// SetNillableImage sets the "image" field if the given value is not nil.
func (puo *ProductUpdateOne) SetNillableImage(s *string) *ProductUpdateOne {
	if s != nil {
		puo.SetImage(*s)
	}
	return puo
}

// SetCost sets the "cost" field.
func (puo *ProductUpdateOne) SetCost(i int) *ProductUpdateOne {
	puo.mutation.ResetCost()
	puo.mutation.SetCost(i)
	return puo
}

// SetNillableCost sets the "cost" field if the given value is not nil.
func (puo *ProductUpdateOne) SetNillableCost(i *int) *ProductUpdateOne {
	if i != nil {
		puo.SetCost(*i)
	}
	return puo
}

// AddCost adds i to the "cost" field.
func (puo *ProductUpdateOne) AddCost(i int) *ProductUpdateOne {
	puo.mutation.AddCost(i)
	return puo
}

// SetRating sets the "rating" field.
func (puo *ProductUpdateOne) SetRating(i int) *ProductUpdateOne {
	puo.mutation.ResetRating()
	puo.mutation.SetRating(i)
	return puo
}

// SetNillableRating sets the "rating" field if the given value is not nil.
func (puo *ProductUpdateOne) SetNillableRating(i *int) *ProductUpdateOne {
	if i != nil {
		puo.SetRating(*i)
	}
	return puo
}

// AddRating adds i to the "rating" field.
func (puo *ProductUpdateOne) AddRating(i int) *ProductUpdateOne {
	puo.mutation.AddRating(i)
	return puo
}

// Mutation returns the ProductMutation object of the builder.
func (puo *ProductUpdateOne) Mutation() *ProductMutation {
	return puo.mutation
}

// Where appends a list predicates to the ProductUpdate builder.
func (puo *ProductUpdateOne) Where(ps ...predicate.Product) *ProductUpdateOne {
	puo.mutation.Where(ps...)
	return puo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (puo *ProductUpdateOne) Select(field string, fields ...string) *ProductUpdateOne {
	puo.fields = append([]string{field}, fields...)
	return puo
}

// Save executes the query and returns the updated Product entity.
func (puo *ProductUpdateOne) Save(ctx context.Context) (*Product, error) {
	return withHooks(ctx, puo.sqlSave, puo.mutation, puo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (puo *ProductUpdateOne) SaveX(ctx context.Context) *Product {
	node, err := puo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (puo *ProductUpdateOne) Exec(ctx context.Context) error {
	_, err := puo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (puo *ProductUpdateOne) ExecX(ctx context.Context) {
	if err := puo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (puo *ProductUpdateOne) check() error {
	if v, ok := puo.mutation.Cost(); ok {
		if err := product.CostValidator(v); err != nil {
			return &ValidationError{Name: "cost", err: fmt.Errorf(`ent: validator failed for field "Product.cost": %w`, err)}
		}
	}
	if v, ok := puo.mutation.Rating(); ok {
		if err := product.RatingValidator(v); err != nil {
			return &ValidationError{Name: "rating", err: fmt.Errorf(`ent: validator failed for field "Product.rating": %w`, err)}
		}
	}
	return nil
}

func (puo *ProductUpdateOne) sqlSave(ctx context.Context) (_node *Product, err error) {
	if err := puo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(product.Table, product.Columns, sqlgraph.NewFieldSpec(product.FieldID, field.TypeString))
	id, ok := puo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Product.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := puo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, product.FieldID)
		for _, f := range fields {
			if !product.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != product.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := puo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := puo.mutation.Name(); ok {
		_spec.SetField(product.FieldName, field.TypeString, value)
	}
	if value, ok := puo.mutation.Category(); ok {
		_spec.SetField(product.FieldCategory, field.TypeString, value)
	}
	if value, ok := puo.mutation.Image(); ok {
		_spec.SetField(product.FieldImage, field.TypeString, value)
	}
	if value, ok := puo.mutation.Cost(); ok {
		_spec.SetField(product.FieldCost, field.TypeInt, value)
	}
	if value, ok := puo.mutation.AddedCost(); ok {
		_spec.AddField(product.FieldCost, field.TypeInt, value)
	}
	if value, ok := puo.mutation.Rating(); ok {
		_spec.SetField(product.FieldRating, field.TypeInt, value)
	}
	if value, ok := puo.mutation.AddedRating(); ok {
		_spec.AddField(product.FieldRating, field.TypeInt, value)
	}
	_node = &Product{config: puo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, puo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{product.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	puo.mutation.done = true
	return _node, nil
}