package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Product holds the schema definition for the Product entity.
type Product struct {
	ent.Schema
}

// Fields of the Product.
func (Product) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique(),
		field.String("category"),
		field.String("id").Unique(),
		field.String("image"),
		field.Int("cost").Positive(),
		field.Int("rating").Positive(),
	}
}

// Edges of the Product.
func (Product) Edges() []ent.Edge {
	return nil
}
