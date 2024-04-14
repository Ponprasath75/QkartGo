package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Cart holds the schema definition for the Cart entity.
type Cart struct {
	ent.Schema
}

type CartItem struct {
	ProductId string `json:"productId"`
	Quantity  int16 `json:"qty"`
}

// Fields of the Cart.
func (Cart) Fields() []ent.Field {
	return []ent.Field{
	field.String("username").Unique(),
	field.JSON("cart", []CartItem{}),
	}
}

// Edges of the Cart.
func (Cart) Edges() []ent.Edge {
	return nil
}
