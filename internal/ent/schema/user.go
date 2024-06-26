package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("username").Unique(),
		field.String("password"),
		field.String("id").Unique(),
		field.String("address"),
		field.Int("balance").Positive(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return nil
}