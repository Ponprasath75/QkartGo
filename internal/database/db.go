package common

import (
	"fmt"
	"log"

	"github.com/Ponprasath75/QkartGoBackend/internal/ent"
	_ "github.com/lib/pq"
)


var EntClient *ent.Client


func InitDB() {
	fmt.Println("db.go func InitDB ran")
	// client, err := ent.Open("postgres","host=localhost port=5433 user=postgres dbname=qkartContainer password=Gopassword sslmode=disable")
	client, err := ent.Open("postgres","host=localhost port=5432 user=postgres dbname=QkartDB password=Gopassword sslmode=disable")
	if err!=nil{
		log.Fatalf("failed opening connection to postgres : %v" , err)
	}
	// defer client.Close()
	

	EntClient = client
}




