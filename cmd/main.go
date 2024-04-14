package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"crypto/sha256"

	common "github.com/Ponprasath75/QkartGoBackend/internal/database"
	ent "github.com/Ponprasath75/QkartGoBackend/internal/ent"
	"github.com/Ponprasath75/QkartGoBackend/internal/ent/cart"
	"github.com/Ponprasath75/QkartGoBackend/internal/ent/schema"
	"github.com/Ponprasath75/QkartGoBackend/internal/ent/user"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Product struct {
	name     string
	category string
	cost     int64
	rating   int16
	image    string
	_id      string
}

var ctx context.Context

type User struct {
	username  string
	password  string
	balance   int64
	addresses string
	_id       string
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Balance  int32  `json:"balance"`
	Success  bool   `json:"success"`
	Token    string `json:"token"`
	Username string `json:"username"`
}

func main() {
	fmt.Println("main.go func main ran")
	common.InitDB()
	// Test()

	// ctx:=context.Background()

	router := gin.Default()
	router.Use(CORSMiddleware())

	if err := common.EntClient.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}

	// .Query().All().Only(ctx)
	router.GET("/api/v1/products", GetProducts)
	router.POST("/api/v1/auth/register", UserRegistration)
	router.POST("api/v1/auth/login", UserLogin)
	router.POST("api/v1/cart", AddToCart)
	router.GET("api/v1/cart", GetCart)

	router.Run()

	// if err = CreateProduct(ctx, client); err != nil {
	// 	log.Fatal(err)
	// }

	// if err = CreateCart(ctx, client); err != nil {
	// 	log.Fatal(err)
	// }

}

//	func Test() {
//		fmt.Println("called Test")
//		cart,err:= common.EntClient.Cart.Create().SetUsername("Test").SetCart([]schema.CartItem{{ProductId:"BW0jAAeDJmlZCF8i",Quantity:3},{ProductId:"y4sLtEcMpzabRyfx",Quantity:8}}).Save(context.Background())
//		if err!=nil{
//			fmt.Println(err)
//		}
//		fmt.Println(cart)
//	}
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// func CreateProduct(ctx context.Context, client *ent.Client) (error){

// 	var errVal error
// 	productJson := []Product {{name:"UNIFACTOR Mens Running Shoes",category:"Fashion",cost:50,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/42d4d057-8704-4174-8d74-e5e9052677c6.png",_id:"BW0jAAeDJmlZCF8i"},
// 	{name:"YONEX Smash Badminton Racquet",category:"Sports",cost:100,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/64b930f7-3c82-4a29-a433-dbc6f1493578.png",_id:"KCRwjF7lN97HnEaY"},
// 	{name:"Tan Leatherette Weekender Duffle",category:"Fashion",cost:150,rating:4,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/ff071a1c-1099-48f9-9b03-f858ccc53832.png",_id:"PmInA797xJhMIPti"},
// 	{name:"The Minimalist Slim Leather Watch",category:"Electronics",cost:60,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/5b478a4a-bf81-467c-964c-1881887799b7.png",_id:"TwMM4OAhmK0VQ93S"},
// 	{name:"Atomberg 1200mm BLDC motor",category:"Home & Kitchen",cost:80,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/e8e0832c-8f16-4468-95a0-8aaed387a169.png",_id:"a4sLtEcMpzabRyfx"},
// 	{name:"Bonsai Spirit Tree Table Lamp",category:"Home & Kitchen",cost:80,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/b49ee2dc-6458-42de-851d-b014ac24cd8e.png",_id:"upLK9JbQ4rMhTwt4"},
//     {name:"Stylecon 9 Seater RHS Sofa Set ",category:"Home & Kitchen",cost:650,rating:3,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/7ad56699-20c9-4778-a783-4021e5f0864c.png",_id:"v4sLtEcMpzabRyf"},
// 	{name:"Diamond Pendant (0.01 ct, IJ-SI)",category:"Fashion",cost:1000,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/95d6d42d-3a37-4efb-ad10-3bcbbb599856.png",_id:"v4sLtEcMpzabRyfx"},
// 	{name:"Apple iPad Pro with Apple M1 chip",category:"Electronics",cost:900,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/82ac2e7b-e4dd-4a5b-8dbc-3260225d7eb2.png",_id:"w4sLtEcMpzabRyfx"},
// 	{name:"OnePlus (55 inches) Q1 Series 4K",category:"Electronics",cost:1200,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/a9ca1e8b-8783-4be3-83f8-d06409016e15.png",_id:"x4sLtEcMpzabRyfx"},
// 	{name:"Thinking, Fast and Slow",category:"Books",cost:15,rating:5,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/cdb64440-5e95-4aaa-858b-8c12ee316d93.png",_id:"y4sLtEcMpzabRyfx"},
// 	{name:"GREY DOUBLE BUTTON BLAZER",category:"Fashion",cost:75,rating:4,image:"https://crio-directus-assets.s3.ap-south-1.amazonaws.com/869ec5e2-52d2-4b8e-bc6b-57eace9ab39e.png",_id:"z4sLtEcMpzabRyfx"}}

// 	for key,value :=range productJson{
// 		fmt.Println(key,value)
// 		p, err := client.Product.Create().
// 		SetName(value.name).
// 		SetCategory(value.category).
// 		SetCost(int(value.cost)).
// 		SetID(value._id).
// 		SetImage(value.image).
// 		SetRating(int(value.rating)).
// 		Save(ctx)
// 		if err!=nil{
// 			errVal=err
// 			break
// 		}
// 		log.Println("Product was created: ", p)
// 	}
// 	return errVal
// 	// p,err := client.Product.Create().se
// }

func GetProducts(c *gin.Context) {
	// common.EntClient.Product.Query().Where(product.ID("a4sLtEcMpzabRyfx")).Only(context.Background())
	product, err := common.EntClient.Product.Query().All(context.Background())
	if err != nil {
		log.Fatalln("Query failed")
	}
	log.Println("user returned: ", product)
	c.JSON(http.StatusOK, product)
	//  return nil
	// c.Status(200).JSON(common.EntClient.Product.Query().All())
	// c.String(http.StatusOK,JSON(common.EntClient.Product.Query().All()))

	// c.String(http.StatusOK, "Hello World!")

}

func UserRegistration(c *gin.Context) {
	var login Login
	if err := c.BindJSON(&login); err != nil {
		c.JSON(http.StatusInternalServerError, "Error getting data")
		return
	}
	if login.Username == "" || login.Password == "" {
		c.JSON(http.StatusBadRequest, "Please provide valid data")
		return
	}
	query, err := common.EntClient.User.Query().Where(user.UsernameIn(login.Username)).Only(context.Background())

	if ent.IsNotFound(err) {
		password := sha256.Sum256([]byte(login.Password))
		encryptedPass := hex.EncodeToString(password[:])
		id := uuid.NewString()
		log.Println(password, id, login.Username, login.Password)
		u, err := common.EntClient.User.Create().
			SetUsername(login.Username).
			SetPassword(encryptedPass).
			SetBalance(5000).
			SetAddress("").
			SetID(id).
			Save(context.Background())

		if err != nil {
			log.Println(err)
			c.JSON(http.StatusInternalServerError, "Unable to create user at this time")
			return
		}

		log.Println("User was created: ", u)
		c.JSON(http.StatusCreated, "User Created Successfully")
	} else {
		log.Println("Unable to register user:", err)
		c.JSON(http.StatusBadRequest, "User Registration ")
		return
	}

	if query != nil {
		log.Println(query)
		c.JSON(http.StatusBadRequest, "UserName Already Exists")
		return
	}

}

func UserLogin(c *gin.Context) {
	var login Login
	var lr LoginResponse
	if err := c.BindJSON(&login); err != nil {
		c.JSON(http.StatusInternalServerError, "Error getting data")
		return
	}

	if login.Username == "" || login.Password == "" {
		c.JSON(http.StatusBadRequest, "Please provide valid data")
		return
	}

	query, err := common.EntClient.User.Query().Where(user.UsernameIn(login.Username)).Only(context.Background())

	if ent.IsNotFound(err) {
		c.JSON(http.StatusForbidden, "Username/Password is incorrect")
		fmt.Println("Username Wrong")
		return
	} else {
		fmt.Println(query.Password, login.Password)
		if query.Password != login.Password {
			c.JSON(http.StatusForbidden, "Username/Password is incorrect")
			fmt.Println("Password Wrong")
			return
		}

		// t:=time.Now().Add(time.Hour*6)
		// year:=t.Year()
		// month:=t.Month()
		// day:=t.Day()
		// hour:=t.Hour()
		// minute:=t.Minute()
		// second:=t.Second()
		// timestamp := time.Date(year, month, day , hour , minute , second, 0, time.UTC)
		claims := &jwt.RegisteredClaims{
			Issuer:    "Qkart",
			Subject:   login.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString([]byte("The secret key"))

		if err != nil {
			c.JSON(http.StatusInternalServerError, "Internal Server Error")
		}
		lr = LoginResponse{
			Success:  true,
			Balance:  int32(query.Balance),
			Token:    ss,
			Username: login.Username,
		}
		fmt.Println(lr)
		c.JSONP(http.StatusOK, lr)
	}

}

func GetCart(c *gin.Context) {
	CartItems := []schema.CartItem{}
	val := c.GetHeader("Authorization")
	fmt.Println(val)
	username, err := VerifyToken(strings.Split(val, " ")[1])

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusForbidden, "Missing/Invalid Token")
	}

	query, err := common.EntClient.Cart.Query().Where(cart.UsernameEQ(username)).Only(context.Background())

	if ent.IsNotFound(err) {
		c.JSON(http.StatusOK, CartItems)
		return
	}

	c.JSON(http.StatusOK, query.Cart)
	return
}

func AddToCart(c *gin.Context) {
	val := c.GetHeader("Authorization")
	fmt.Println(val)
	username, err := VerifyToken(strings.Split(val, " ")[1])

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusForbidden, "Missing/Invalid Token")
	}
	// fmt.Println(strings.Split(val, " ")[2])
	var CartItems schema.CartItem

	if err := c.BindJSON(&CartItems); err != nil {
		c.JSON(http.StatusInternalServerError, "Error getting data")
		return
	}

	query, err := common.EntClient.Cart.Query().Where(cart.UsernameEQ(username)).Only(context.Background())

	if ent.IsNotFound(err) {
		_, err := common.EntClient.Cart.Create().SetUsername(username).SetCart([]schema.CartItem{CartItems}).Save(context.Background())

		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, "Can't process the request at the moment")
			return
		}

		c.JSON(http.StatusOK, "Cart successfully modified")
		return
		// c.JSON(http.StatusForbidden,"Username/Password is incorrect")
		// fmt.Println("Username Wrong")
		// return
	} else {
		cartItems := query.Cart
		var newCartItems []schema.CartItem

		for _, val := range cartItems {
			if val.ProductId != CartItems.ProductId {
				newCartItems = append(newCartItems, val)
			}
		}

		if CartItems.Quantity != 0 {
			newCartItems = append(newCartItems, CartItems)
		}

		if len(newCartItems) == 0 {
			deletedCart, err := common.EntClient.Cart.Delete().Where(cart.UsernameEQ(username)).Exec(context.Background())
			if err != nil {
				fmt.Println(err)
				c.JSON(http.StatusInternalServerError, "Cart cannot be modified at the moment")
				return
			}
			fmt.Println(deletedCart)
		} else {
			updatedCart, err := common.EntClient.Cart.Update().SetCart(newCartItems).Where(cart.UsernameEQ(username)).Save(context.Background())

			if err != nil {
				fmt.Println(err)
				c.JSON(http.StatusInternalServerError, "Cart cannot be modified at the moment")
				return
			}

			fmt.Println(updatedCart)
		}
		c.JSON(http.StatusOK, "Cart successfully modified")
		return
	}

	// fmt.Println(CartItems)

}

func VerifyToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) { return []byte("The secret key"), nil }, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		return claims.Subject, nil
	} else {
		return "", fmt.Errorf("unknown claims type, cannot proceed")
	}

}
