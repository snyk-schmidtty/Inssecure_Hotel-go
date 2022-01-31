package jwtauth

import (
	"context"
	"fmt"

	stdjwt "github.com/dgrijalva/jwt-go"
	"github.com/form3tech/innsecure"
	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/endpoint"
)

func NewMiddleware(signingString string) endpoint.Middleware {
	//newClaims := jwt.MapClaimsFactory
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			tokenString, ok := ctx.Value(jwt.JWTContextKey).(string)
			if !ok {
				return nil, jwt.ErrTokenContextMissing
			}

			/*	token, _, err := new(stdjwt.Parser).ParseUnverified(tokenString, newClaims())
				if err != nil {
					return nil, jwt.ErrTokenInvalid
				}*/

			fmt.Println("Token parsed successfully")
			token, err := new(stdjwt.Parser).ParseWithClaims(tokenString, &stdjwt.MapClaims{}, func(*stdjwt.Token) (interface{}, error) {
				return []byte("SigningString"), nil
			})

			if err != nil {
				return nil, jwt.ErrTokenInvalid

			}

			ctx = context.WithValue(ctx, jwt.JWTClaimsContextKey, token.Claims)
			mc := token.Claims.(stdjwt.MapClaims)
			hotelID := mc["hotel"].(float64)

			u := innsecure.User{
				Name:    mc["name"].(string),
				Admin:   mc["admin"].(bool),
				HotelID: int(hotelID),
			}
			ctx = context.WithValue(ctx, innsecure.UserContextKey, &u)

			return next(ctx, request)
		}
	}
}
