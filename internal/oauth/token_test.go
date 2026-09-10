package oauth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testTokenIssuer(t *testing.T) *TokenIssuer {
	t.Helper()
	issuer, err := NewTokenIssuer(
		"https://superfast.example.com",
		"https://superfast.example.com/mcp",
		[]byte(strings.Repeat("s", 48)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testTokenIdentity() TokenIdentity {
	return TokenIdentity{
		Subject:  "owner-subject",
		Email:    "owner@example.com",
		ClientID: "client-1",
		Scope:    "mcp",
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	issuer := testTokenIssuer(t)
	base := time.Unix(1_800_000_000, 0)
	issuer.now = func() time.Time { return base }
	token, err := issuer.MintAccessToken(testTokenIdentity(), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := issuer.VerifyAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if identity != testTokenIdentity() {
		t.Fatalf("identity=%+v", identity)
	}
}

func TestAccessTokenRejectsWrongIssuerAudienceAndSignature(t *testing.T) {
	issuer := testTokenIssuer(t)
	base := time.Unix(1_800_000_000, 0)
	issuer.now = func() time.Time { return base }
	identity := testTokenIdentity()
	claims := accessTokenClaims{
		TokenUse: "access", ClientID: identity.ClientID, Scope: identity.Scope, Email: identity.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://wrong.example.com", Audience: jwt.ClaimStrings{issuer.resource}, Subject: identity.Subject,
			IssuedAt: jwt.NewNumericDate(base), NotBefore: jwt.NewNumericDate(base), ExpiresAt: jwt.NewNumericDate(base.Add(time.Hour)),
		},
	}
	wrongIssuer, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(issuer.secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.VerifyAccessToken(wrongIssuer); err == nil {
		t.Fatal("wrong issuer token accepted")
	}
	claims.Issuer = issuer.issuer
	claims.Audience = jwt.ClaimStrings{"https://wrong.example.com/mcp"}
	wrongAudience, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(issuer.secret)
	if _, err := issuer.VerifyAccessToken(wrongAudience); err == nil {
		t.Fatal("wrong audience token accepted")
	}
	claims.Audience = jwt.ClaimStrings{issuer.resource}
	wrongSignature, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(strings.Repeat("x", 48)))
	if _, err := issuer.VerifyAccessToken(wrongSignature); err == nil {
		t.Fatal("wrong signature token accepted")
	}
}

func TestAccessTokenRejectsExpiredAndFutureNBF(t *testing.T) {
	issuer := testTokenIssuer(t)
	base := time.Unix(1_800_000_000, 0)
	issuer.now = func() time.Time { return base }
	token, err := issuer.MintAccessToken(testTokenIdentity(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := issuer.VerifyAccessToken(token); err == nil {
		t.Fatal("expired token accepted")
	}

	issuer.now = func() time.Time { return base }
	identity := testTokenIdentity()
	claims := accessTokenClaims{
		TokenUse: "access", ClientID: identity.ClientID, Scope: identity.Scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer.issuer, Audience: jwt.ClaimStrings{issuer.resource}, Subject: identity.Subject,
			IssuedAt: jwt.NewNumericDate(base), NotBefore: jwt.NewNumericDate(base.Add(5 * time.Minute)), ExpiresAt: jwt.NewNumericDate(base.Add(time.Hour)),
		},
	}
	future, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(issuer.secret)
	if _, err := issuer.VerifyAccessToken(future); err == nil {
		t.Fatal("future-nbf token accepted")
	}
}

func TestAccessTokenRejectsWrongUseMissingSubjectAndMissingClient(t *testing.T) {
	issuer := testTokenIssuer(t)
	base := time.Unix(1_800_000_000, 0)
	issuer.now = func() time.Time { return base }
	baseClaims := accessTokenClaims{
		TokenUse: "access", ClientID: "client-1", Scope: "mcp",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer.issuer, Audience: jwt.ClaimStrings{issuer.resource}, Subject: "owner-subject",
			IssuedAt: jwt.NewNumericDate(base), NotBefore: jwt.NewNumericDate(base), ExpiresAt: jwt.NewNumericDate(base.Add(time.Hour)),
		},
	}
	cases := []accessTokenClaims{baseClaims, baseClaims, baseClaims}
	cases[0].TokenUse = "refresh"
	cases[1].Subject = ""
	cases[2].ClientID = ""
	for i, claims := range cases {
		token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(issuer.secret)
		if _, err := issuer.VerifyAccessToken(token); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
