package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/expr-lang/expr"
	"github.com/framjet/go-cloudflare-access-external-evaluation/cmd/framjet-cfa-ex-eval/api"
	"github.com/framjet/go-cloudflare-access-external-evaluation/cmd/framjet-cfa-ex-eval/cliutil"
	"github.com/framjet/go-cloudflare-access-external-evaluation/cmd/framjet-cfa-ex-eval/metrics"
	jwtlib "github.com/golang-jwt/jwt/v4"
	jwxjwt "github.com/lestrrat-go/jwx/jwt"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"log"
	"net/http"
	"os"
)

var (
	Version   = "DEV"
	BuildTime = "unknown"
	BuildType = ""
	Runtime   = "host"

	// jwkURL is the remote URL from which to fetch the JWK set for verifying tokens.
	jwkURL string
	// Our signing keys loaded at startup.
	privKey      *rsa.PrivateKey
	pubKey       []byte
	pubJwkKey    jwk.Key
	pubKeyKid    string
	programCache CompiledProgramCache
	tokenExp     time.Duration
)

// loadPrivateKey loads an RSA private key from a PEM file.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block from private key")
	}
	// Try PKCS1 first.
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}
	// Otherwise, try PKCS8.
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaPriv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}
	return rsaPriv, nil
}

// loadPublicKey loads a public key from a PEM file. The PEM is expected to be in PKIX format.
func loadPublicKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading public key file: %w", err)
	}

	pubKey = data

	pubJwkKey, err = jwk.ParseKey(data, jwk.WithPEM(true))
	if err != nil {
		return fmt.Errorf("failed to parse public key as JWK: %w", err)
	}

	kid, err := pubJwkKey.Thumbprint(crypto.SHA1)
	if err != nil {
		return fmt.Errorf("failed to compute key thumbprint: %w", err)
	}

	pubKeyKid = hex.EncodeToString(kid)

	_ = pubJwkKey.Set("alg", "RS256")
	_ = pubJwkKey.Set("use", "sig")
	_ = pubJwkKey.Set("kid", pubKeyKid)

	return nil
}

func httpError(w http.ResponseWriter, msg string, code int) {
	resp, err := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   msg,
		"code":    code,
	})

	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)

		return
	}

	http.Error(w, string(resp), code)
}

func keysHandler(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	var resp struct {
		Keys       []jwk.Key `json:"keys"`
		PublicCert struct {
			Kid  string `json:"kid"`
			Cert string `json:"cert"`
		} `json:"public_cert"`
		PublicCerts []struct {
			Kid  string `json:"kid"`
			Cert string `json:"cert"`
		}
	}

	resp.Keys = append(resp.Keys, pubJwkKey)
	resp.PublicCert.Kid = pubKeyKid
	resp.PublicCert.Cert = string(pubKey)
	resp.PublicCerts = append(resp.PublicCerts, resp.PublicCert)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		httpError(w, "internal server error", http.StatusInternalServerError)
		logger.WithError(err).Error("failed to encode public key to response")
		return
	}

	logger.Info("public keys sent successfully")
}

// postHandler handles POST requests. It expects the URL to include a base64-encoded expression
// and a JSON body with the field "token". The provided token is verified against the JWK set
// from the URL specified in the CLI flag. If the expr-lang expression evaluates to true, a new JWT
// with payload {"result": true, "iat": ..., "exp": now() + 60} is created and signed with our private key.
func postHandler(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithContext(r.Context())
	vars := mux.Vars(r)
	exprBase64 := vars["expr"]
	if exprBase64 == "" {
		exprBase64 = "MSAhPSAxCg" // 1 != 1
	}

	// Decode the base64 expression.
	exprBytes, err := base64.URLEncoding.DecodeString(exprBase64)
	if err != nil {
		// Try without padding.
		exprBytes, err = base64.RawURLEncoding.DecodeString(exprBase64)
		if err != nil {
			http.Error(w, "failed to decode base64 expression", http.StatusBadRequest)
			logger.WithError(err).Error("failed to decode base64 expression")
			return
		}
	}
	exprString := strings.Trim(string(exprBytes), " \r\n\t")
	logger = logger.WithField("expression", exprString)

	// Parse the JSON body. It must include the "token" field.
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		logger.WithError(err).Error("invalid JSON body")
		return
	}
	if body.Token == "" {
		http.Error(w, "missing token in body", http.StatusBadRequest)
		logger.Error("missing token in body")
		return
	}

	logger.WithField("token", body.Token).Debug("token received")

	// Fetch the JWK set from the provided URL.
	keySet, err := jwk.Fetch(r.Context(), jwkURL)
	if err != nil {
		http.Error(w, "failed to fetch JWK set", http.StatusInternalServerError)
		logger.WithError(err).Error("failed to fetch JWK set")
		return
	}

	// Verify and parse the provided token using the fetched JWK set.
	tokenResult, err := jwxjwt.ParseString(body.Token, jwxjwt.WithKeySet(keySet))
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		logger.WithError(err).Error("invalid token")
		return
	}
	// Token is verified at this point.
	logger.Info("token verified successfully")

	// Compile the expression using expr-lang.
	program, err := programCache.GetOrCompile(exprString)
	if err != nil {
		http.Error(w, "failed to compile expression: "+err.Error(), http.StatusBadRequest)
		logger.WithError(err).Error("failed to compile expression")
		return
	}

	var exprResult = false

	env, err := tokenResult.AsMap(r.Context())
	if err != nil {
		http.Error(w, "failed to convert token to map: "+err.Error(), http.StatusBadRequest)
		logger.WithError(err).Error("failed to convert token to map")
		return
	}

	logger.WithField("env", env).Debug("trying to run expression with env")

	output, err := expr.Run(program, env)
	if err != nil {
		logger.WithError(err).Error("failed to run expression")

		exprResult = false
	} else {
		boolResult, ok := output.(bool)
		if !ok {
			http.Error(w, "expression did not evaluate to a boolean", http.StatusBadRequest)
			logger.Error("expression did not evaluate to a boolean")
			return
		}
		if !boolResult {
			logger.Error("expression evaluated to false")
		} else {
			logger.Info("expression evaluated to true")
		}

		exprResult = boolResult
	}

	nonce, empty := tokenResult.Get("nonce")
	if !empty {
		http.Error(w, "failed to get nonce from token", http.StatusBadRequest)
		logger.WithError(err).Error("failed to get nonce from token")
		return
	}

	// If the expression evaluates to true, create a new JWT with the payload.
	newToken := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"success": exprResult,
		"nonce":   nonce,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(tokenExp).Unix(),
	})

	newToken.Header["kid"] = pubKeyKid

	signedToken, err := newToken.SignedString(privKey)

	if err != nil {
		http.Error(w, "failed to sign new token", http.StatusInternalServerError)
		logger.WithError(err).Error("failed to sign new token")
		return
	}

	logger.WithField("token", signedToken).Debug("signed token")

	// Return the signed token as JSON.
	resp := map[string]string{"token": signedToken}
	w.Header().Set("Content-Type", "application/json")
	// serialize the response to string
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		logger.WithError(err).Error("failed to encode response")
	}
	_, _ = w.Write(jsonResp)

	logger.Info("new token issued successfully")
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logrus.WithError(err).Error("failed to encode health check response")
	}
}

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)

	bInfo := cliutil.GetBuildInfo(BuildType, Version)

	cmd := &cli.Command{
		Name:      "FramJet Cloudflare Access External Evaluation Server",
		Usage:     "A simple HTTP server that evaluates expressions based on Cloudflare Access tokens with Expr-lang expressions",
		UsageText: "framjet-cfa-ex-eval [options]",
		Version:   fmt.Sprintf("%s (built %s%s)", Version, BuildTime, bInfo.GetBuildTypeMsg()),
		Copyright: fmt.Sprintf(
			`(c) %d FramJet.
   Your installation of this software constitutes a symbol of your signature indicating that you accept
   the terms of the MIT (https://github.com/framjet/go-cloudflare-access-external-evaluation?tab=MIT-1-ov-file).`, time.Now().Year(),
		),
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "jwk",
				Usage:    "URL to fetch JWK set for verifying incoming tokens (https://<team_name>.cloudflareaccess.com/cdn-cgi/access/certs)",
				Required: true,
				Sources:  cli.EnvVars("JWK_URL"),
			},
			&cli.StringFlag{
				Name:     "private-key",
				Usage:    "Path to private PEM key used for signing tokens",
				Required: true,
				Sources:  cli.EnvVars("PRIVATE_KEY"),
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					if _, err := os.Stat(v); os.IsNotExist(err) {
						return fmt.Errorf("private key file does not exist: %s", v)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:     "public-key",
				Usage:    "Path to public PEM key (exposed at /keys)",
				Required: true,
				Sources:  cli.EnvVars("PUBLIC_KEY"),
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					if _, err := os.Stat(v); os.IsNotExist(err) {
						return fmt.Errorf("public key file does not exist: %s", v)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:    "host",
				Aliases: []string{"s"},
				Usage:   "HTTP network address",
				Value:   "0.0.0.0",
				Sources: cli.EnvVars("HTTP_HOST"),
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "HTTP network port",
				Value:   8000,
				Sources: cli.EnvVars("HTTP_PORT"),
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					if v < 1 || v > 65535 {
						return fmt.Errorf("invalid port number: %d", v)
					}

					return nil
				},
			},
			&cli.IntFlag{
				Name:    "cache-size",
				Usage:   "Size of the compiled expression cache",
				Value:   100,
				Sources: cli.EnvVars("CACHE_SIZE"),
			},
			&cli.IntFlag{
				Name:    "rate-limit",
				Usage:   "Rate limit for the API",
				Value:   50,
				Sources: cli.EnvVars("RATE_LIMIT"),
			},
			&cli.DurationFlag{
				Name:    "token-expiration",
				Usage:   "Expiration time for signed tokens",
				Value:   60 * time.Second,
				Sources: cli.EnvVars("TOKEN_EXPIRATION"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set log level (debug, info, warn, error, fatal, panic)",
				Value:   "info",
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Enable verbose logging (overrides log-level to debug)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Disable all logging (overrides log-level to panic)",
				Value:   false,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			logLevelStr := c.String("log-level")
			if c.Bool("verbose") {
				logLevelStr = "debug"
			}
			level, err := logrus.ParseLevel(logLevelStr)
			if err != nil {
				return fmt.Errorf("invalid log level: %w", err)
			}
			logrus.SetLevel(level)
			logrus.WithField("log_level", logrus.GetLevel().String()).Info("log level set")

			jwkURL = c.String("jwk")
			privKeyPath := c.String("private-key")
			pubKeyPath := c.String("public-key")
			addr := fmt.Sprintf("%s:%d", c.String("host"), c.Int("port"))
			tokenExp = c.Duration("token-expiration")

			logrus.WithFields(logrus.Fields{
				"jwk_url":     jwkURL,
				"private_key": privKeyPath,
				"public_key":  pubKeyPath,
				"addr":        addr,
			}).Info("starting JWT server with provided configuration")

			// Load RSA keys.
			var errKey error
			privKey, errKey = loadPrivateKey(privKeyPath)
			if errKey != nil {
				return fmt.Errorf("failed to load private key: %w", errKey)
			}
			errKey = loadPublicKey(pubKeyPath)
			if errKey != nil {
				return fmt.Errorf("failed to load public key: %w", errKey)
			}

			programCache, err = NewCompiledProgramCache(int(c.Int("cache-size")))
			if err != nil {
				logrus.WithError(err).Error("failed to create program cache")
				return err
			}

			r := mux.NewRouter()
			metrics.SetupMetrics(r)
			api.SetupRateLimit(int(c.Int("rate-limit")), r)

			r.HandleFunc("/status", healthCheckHandler).Methods("GET")
			r.HandleFunc("/keys", keysHandler).Methods("GET")
			r.HandleFunc("/{expr:.*}", postHandler).Methods("POST")
			r.NotFoundHandler = r.NewRoute().HandlerFunc(http.NotFound).GetHandler()

			logrus.WithField("addr", addr).Info("http server is starting")

			srv := &http.Server{
				Addr:    addr,
				Handler: r,
			}

			go func() {
				if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					log.Fatalf("listen: %s\n", err)
				}
			}()

			// Wait for interrupt signal
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, os.Interrupt)
			<-quit

			// Gracefully shutdown the server
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				log.Fatal("Server forced to shutdown:", err)
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
