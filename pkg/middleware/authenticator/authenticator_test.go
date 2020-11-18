package authenticator

import (
	"bytes"
	"context"
	"github.com/go-chi/chi"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticatorHTTPMux(t *testing.T) {
	mux := http.NewServeMux()
	authenticatorMd := Authenticator(func(ctx context.Context) (*string, error) {
		id := "192.0.2.1"
		return &id, nil
	}, func(ctx context.Context, id *string) (interface{}, error) {
		return "USERAUTH", nil
	})
	mux.Handle(
		"/get",
		authenticatorMd(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			profile, err := Authentication(request.Context())
			if err != nil {
				t.Fatal(err)
			}
			data := profile.(string)

			_, err = writer.Write([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
		})),
	)

	type args struct {
		method string
		path   string
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{name: "GET", args: args{method: "GET", path: "/get"}, want: []byte("USERAUTH")},
		{name: "POST", args: args{method: "POST", path: "/get"}, want: []byte("USERAUTH")},
		{name: "PUT", args: args{method: "PUT", path: "/get"}, want: []byte("USERAUTH")},
		{name: "DELETE", args: args{method: "DELETE", path: "/get"}, want: []byte("USERAUTH")},
	}

	for _, tt := range tests {
		request := httptest.NewRequest(tt.args.method, tt.args.path, nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		got := response.Body.Bytes()
		if !bytes.Equal(tt.want, got) {
			t.Errorf("got %s, want %s", got, tt.want)
		}
	}
}

func TestNoAuthenticatorHTTPMux(t *testing.T) {
	mux := http.NewServeMux()
	authenticatorMd := Authenticator(func(ctx context.Context) (*string, error) {
		id := "192.0.2.1"
		return &id, nil
	}, func(ctx context.Context, id *string) (interface{}, error) {
		return nil, ErrNoAuthentication
	})
	mux.Handle(
		"/get",
		authenticatorMd(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			profile, err := Authentication(request.Context())
			if err != nil {
				t.Fatal(err)
			}
			data := profile.(string)

			_, err = writer.Write([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
		})),
	)

	type args struct {
		method string
		path   string
	}

	tests := []struct {
		name string
		args args
		want []byte
		code int
	}{
		{name: "GET", args: args{method: "GET", path: "/get"}, want: []byte(""), code: 401},
		{name: "POST", args: args{method: "POST", path: "/get"}, want: []byte(""), code: 401},
		{name: "PUT", args: args{method: "PUT", path: "/get"}, want: []byte(""), code: 401},
		{name: "DELETE", args: args{method: "DELETE", path: "/get"}, want: []byte(""), code: 401},
	}

	for _, tt := range tests {
		request := httptest.NewRequest(tt.args.method, tt.args.path, nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		got := response.Body.Bytes()
		code := response.Code
		if !bytes.Equal(tt.want, got) {
			t.Errorf("got %s, want %s", got, tt.want)
		}
		if tt.code != code {
			t.Errorf("code %d, tt.code %d", code, tt.code)
		}
	}
}

func TestAuthenticatorChi(t *testing.T) {
	router := chi.NewRouter()
	authenticatorMd := Authenticator(func(ctx context.Context) (*string, error) {
		id := "192.0.2.1"
		return &id, nil
	}, func(ctx context.Context, id *string) (interface{}, error) {
		return "USERAUTH", nil
	})
	router.With(authenticatorMd).Get(
		"/get",
		func(writer http.ResponseWriter, request *http.Request) {
			profile, err := Authentication(request.Context())
			if err != nil {
				t.Fatal(err)
			}
			data := profile.(string)

			_, err = writer.Write([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
		},
	)

	type args struct {
		method string
		path   string
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{name: "GET", args: args{method: "GET", path: "/get"}, want: []byte("USERAUTH")},
	}

	for _, tt := range tests {
		request := httptest.NewRequest(tt.args.method, tt.args.path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		got := response.Body.Bytes()
		if !bytes.Equal(tt.want, got) {
			t.Errorf("got %s, want %s", got, tt.want)
		}
	}
}

func TestNoAuthenticatorChi(t *testing.T) {
	router := chi.NewRouter()
	authenticatorMd := Authenticator(func(ctx context.Context) (*string, error) {
		id := "192.0.2.1"
		return &id, nil
	}, func(ctx context.Context, id *string) (interface{}, error) {
		return nil, ErrNoAuthentication
	})
	router.With(authenticatorMd).Get(
		"/get",
		func(writer http.ResponseWriter, request *http.Request) {
			profile, err := Authentication(request.Context())
			if err != nil {
				t.Fatal(err)
			}
			data := profile.(string)

			_, err = writer.Write([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
		},
	)

	type args struct {
		method string
		path   string
	}

	tests := []struct {
		name string
		args args
		want []byte
		code int
	}{
		{name: "GET", args: args{method: "GET", path: "/get"}, want: []byte(""), code: 401},
	}

	for _, tt := range tests {
		request := httptest.NewRequest(tt.args.method, tt.args.path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		got := response.Body.Bytes()
		code := response.Code
		if !bytes.Equal(tt.want, got) {
			t.Errorf("got %s, want %s", got, tt.want)
		}
		if tt.code != code {
			t.Errorf("code %d, tt.code %d", code, tt.code)
		}
	}
}
