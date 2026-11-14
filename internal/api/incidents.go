package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"netwatch.local/netwatch/internal/store"
	"strconv"
	"strings"
	"time"
)

func incidentRoutes(mux *http.ServeMux, c Config) {
	operators := map[[32]byte]string{}
	for actor, token := range c.Operators {
		operators[sha256.Sum256([]byte(token))] = actor
	}
	protect := func(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			actor, known := operators[sha256.Sum256([]byte(token))]
			if !ok || !known {
				w.Header().Set("WWW-Authenticate", "Bearer")
				sendJSON(w, 401, map[string]string{"error": "operator_required"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			next(w, r.WithContext(ctx), actor)
		}
	}
	failure := func(w http.ResponseWriter, err error) {
		if errors.Is(err, pgx.ErrNoRows) {
			sendJSON(w, 404, map[string]string{"error": "not_found"})
		} else {
			sendJSON(w, 503, map[string]string{"error": "storage_unavailable"})
		}
	}
	bad := func(w http.ResponseWriter) { sendJSON(w, 400, map[string]string{"error": "invalid_filter_or_id"}) }
	number := func(r *http.Request, key string, def int64) (int64, error) {
		s := r.URL.Query().Get(key)
		if s == "" {
			return def, nil
		}
		v, e := strconv.ParseInt(s, 10, 64)
		if v < 0 {
			e = strconv.ErrRange
		}
		return v, e
	}
	mux.HandleFunc("GET /v1/incidents", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		q := r.URL.Query()
		f := store.IncidentFilter{Entity: q.Get("entity"), Model: q.Get("model")}
		var err error
		for k, target := range map[string]*int64{"from": &f.From, "until": &f.Until, "before": &f.Before} {
			*target, err = number(r, k, 0)
			if err != nil {
				bad(w)
				return
			}
		}
		if len(f.Entity) > 800 || len(f.Model) > 200 || f.Until != 0 && f.Until <= f.From {
			bad(w)
			return
		}
		items, err := c.Store.IncidentList(r.Context(), f)
		if err != nil {
			failure(w, err)
			return
		}
		var next string
		if len(items) > 50 {
			items = items[:50]
			var last struct{ ID string }
			json.Unmarshal(items[49], &last)
			next = last.ID
		}
		pending, retrying, err := c.Store.JournalStatus(r.Context())
		if err != nil {
			failure(w, err)
			return
		}
		sendJSON(w, 200, map[string]any{"incidents": items, "next": next, "pending": pending, "retrying": retrying})
	}))
	mux.HandleFunc("GET /v1/incidents/{id}", protect(func(w http.ResponseWriter, r *http.Request, _ string) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		after, e := number(r, "after", -1)
		if err != nil || id < 1 || e != nil {
			bad(w)
			return
		}
		data, err := c.Store.Incident(r.Context(), id, after)
		if err != nil {
			failure(w, err)
			return
		}
		sendJSON(w, 200, data)
	}))
	mux.HandleFunc("POST /v1/incidents/{id}/ack", protect(func(w http.ResponseWriter, r *http.Request, actor string) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id < 1 {
			bad(w)
			return
		}
		if err = c.Store.AckIncident(r.Context(), id, actor); err != nil {
			failure(w, err)
			return
		}
		w.WriteHeader(204)
	}))
	if c.WebDir != "" {
		assets := http.FileServer(http.Dir(c.WebDir))
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { assets.ServeHTTP(w, r) })
		mux.Handle("GET /assets/", assets)
	}
}
