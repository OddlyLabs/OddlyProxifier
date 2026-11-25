package api

import (
	"encoding/json"
	"io"
	"net/http"

	"oddlyproxifier/internal/config"
	"oddlyproxifier/internal/ppx"
	"oddlyproxifier/internal/profiles"
)

func (s *Server) store(w http.ResponseWriter) *profiles.Store {
	st := profiles.For(s.eng.Path())
	if st == nil {
		writeErr(w, http.StatusConflict, "this engine runs without a profile file")
	}
	return st
}

func (s *Server) listProfiles(w http.ResponseWriter, _ *http.Request) {
	st := s.store(w)
	if st == nil {
		return
	}
	list, err := st.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"active": s.eng.Profile().Name, "list": list, "dir": st.Dir()})
}

// saveProfile stores the active profile under a name and makes that name
// the active one.
func (s *Server) saveProfile(w http.ResponseWriter, r *http.Request) {
	st := s.store(w)
	if st == nil {
		return
	}
	name := r.PathValue("name")
	cur := s.eng.Profile()
	if err := st.Save(name, cur); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	cur.Name = name
	if err := s.eng.SetProfile(cur); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.listProfiles(w, r)
}

func (s *Server) activateProfile(w http.ResponseWriter, r *http.Request) {
	st := s.store(w)
	if st == nil {
		return
	}
	name := r.PathValue("name")
	saved, err := st.Load(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.eng.SetProfile(profiles.Apply(s.eng.Profile(), saved, name)); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, s.eng.Profile())
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	st := s.store(w)
	if st == nil {
		return
	}
	name := r.PathValue("name")
	if err := st.Delete(name); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if cur := s.eng.Profile(); cur.Name == name {
		cur.Name = ""
		_ = s.eng.SetProfile(cur)
	}
	s.listProfiles(w, r)
}

// exportProfile returns the portable part of the active profile.
func (s *Server) exportProfile(w http.ResponseWriter, r *http.Request) {
	cur := s.eng.Profile()
	data, err := profiles.Export(cur, cur.Name, r.URL.Query().Get("passwords") == "1")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}

// importProfile replaces the routing part of the active profile with an
// uploaded one: an exported JSON profile or a Proxifier .ppx file.
func (s *Server) importProfile(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var in *config.Profile
	notes := []string{}
	if ppx.Looks(data) {
		var n []string
		if in, n, err = ppx.Import(data); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		notes = append(notes, n...)
	} else {
		in = &config.Profile{}
		if err := json.Unmarshal(data, in); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "neither a JSON profile nor a Proxifier profile: "+err.Error())
			return
		}
		if in.Proxies == nil && in.Rules == nil && in.Chains == nil {
			writeErr(w, http.StatusUnprocessableEntity, "the file holds no proxies, chains or rules")
			return
		}
		in.Normalize()
	}
	name := r.URL.Query().Get("name")
	if name != "" {
		if err := profiles.CheckName(name); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	next := profiles.Apply(s.eng.Profile(), in, name)
	if err := s.eng.SetProfile(next); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if st := profiles.For(s.eng.Path()); st != nil && name != "" {
		if err := st.Save(name, next); err != nil {
			notes = append(notes, "the profile is active but could not be saved under its name: "+err.Error())
		}
	}
	writeJSON(w, map[string]any{"profile": s.eng.Profile(), "notes": notes})
}
