package store

import (
	"context"
	"database/sql"
)

// Generation counts committed changes that can alter the derived fleet views
// the server caches (package needs, endpoint missing counts, fleet status,
// acquisition request refs): catalog states, deployments and their targets,
// exceptions, endpoint inventory, enrolment / retirement, bundle intake and
// acquisition reports and requests. It is bumped after the commit, so a
// view built from a generation read before the build is stale as soon as
// the generation moves on. Target state changes from agent reports do not
// bump it (too frequent); caches also expire after a short TTL for those.
func (s *Store) Generation() uint64 { return s.gen.Load() }

// Changed bumps Generation (for changes made outside the store's own
// methods, e.g. update intelligence received by intake).
func (s *Store) Changed() { s.gen.Add(1) }

// txChanged is tx followed, after a successful commit, by Changed.
func (s *Store) txChanged(ctx context.Context, fn func(*sql.Tx) error) error {
	if err := s.tx(ctx, fn); err != nil {
		return err
	}
	s.Changed()
	return nil
}
