// Code generated by ent, DO NOT EDIT.

package mailboxattr

import (
	"entgo.io/ent/dialect/sql"
	"github.com/ProtonMail/gluon/internal/backend/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// Value applies equality check predicate on the "Value" field. It's identical to ValueEQ.
func Value(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldValue), v))
	})
}

// ValueEQ applies the EQ predicate on the "Value" field.
func ValueEQ(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldValue), v))
	})
}

// ValueNEQ applies the NEQ predicate on the "Value" field.
func ValueNEQ(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldValue), v))
	})
}

// ValueIn applies the In predicate on the "Value" field.
func ValueIn(vs ...string) predicate.MailboxAttr {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldValue), v...))
	})
}

// ValueNotIn applies the NotIn predicate on the "Value" field.
func ValueNotIn(vs ...string) predicate.MailboxAttr {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldValue), v...))
	})
}

// ValueGT applies the GT predicate on the "Value" field.
func ValueGT(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldValue), v))
	})
}

// ValueGTE applies the GTE predicate on the "Value" field.
func ValueGTE(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldValue), v))
	})
}

// ValueLT applies the LT predicate on the "Value" field.
func ValueLT(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldValue), v))
	})
}

// ValueLTE applies the LTE predicate on the "Value" field.
func ValueLTE(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldValue), v))
	})
}

// ValueContains applies the Contains predicate on the "Value" field.
func ValueContains(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldValue), v))
	})
}

// ValueHasPrefix applies the HasPrefix predicate on the "Value" field.
func ValueHasPrefix(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldValue), v))
	})
}

// ValueHasSuffix applies the HasSuffix predicate on the "Value" field.
func ValueHasSuffix(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldValue), v))
	})
}

// ValueEqualFold applies the EqualFold predicate on the "Value" field.
func ValueEqualFold(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldValue), v))
	})
}

// ValueContainsFold applies the ContainsFold predicate on the "Value" field.
func ValueContainsFold(v string) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldValue), v))
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.MailboxAttr) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.MailboxAttr) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.MailboxAttr) predicate.MailboxAttr {
	return predicate.MailboxAttr(func(s *sql.Selector) {
		p(s.Not())
	})
}
