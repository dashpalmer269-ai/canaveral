package models

// Value holds either a collected value or the reason it could not be collected.
// It can never hold both, so a collector cannot return a guessed value alongside
// a failure. The zero Value means the item was not collected at all.
type Value[T any] struct {
	v      T
	known  bool
	reason string
}

// Known returns a Value holding v.
func Known[T any](v T) Value[T] {
	return Value[T]{v: v, known: true}
}

// Unavailable returns a Value recording why the item could not be collected.
func Unavailable[T any](reason string) Value[T] {
	if reason == "" {
		reason = "no reason recorded"
	}
	return Value[T]{reason: reason}
}

// Get returns the value and whether it is known. When it is not known the
// returned value is T's zero value and must not be used as data.
func (x Value[T]) Get() (T, bool) {
	return x.v, x.known
}

// IsKnown reports whether a value was collected.
func (x Value[T]) IsKnown() bool {
	return x.known
}

// Reason returns why the value is unavailable, "not collected" for the zero
// Value, and "" when the value is known.
func (x Value[T]) Reason() string {
	switch {
	case x.known:
		return ""
	case x.reason == "":
		return "not collected"
	default:
		return x.reason
	}
}
