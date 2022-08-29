package backend

import (
	"context"
)

type handleUIDType struct{}

var handleUIDKey handleUIDType

// AsUID marks this context as handling a UID command.
// This modifies some backend behaviour (such as returning UID within FETCH responses).
func AsUID(parent context.Context) context.Context {
	return context.WithValue(parent, handleUIDKey, struct{}{})
}

func isUID(ctx context.Context) bool {
	return ctx.Value(handleUIDKey) != nil
}

type handleCloseType struct{}

var handleCloseKey handleCloseType

// AsClose marks this context as handling a CLOSE command.
// This modifies some backend behaviour (such as not returning EXPUNGE responses).
func AsClose(parent context.Context) context.Context {
	return context.WithValue(parent, handleCloseKey, struct{}{})
}

func isClose(ctx context.Context) bool {
	return ctx.Value(handleCloseKey) != nil
}

type handleSilentType struct{}

var handleSilentKey handleSilentType

// AsSilent marks this context as handling a silent STORE command.
// This modifies some backend behaviour (such as not returning EXPUNGE responses).
func AsSilent(parent context.Context) context.Context {
	return context.WithValue(parent, handleSilentKey, struct{}{})
}

func isSilent(ctx context.Context) bool {
	return ctx.Value(handleSilentKey) != nil
}

type handleRemoteUpdateCtxType struct{}

var handleRemoteUpdateCtxKey handleRemoteUpdateCtxType

func isRemoteUpdateCtx(ctx context.Context) bool {
	return ctx.Value(handleRemoteUpdateCtxKey) != nil
}

func NewRemoteUpdateCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, handleRemoteUpdateCtxKey, struct{}{})
}

type stateContextType struct{}

var stateContextKey stateContextType

func NewStateContext(ctx context.Context, s *State) context.Context {
	if s == nil {
		return ctx
	}

	return context.WithValue(ctx, stateContextKey, s.stateID)
}

func getStateIDFromContext(ctx context.Context) (int, bool) {
	v := ctx.Value(stateContextKey)
	if v == nil {
		return 0, false
	}

	stateID, ok := v.(int)

	return stateID, ok
}
