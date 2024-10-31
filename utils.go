package main

import "context"

func Try[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func Catch(f func(error)) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			f(err)
		} else {
			panic(value)
		}
	}
}

func IsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
