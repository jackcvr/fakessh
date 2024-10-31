package main

func try[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func catch(f func(error)) {
	if value := recover(); value != nil {
		if err, ok := value.(error); ok {
			f(err)
		} else {
			panic(value)
		}
	}
}
