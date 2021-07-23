package errors

type Const string

func (e Const) Error() string { return string(e) }
