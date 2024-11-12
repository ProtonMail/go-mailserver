package response

import "strings"

type continuation struct {
	tag string
}

func Continuation() *continuation {
	return &continuation{
		tag: "+",
	}
}

func (r *continuation) Send(s Session, message string) error {
	return s.WriteResponse(r.String(message))
}

func (r *continuation) String(message string) string {
	if len(message) == 0 {
		return r.tag
	}

	return strings.Join([]string{r.tag, message}, " ")
}
