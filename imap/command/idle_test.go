package command

import (
	"bytes"
	"github.com/ProtonMail/gluon/rfcparser"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParser_IdleCommand(t *testing.T) {
	input := toIMAPLine(`tag IDLE`)
	s := rfcparser.NewScanner(bytes.NewReader(input))
	p := NewParser(s)

	expected := Command{Tag: "tag", Payload: &IdleCommand{}}

	cmd, err := p.Parse()
	require.NoError(t, err)
	require.Equal(t, expected, cmd)
	require.Equal(t, "idle", p.LastParsedCommand())
	require.Equal(t, "tag", p.LastParsedTag())
}
