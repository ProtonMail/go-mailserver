package gluon

import (
	"crypto/tls"
	"io"
	"time"

	"github.com/ProtonMail/gluon/profiling"
	"github.com/ProtonMail/gluon/reporter"
	"github.com/ProtonMail/gluon/store"
	"github.com/ProtonMail/gluon/version"
)

// Option represents a type that can be used to configure the server.
type Option interface {
	config(*serverBuilder)
}

// WithDelimiter instructs the server to use the given path delimiter instead of the default ('/').
func WithDelimiter(delimiter string) Option {
	return &withDelimiter{
		delimiter: delimiter,
	}
}

type withDelimiter struct {
	delimiter string
}

func (opt withDelimiter) config(builder *serverBuilder) {
	builder.delim = opt.delimiter
}

// WithLoginJailTime instructs the server to use the given login jail time.
func WithLoginJailTime(loginJailTime time.Duration) Option {
	return &withLoginJailTime{
		loginJailTime: loginJailTime,
	}
}

func (opt withLoginJailTime) config(builder *serverBuilder) {
	builder.loginJailTime = opt.loginJailTime
}

type withLoginJailTime struct {
	loginJailTime time.Duration
}

// WithTLS instructs the server to use the given TLS config.
func WithTLS(cfg *tls.Config) Option {
	return &withTLS{
		cfg: cfg,
	}
}

type withTLS struct {
	cfg *tls.Config
}

func (opt withTLS) config(builder *serverBuilder) {
	builder.tlsConfig = opt.cfg
}

// WithIdleBulkTime instructs the server to use the given IDLE bulk time.
func WithIdleBulkTime(idleBulkTime time.Duration) Option {
	return &withIdleBulkTime{
		idleBulkTime: idleBulkTime,
	}
}

type withIdleBulkTime struct {
	idleBulkTime time.Duration
}

func (opt withIdleBulkTime) config(builder *serverBuilder) {
	builder.idleBulkTime = opt.idleBulkTime
}

// WithLogger instructs the server to write incoming and outgoing IMAP communication to the given io.Writers.
func WithLogger(in, out io.Writer) Option {
	return &withLogger{
		in:  in,
		out: out,
	}
}

type withLogger struct {
	in, out io.Writer
}

func (opt withLogger) config(builder *serverBuilder) {
	builder.inLogger = opt.in
	builder.outLogger = opt.out
}

type withVersionInfo struct {
	versionInfo version.Info
}

func (vi *withVersionInfo) config(builder *serverBuilder) {
	builder.versionInfo = vi.versionInfo
}

func WithVersionInfo(
	vmajor, vminor, vpatch int,
	name, vendor, supportURL string,
) Option {
	return &withVersionInfo{
		versionInfo: version.Info{
			Name: name,
			Version: version.Version{
				Major: vmajor,
				Minor: vminor,
				Patch: vpatch,
			},
			Vendor:     vendor,
			SupportURL: supportURL,
		},
	}
}

type withCmdExecProfiler struct {
	builder profiling.CmdProfilerBuilder
}

func (c *withCmdExecProfiler) config(builder *serverBuilder) {
	builder.cmdExecProfBuilder = c.builder
}

// WithCmdProfiler allows a specific CmdProfilerBuilder to be set for the server's execution.
func WithCmdProfiler(builder profiling.CmdProfilerBuilder) Option {
	return &withCmdExecProfiler{builder: builder}
}

type withStoreBuilder struct {
	builder store.Builder
}

func (w *withStoreBuilder) config(builder *serverBuilder) {
	builder.storeBuilder = w.builder
}

func WithStoreBuilder(builder store.Builder) Option {
	return &withStoreBuilder{builder: builder}
}

type withDataDir struct {
	path string
}

func (w *withDataDir) config(builder *serverBuilder) {
	builder.dir = w.path
}

func WithDataDir(path string) Option {
	return &withDataDir{path: path}
}

type withReporter struct {
	reporter reporter.Reporter
}

func (w *withReporter) config(builder *serverBuilder) {
	builder.reporter = w.reporter
}

func WithReporter(reporter reporter.Reporter) Option {
	return &withReporter{reporter: reporter}
}

// WithIMAPLog allow to have IMAP logs unfiltered
func WithIMAPLog(unfiltered bool) Option {
	return &withIMAPLog{
		unfiltered: unfiltered,
	}
}

type withIMAPLog struct {
	unfiltered bool
}

func (opt withIMAPLog) config(builder *serverBuilder) {
	builder.imapUnfiltered = opt.unfiltered
}
