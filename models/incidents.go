package models

import (
	"encoding/json"
	"time"

	"bosun.org/opentsdb"
)

type Incident struct {
	Id       uint64
	Start    time.Time
	End      *time.Time
	AlertKey AlertKey
}

type IncidentState struct {
	Id       int64
	Start    time.Time
	End      *time.Time
	AlertKey AlertKey
	Alert    string // helper data since AlertKeys don't serialize to JSON well
	Tags     string // string representation of Group

	*Result

	// Most recent last.
	Events  []Event  `json:",omitempty"`
	Actions []Action `json:",omitempty"`

	Subject      string
	Body         string
	EmailBody    []byte        `json:"-"`
	EmailSubject []byte        `json:"-"`
	Attachments  []*Attachment `json:"-"`

	NeedAck bool
	Open    bool
	// TODO: Frogotten
	Forgotten   bool
	Unevaluated bool

	CurrentStatus Status
	WorstStatus   Status

	LastAbnormalStatus Status
	LastAbnormalTime   int64
}

func (s *IncidentState) Last() Event {
	if len(s.Events) == 0 {
		return Event{}
	}
	return s.Events[len(s.Events)-1]
}

func (s *IncidentState) IsActive() bool {
	return s.CurrentStatus > StNormal
}

type Event struct {
	Warn, Crit  *Result `json:",omitempty"`
	Status      Status
	Time        time.Time
	Unevaluated bool
}

type Result struct {
	Computations `json:",omitempty"`
	Value        float64
	Group        opentsdb.TagSet
	Expr         string
}

type Computations []Computation

type Computation struct {
	Text  string
	Value interface{}
}

type FuncType int

func (f FuncType) String() string {
	switch f {
	case TypeNumberSet:
		return "number"
	case TypeString:
		return "string"
	case TypeSeriesSet:
		return "series"
	case TypeScalar:
		return "scalar"
	default:
		return "unknown"
	}
}

const (
	TypeString FuncType = iota
	TypeScalar
	TypeNumberSet
	TypeSeriesSet
)

type Status int

const (
	StNone Status = iota
	StNormal
	StWarning
	StCritical
	StUnknown
)

func (s Status) String() string {
	switch s {
	case StNormal:
		return "normal"
	case StWarning:
		return "warning"
	case StCritical:
		return "critical"
	case StUnknown:
		return "unknown"
	default:
		return "none"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"normal"`:
		*s = StNormal
	case `"warning"`:
		*s = StWarning
	case `"critical"`:
		*s = StCritical
	case `"unknown"`:
		*s = StUnknown
	default:
		*s = StNone
	}
	return nil
}

func (s Status) IsNormal() bool   { return s == StNormal }
func (s Status) IsWarning() bool  { return s == StWarning }
func (s Status) IsCritical() bool { return s == StCritical }
func (s Status) IsUnknown() bool  { return s == StUnknown }

type Action struct {
	User    string
	Message string
	Time    time.Time
	Type    ActionType
}

type ActionType int

const (
	ActionNone ActionType = iota
	ActionAcknowledge
	ActionClose
	ActionForget
)

func (a ActionType) String() string {
	switch a {
	case ActionAcknowledge:
		return "Acknowledged"
	case ActionClose:
		return "Closed"
	case ActionForget:
		return "Forgotten"
	default:
		return "none"
	}
}

func (a ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

type Attachment struct {
	Data        []byte
	Filename    string
	ContentType string
}
