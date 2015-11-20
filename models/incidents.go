package models

import (
	"time"

	"bosun.org/opentsdb"
)

type Incident struct {
	Id       uint64
	Start    time.Time
	End      *time.Time
	AlertKey AlertKey
}

type ExpressionResult struct {
	Computations
	Value
	Group opentsdb.TagSet
}

type Computations []Computation

type Computation struct {
	Text  string
	Value interface{}
}

type Value interface {
	Type() FuncType
	Value() interface{}
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
