package flag

import (
	"time"

	charts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"
	"github.com/spf13/pflag"
)

type (
	Flag interface {
		Apply(values *charts.Values)
		IsSet() bool
	}

	UintFlag struct {
		name    string
		Value   uint
		flagSet *pflag.FlagSet
		apply   func(values *charts.Values, value uint)
	}

	Int64Flag struct {
		name    string
		Value   int64
		flagSet *pflag.FlagSet
		apply   func(values *charts.Values, value int64)
	}

	StringFlag struct {
		name    string
		Value   string
		flagSet *pflag.FlagSet
		apply   func(values *charts.Values, value string)
	}

	BoolFlag struct {
		name    string
		Value   bool
		flagSet *pflag.FlagSet
		apply   func(values *charts.Values, value bool)
	}

	DurationFlag struct {
		name    string
		Value   time.Duration
		flagSet *pflag.FlagSet
		apply   func(values *charts.Values, value time.Duration)
	}
)

func NewUintFlag(flagSet *pflag.FlagSet, name string, defaultValue uint, description string, apply func(values *charts.Values, value uint)) *UintFlag {
	flag := UintFlag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.UintVar(&flag.Value, name, defaultValue, description)
	return &flag
}

func NewInt64Flag(flagSet *pflag.FlagSet, name string, defaultValue int64, description string, apply func(values *charts.Values, value int64)) *Int64Flag {
	flag := Int64Flag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.Int64Var(&flag.Value, name, defaultValue, description)
	return &flag
}

func NewStringFlag(flagSet *pflag.FlagSet, name string, defaultValue string, description string, apply func(values *charts.Values, value string)) *StringFlag {
	flag := StringFlag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.StringVar(&flag.Value, name, defaultValue, description)
	return &flag
}

func NewStringFlagP(flagSet *pflag.FlagSet, name string, short string, defaultValue string, description string, apply func(values *charts.Values, value string)) *StringFlag {
	flag := StringFlag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.StringVarP(&flag.Value, name, short, defaultValue, description)
	return &flag
}

func NewBoolFlag(flagSet *pflag.FlagSet, name string, defaultValue bool, description string, apply func(values *charts.Values, value bool)) *BoolFlag {
	flag := BoolFlag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.BoolVar(&flag.Value, name, defaultValue, description)
	return &flag
}

func NewDurationFlag(flagSet *pflag.FlagSet, name string, defaultValue time.Duration, description string, apply func(values *charts.Values, value time.Duration)) *DurationFlag {
	flag := DurationFlag{
		name:    name,
		flagSet: flagSet,
		apply:   apply,
	}
	flagSet.DurationVar(&flag.Value, name, defaultValue, description)
	return &flag
}

func (flag *UintFlag) Apply(values *charts.Values) {
	flag.apply(values, flag.Value)
}

func (flag *UintFlag) IsSet() bool {
	return flag.flagSet.Changed(flag.name)
}

func (flag *Int64Flag) Apply(values *charts.Values) {
	flag.apply(values, flag.Value)
}

func (flag *Int64Flag) IsSet() bool {
	return flag.flagSet.Changed(flag.name)
}

func (flag *StringFlag) Apply(values *charts.Values) {
	flag.apply(values, flag.Value)
}

func (flag *StringFlag) IsSet() bool {
	return flag.flagSet.Changed(flag.name)
}

func (flag *BoolFlag) Apply(values *charts.Values) {
	flag.apply(values, flag.Value)
}

func (flag *BoolFlag) IsSet() bool {
	return flag.flagSet.Changed(flag.name)
}

func (flag *DurationFlag) Apply(values *charts.Values) {
	flag.apply(values, flag.Value)
}

func (flag *DurationFlag) IsSet() bool {
	return flag.flagSet.Changed(flag.name)
}

func ApplySetFlags(values *charts.Values, flags []Flag) {
	for _, flag := range flags {
		if flag.IsSet() {
			flag.Apply(values)
		}
	}
}
