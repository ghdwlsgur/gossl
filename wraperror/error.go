// Copyright © 2020 gjbae1212
// Released under the MIT license.
// (https://github.com/gjbae1212/gossm)

package wraperror

import (
	"errors"
)

type WrapError struct {
	current error
	child   error
}

func (e *WrapError) Current() error {
	return e.current
}

func (e *WrapError) Child() error {
	return e.child
}

func (e *WrapError) Wrap(err error) *WrapError {
	return &WrapError{current: err, child: e}
}

func (e *WrapError) Flatten() []error {
	var errs []error

	if e.current != nil {
		if _, ok := e.current.(*WrapError); ok {
			errs = append(errs, e.current.(*WrapError).Flatten()...)
		} else {
			errs = append(errs, e.current)
			if unwrap := errors.Unwrap(e.current); unwrap != nil {
				errs = append(errs, Error(unwrap).Flatten()...)
			}
		}
	}

	if e.child != nil {
		if _, ok := e.child.(*WrapError); ok {
			errs = append(errs, e.child.(*WrapError).Flatten()...)
		} else {
			errs = append(errs, e.child)
			if unwrap := errors.Unwrap(e.child); unwrap != nil {
				errs = append(errs, Error(unwrap).Flatten()...)
			}
		}
	}
	return errs
}

func (e *WrapError) Error() string {
	if e.current == nil {
		return ""
	}
	msg := e.current.Error()
	if e.child != nil {
		msg += " " + e.child.Error()
	}
	return msg
}

func (e *WrapError) Unwrap() error {
	return e.child
}

func (e *WrapError) Is(target error) bool {
	return errors.Is(e.current, target)
}

func (e *WrapError) As(target interface{}) bool {
	return errors.As(e.current, target)
}

func Error(err error) *WrapError {
	if err == nil {
		return &WrapError{}
	}

	switch err := err.(type) {
	case *WrapError:
		return err
	default:
		return &WrapError{current: err}
	}
}

func FromError(err error) (*WrapError, bool) {
	if err == nil {
		return nil, false
	}
	wrapErr, ok := err.(*WrapError)
	return wrapErr, ok
}
