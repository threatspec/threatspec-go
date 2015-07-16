package threatspec

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// TODO: Refs
var mitigationPattern = regexp.MustCompile(`^Mitigates (?P<Component>.+?) against (?P<Threat>.+?) with (?P<Mitigation>.+?)$`) //\s*(?:\((?P<Ref>.*?)\))?$`)
var exposurePattern = regexp.MustCompile(`^Exposes (?P<Component>.+?) to (?P<Threat>.+?) with (?P<Exposure>.+?)$`)            //\s*(?:\((?P<Ref>.*?)\))?`)

// Currently not used patterns:
// var ThreatSpecPattern = regexp.MustCompile(`ThreatSpec (?P<Model>.+?) for (?P<Function>.+?)$`)
// var DoesPattern = regexp.MustCompile(`Does (?P<Action>.+?) for (?P<Component>.+?)\s*(?:\((?P<Ref>.*?)\))?$`)

// An Exposure ...
type Exposure struct {
	Name      string
	Component string
	Threat    string
	Ref       string
	Function  *Function
}

// A Mitigation ...
type Mitigation struct {
	Name      string
	Component string
	Threat    string
	Ref       string
	Function  *Function
}

// A Function ...
type Function struct {
	Name     string
	Package  string
	Begin    int
	End      int
	Filepath string
	Comments []*ast.CommentGroup
}

// LocationString returns a compact representation of the function's location
func (f *Function) LocationString() string {
	return fmt.Sprintf("%s:%d:%d:%s", f.Filepath, f.Begin, f.End, f.Name)
}

func (f *Function) isMitigation() (Mitigation, bool) {
	m, match := f.matchFunction(mitigationPattern)
	if match {
		ref := ""
		if len(m) == 4 {
			ref = m[3]
		}
		return Mitigation{Name: m[2], Component: m[0], Threat: m[1], Ref: ref, Function: f}, true
	}
	return Mitigation{}, false
}

func (f *Function) isExposure() (Exposure, bool) {
	m, match := f.matchFunction(exposurePattern)
	if match {
		ref := ""
		if len(m) == 4 {
			ref = m[3]
		}
		return Exposure{Name: m[2], Component: m[0], Threat: m[1], Ref: ref, Function: f}, true
	}
	return Exposure{}, false
}

func (f *Function) matchFunction(re *regexp.Regexp) ([]string, bool) {
	for _, lines := range f.Comments {
		for _, line := range strings.Split(lines.Text(), "\n") {
			m := re.FindStringSubmatch(line)
			if len(m) > 1 {
				return m[1:], true // cut-off whole-line match
			}
		}
	}
	return []string{}, false
}

// File reads a file and gathers the functions defined in it, its exposures, and its mitigations
func File(filename string) ([]Function, []Exposure, []Mitigation, error) {
	var res []Function
	var exposures []Exposure
	var mitigations []Mitigation

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return []Function{}, []Exposure{}, []Mitigation{}, err // TODO: this feels wrong
	}

	cmap := ast.NewCommentMap(fset, f, f.Comments)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			fun := Function{Begin: fset.Position(x.Pos()).Line,
				Package:  f.Name.String(),
				Name:     x.Name.String(),
				End:      fset.Position(x.End()).Line,
				Filepath: fset.Position(x.Pos()).Filename,
				Comments: cmap[n]}

			if e, match := fun.isExposure(); match {
				exposures = append(exposures, e)
			}
			if m, match := fun.isMitigation(); match {
				mitigations = append(mitigations, m)
			}
			res = append(res, fun)
		}
		return true
	})
	return res, exposures, mitigations, nil
}

// Files is a convenience wrapper
func Files(filenames []string) ([]Function, []Exposure, []Mitigation, error) {
	var funcs []Function
	var exposures []Exposure
	var mitigations []Mitigation

	for _, filename := range filenames {
		nfuncs, nexposures, nmitigations, err := File(filename)
		if err != nil {
			return []Function{}, []Exposure{}, []Mitigation{}, err
		}
		funcs = append(funcs, nfuncs...)
		exposures = append(exposures, nexposures...)
		mitigations = append(mitigations, nmitigations...)
	}
	return funcs, exposures, mitigations, nil
}

// IsMitigated returns if the exposure is mitigated by the given mitigations
func (e *Exposure) IsMitigated(ms []Mitigation) bool {
	found := false
	for _, m := range ms {
		if m.Threat == e.Threat && m.Component == e.Component {
			found = true
			break
		}
	}
	return found
}

// Unmitigated returns unmitigated exposures
func Unmitigated(es []Exposure, ms []Mitigation) []Exposure {
	var us []Exposure
	for _, e := range es {
		if !e.IsMitigated(ms) {
			us = append(us, e)
		}
	}
	return us
}
