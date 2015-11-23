package threatspec

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"path"
	"regexp"
	"strings"
	"time"
)

var Name = "ThreatSpec"
var Version = "0.1"

var idCleanPattern = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
var idSpacePattern = regexp.MustCompile(`\s+`)

var aliasPattern = regexp.MustCompile(`(?i)^\s*alias (?P<class>boundary|component|threat) (?P<alias>\@[a-z0-9_]+?) to (?P<text>.+?)\s*$`)
var mitigationPattern = regexp.MustCompile(`(?i)^\s*mitigates (?:(?P<boundary>.+?):)?(?P<component>.+?) against (?P<threat>.+?) with (?P<mitigation>.+?)\s*(?:\((?P<ref>.*?)\))?\s*$`)
var exposurePattern = regexp.MustCompile(`(?i)^\s*exposes (?:(?P<boundary>.+?):)?(?P<component>.+?) to (?P<threat>.+?) with (?P<exposure>.+?)\s*(?:\((?P<ref>.*?)\))?\s*$`)
var acceptancePattern = regexp.MustCompile(`(?i)^\s*accepts (?P<threat>.+?) to (?:(?P<boundary>.+?):)?(?P<component>.+?) with (?P<acceptance>.+?)\s*(?:\((?P<ref>.*?)\))?\s*$`)
var transferPattern = regexp.MustCompile(`(?i)^\s*transfers (?P<threat>.+?) to (?:(?P<boundary>.+?):)?(?P<component>.+?) with (?P<transfer>.+?)\s*(?:\((?P<ref>.*?)\))?\s*$`)

/* ****************************************************************
 * ThreatSpec intermediate representation
 * ****************************************************************/

type Id string

var ProjectName string

type Metadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Created int64  `json:"created"`
	Updated int64  `json:"updated"`
}

type Alias struct {
	Class string `json:"string"`
	Text  string `json:"text"`
}

type Boundary struct {
	Name string `json:"name"`
}

type Component struct {
	Name string `json:"name"`
}

type Threat struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
}

type Source struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

type Mitigation struct {
	Mitigation string  `json:"mitigation"`
	Boundary   Id      `json:"boundary"`
	Component  Id      `json:"component"`
	Threat     Id      `json:"threat"`
	Reference  string  `json:"reference"`
	Source     *Source `json:"source,omitempty"`
}

type Exposure struct {
	Exposure  string  `json:"exposure"`
	Boundary  Id      `json:"boundary"`
	Component Id      `json:"component"`
	Threat    Id      `json:"threat"`
	Reference string  `json:"reference"`
	Source    *Source `json:"source,omitempty"`
}

type Transfer struct {
	Transfer  string  `json:"transfer"`
	Boundary  Id      `json:"boundary"`
	Component Id      `json:"component"`
	Threat    Id      `json:"threat"`
	Reference string  `json:"reference"`
	Source    *Source `json:"source,omitempty"`
}

type Acceptance struct {
	Acceptance string  `json:"acceptance"`
	Boundary   Id      `json:"boundary"`
	Component  Id      `json:"component"`
	Threat     Id      `json:"threat"`
	Reference  string  `json:"reference"`
	Source     *Source `json:"source,omitempty"`
}

type Call struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type Project struct {
	Mitigations map[Id][]*Mitigation `json:"mitigations"`
	Exposures   map[Id][]*Exposure   `json:"exposures"`
	Transfers   map[Id][]*Transfer   `json:"transfers"`
	Acceptances map[Id][]*Acceptance `json:"acceptances"`
}

type ThreatSpec struct {
	Metadata   *Metadata           `json:"metadata"`
	Boundaries map[Id]*Boundary    `json:"boundaries"`
	Components map[Id]*Component   `json:"components"`
	Threats    map[Id]*Threat      `json:"threats"`
	Projects   map[string]*Project `json:"projects"`
	CallFlow   []*Call             `json:"callflow,omitempty"`
}

/* ****************************************************************
 * Supporting structs
 * ****************************************************************/

type Function struct {
	Name     string
	Package  string
	Type     string
	Begin    int
	End      int
	Filepath string
	Comments []*ast.CommentGroup
}

func (f *Function) FullName() string {
	if f.Type != "" {
		return fmt.Sprintf("%s.%s.%s", f.Package, f.Type, f.Name)
	} else {
		return fmt.Sprintf("%s.%s", f.Package, f.Name)
	}
}

func (f *Function) Line() int {
	return f.Begin
}

// LocationString returns a compact representation of the function's location
func (f *Function) LocationString() string {
	return fmt.Sprintf("%s:%d:%d:%s", f.Filepath, f.Begin, f.End, f.Name)
}

// LocationStartString returns a compact representation of the function's location, common with the coverage profile
func (f *Function) LocationStartString() string {
	return fmt.Sprintf("%s:%d:%s", f.Filepath, f.Begin, f.Name)
}

func (f *Function) ToSource() *Source {
	return &Source{
		Function: f.FullName(),
		File:     f.Filepath,
		Line:     f.Line(),
	}
}

/* ****************************************************************
 * Main functions
 * ****************************************************************/

func New(project string) *ThreatSpec {
	ProjectName = project

	ts := &ThreatSpec{
		Metadata: &Metadata{
			Name:    Name,
			Version: Version,
			Created: time.Now().Unix(),
			Updated: time.Now().Unix(),
		},
		Boundaries: make(map[Id]*Boundary),
		Components: make(map[Id]*Component),
		Threats:    make(map[Id]*Threat),
		Projects:   make(map[string]*Project),
		CallFlow:   make([]*Call, 0),
	}
	ts.Projects[ProjectName] = &Project{
		Mitigations: make(map[Id][]*Mitigation),
		Exposures:   make(map[Id][]*Exposure),
		Transfers:   make(map[Id][]*Transfer),
		Acceptances: make(map[Id][]*Acceptance),
	}

	return ts
}

func (ts *ThreatSpec) ToJson() string {
	dump, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return ""
	}
	return string(dump)
}

func (ts *ThreatSpec) ToId(name string) Id {

	if name == "" {
		return ""
	}

	if string([]rune(name)[0]) == "@" {
		return Id(name)
	}

	clean := idCleanPattern.ReplaceAllString(name, "")
	underscored := idSpacePattern.ReplaceAllString(clean, "_")
	lower := strings.ToLower(underscored)
	return Id(fmt.Sprintf("@%s", lower))
}

func (ts *ThreatSpec) matchLine(line string, re *regexp.Regexp) map[string]string {
	match := re.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	result := make(map[string]string)

	for i, name := range re.SubexpNames() {
		result[name] = match[i]
	}

	return result
}

func (ts *ThreatSpec) ParseAlias(line string) (Id, *Alias) {
	m := ts.matchLine(line, aliasPattern)
	if m == nil {
		return "", nil
	}
	aliasId := ts.ToId(m["alias"])

	return aliasId, &Alias{
		Class: m["class"],
		Text:  m["text"],
	}
}

func (ts *ThreatSpec) ParseMitigation(line string, source *Source) (Id, *Mitigation) {
	m := ts.matchLine(line, mitigationPattern)
	if m == nil {
		return "", nil
	}

	mitigationId := ts.ToId(m["mitigation"])

	boundaryId := ts.AddBoundary("", m["boundary"])
	componentId := ts.AddComponent("", m["component"])
	threatId := ts.AddThreat("", m["threat"])

	return mitigationId, &Mitigation{
		Mitigation: m["mitigation"],
		Boundary:   boundaryId,
		Component:  componentId,
		Threat:     threatId,
		Reference:  m["reference"],
		Source:     source,
	}
}

func (ts *ThreatSpec) ParseExposure(line string, source *Source) (Id, *Exposure) {
	m := ts.matchLine(line, exposurePattern)
	if m == nil {
		return "", nil
	}

	exposureId := ts.ToId(m["exposure"])

	boundaryId := ts.AddBoundary("", m["boundary"])
	componentId := ts.AddComponent("", m["component"])
	threatId := ts.AddThreat("", m["threat"])

	return exposureId, &Exposure{
		Exposure:  m["exposure"],
		Boundary:  boundaryId,
		Component: componentId,
		Threat:    threatId,
		Reference: m["reference"],
		Source:    source,
	}
}

func (ts *ThreatSpec) ParseTransfer(line string, source *Source) (Id, *Transfer) {
	m := ts.matchLine(line, transferPattern)
	if m == nil {
		return "", nil
	}

	transferId := ts.ToId(m["transfer"])

	threatId := ts.AddThreat("", m["threat"])
	boundaryId := ts.AddBoundary("", m["boundary"])
	componentId := ts.AddComponent("", m["component"])

	return transferId, &Transfer{
		Transfer:  m["transfer"],
		Boundary:  boundaryId,
		Component: componentId,
		Threat:    threatId,
		Reference: m["reference"],
		Source:    source,
	}
}

func (ts *ThreatSpec) ParseAcceptance(line string, source *Source) (Id, *Acceptance) {
	m := ts.matchLine(line, acceptancePattern)
	if m == nil {
		return "", nil
	}

	acceptanceId := ts.ToId(m["acceptance"])

	boundaryId := ts.AddBoundary("", m["boundary"])
	componentId := ts.AddComponent("", m["component"])
	threatId := ts.AddThreat("", m["threat"])

	return acceptanceId, &Acceptance{
		Acceptance: m["acceptance"],
		Boundary:   boundaryId,
		Component:  componentId,
		Threat:     threatId,
		Reference:  m["reference"],
		Source:     source,
	}
}

func (ts *ThreatSpec) AddBoundary(id Id, boundary string) Id {
	if boundary == "" {
		return ""
	}

	if id == "" {
		id = ts.ToId(boundary)
	}

	if _, ok := ts.Boundaries[id]; !ok {
		ts.Boundaries[id] = &Boundary{Name: boundary}
	}

	return id
}

func (ts *ThreatSpec) AddComponent(id Id, component string) Id {
	if id == "" {
		id = ts.ToId(component)
	}

	if _, ok := ts.Components[id]; !ok {
		ts.Components[id] = &Component{Name: component}
	}

	return id
}

func (ts *ThreatSpec) AddThreat(id Id, threat string) Id {
	if id == "" {
		id = ts.ToId(threat)
	}

	if _, ok := ts.Threats[id]; !ok {
		ts.Threats[id] = &Threat{Name: threat, Reference: ""}
	}

	return id
}

func (ts *ThreatSpec) AddAlias(id Id, alias *Alias) {
	switch strings.ToLower(alias.Class) {
	case "boundary":
		ts.AddBoundary(id, alias.Text)
	case "component":
		ts.AddComponent(id, alias.Text)
	case "threat":
		ts.AddThreat(id, alias.Text)
	}
}

func (ts *ThreatSpec) AddMitigation(id Id, mitigation *Mitigation) {
	ts.Projects[ProjectName].Mitigations[id] = append(ts.Projects[ProjectName].Mitigations[id], mitigation)
}

func (ts *ThreatSpec) AddExposure(id Id, exposure *Exposure) {
	ts.Projects[ProjectName].Exposures[id] = append(ts.Projects[ProjectName].Exposures[id], exposure)
}

func (ts *ThreatSpec) AddTransfer(id Id, transfer *Transfer) {
	ts.Projects[ProjectName].Transfers[id] = append(ts.Projects[ProjectName].Transfers[id], transfer)
}

func (ts *ThreatSpec) AddAcceptance(id Id, acceptance *Acceptance) {
	ts.Projects[ProjectName].Acceptances[id] = append(ts.Projects[ProjectName].Acceptances[id], acceptance)
}

func (ts *ThreatSpec) Parse(filenames []string) error {

	for _, filename := range filenames {
		switch path.Ext(filename) {
		case ".go":
			if err := ts.ParseFile(filename); err != nil {
				return err
			}
		case ".threatspec":
			if err := ts.ParseSpecFile(filename); err != nil {
				return err
			}
		case ".json":
			if err := ts.LoadFile(filename); err != nil {
				return err
			}
		}
	}

	return nil
}

func (ts *ThreatSpec) ParseSpecFile(filename string) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	for _, line := range strings.Split(string(content), "\n") {
		if id, alias := ts.ParseAlias(line); alias != nil {
			ts.AddAlias(id, alias)
		} else if id, mitigation := ts.ParseMitigation(line, nil); mitigation != nil {
			ts.AddMitigation(id, mitigation)
		} else if id, exposure := ts.ParseExposure(line, nil); exposure != nil {
			ts.AddExposure(id, exposure)
		} else if id, transfer := ts.ParseTransfer(line, nil); transfer != nil {
			ts.AddTransfer(id, transfer)
		} else if id, acceptance := ts.ParseAcceptance(line, nil); acceptance != nil {
			ts.AddAcceptance(id, acceptance)
		}
	}

	return nil
}

func (ts *ThreatSpec) ParseFile(filename string) error {

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	cmap := ast.NewCommentMap(fset, f, f.Comments)

	// Iterate all looking for non-function comments
	for _, lines := range cmap.Comments() {
		for _, line := range strings.Split(lines.Text(), "\n") {

			if id, alias := ts.ParseAlias(line); alias != nil {
				ts.AddAlias(id, alias)
			}
		}
	}

	// Look for function-specific comments
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			var fType string
			// https://www.socketloop.com/references/golang-go-ast-funcdecl-type-example
			if x.Recv != nil {
				recvType := x.Recv.List[0].Type
				if recvStarType, ok := recvType.(*ast.StarExpr); ok {
					fType = "(*" + recvStarType.X.(*ast.Ident).Name + ")"
				} else {
					fType = recvType.(*ast.Ident).Name
				}
			} else {
				fType = ""
			}

			function := Function{Begin: fset.Position(x.Pos()).Line,
				Package:  f.Name.String(),
				Name:     x.Name.String(),
				Type:     fType,
				End:      fset.Position(x.End()).Line,
				Filepath: fset.Position(x.Pos()).Filename,
				Comments: cmap[n]}

			source := function.ToSource()
			for _, lines := range function.Comments {
				for _, line := range strings.Split(lines.Text(), "\n") {
					if id, mitigation := ts.ParseMitigation(line, source); mitigation != nil {
						ts.AddMitigation(id, mitigation)
					} else if id, exposure := ts.ParseExposure(line, source); exposure != nil {
						ts.AddExposure(id, exposure)
					} else if id, transfer := ts.ParseTransfer(line, source); transfer != nil {
						ts.AddTransfer(id, transfer)
					} else if id, acceptance := ts.ParseAcceptance(line, source); acceptance != nil {
						ts.AddAcceptance(id, acceptance)
					}
				}
			}

		}
		return true
	})

	return nil
}

func (ts *ThreatSpec) LoadFile(filename string) error {
	jsonBlob, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(jsonBlob, ts); err != nil {
		return err
	}
	return nil
}

func Load(filenames []string) (*ThreatSpec, error) {
	ts := new(ThreatSpec)
	for _, filename := range filenames {
		if err := ts.LoadFile(filename); err != nil {
			return nil, err
		}
	}
	return ts, nil
}
