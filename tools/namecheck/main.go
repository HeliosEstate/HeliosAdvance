// SPDX-FileCopyrightText: 2026 Pascal Fairchild
// SPDX-License-Identifier: AGPL-3.0-only

// Command namecheck fails on a Go identifier too short to read without knowing an
// abbreviation convention: sessionID, not sid; queueEntry, not qe; responseRecorder, not
// rr. The developer reads in Pascal, where Go's terseness is unreadable, and the rule was
// prose in two failed attempts; this is the check. Receivers, parameters, results, locals,
// range variables, fields, functions and types are all names. An identifier passes if it
// is on the short list below, which is what is common across C, Pascal and Go alike; a
// command-line flag's name is a string, not an identifier, and is not checked.
//
// Usage: go run ./tools/namecheck [dir ...]   (default: the current directory, walked)
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// allowed is every short name widely known to everyone, not only to Go developers, which
// is the developer's test. Two Go conventions are kept because the type beside them says
// what they are: t for *testing.T, ctx for a context.
var allowed = map[string]bool{
	"i": true, "j": true, "k": true, // index variables
	"n":   true, // a count
	"t":   true, // *testing.T
	"ok":  true, // the comma-ok idiom
	"err": true, "ctx": true, "id": true, "ID": true,
	"rw": true, // read-write, as in rw-r--r-- and O_RDWR
	// transmit, receive, file descriptor
	"tx": true, "Tx": true, "rx": true, "Rx": true, "fd": true,
}

const minimum = 3

func main() {
	roots := os.Args[1:]
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var findings []string
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := entry.Name()
			if entry.IsDir() && (name == ".git" || name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) && path != root {
				return filepath.SkipDir
			}
			if entry.IsDir() || !strings.HasSuffix(name, ".go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			findings = append(findings, check(fset, file)...)
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "namecheck:", err)
			os.Exit(2)
		}
	}
	sort.Strings(findings)
	for _, finding := range findings {
		fmt.Println(finding)
	}
	if len(findings) > 0 {
		fmt.Printf("namecheck: %d identifier(s) too short to read; sessionID, not sid\n", len(findings))
		os.Exit(1)
	}
}

func check(fset *token.FileSet, file *ast.File) []string {
	var findings []string
	report := func(ident *ast.Ident, what string) {
		if ident == nil || ident.Name == "_" || allowed[ident.Name] || len(ident.Name) >= minimum {
			return
		}
		pos := fset.Position(ident.Pos())
		rel := pos.Filename
		if cwd, err := os.Getwd(); err == nil {
			if relative, err := filepath.Rel(cwd, pos.Filename); err == nil {
				rel = relative
			}
		}
		findings = append(findings, fmt.Sprintf("%s:%d:%d: %s `%s` is too short to read", filepath.ToSlash(rel), pos.Line, pos.Column, what, ident.Name))
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncDecl:
			report(n.Name, "function")
			if n.Recv != nil {
				for _, field := range n.Recv.List {
					for _, name := range field.Names {
						report(name, "receiver")
					}
				}
			}
		case *ast.FuncType:
			for _, field := range n.Params.List {
				for _, name := range field.Names {
					report(name, "parameter")
				}
			}
			if n.Results != nil {
				for _, field := range n.Results.List {
					for _, name := range field.Names {
						report(name, "result")
					}
				}
			}
		case *ast.StructType:
			for _, field := range n.Fields.List {
				for _, name := range field.Names {
					report(name, "field")
				}
			}
		case *ast.TypeSpec:
			report(n.Name, "type")
		case *ast.ValueSpec:
			for _, name := range n.Names {
				report(name, "variable")
			}
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						report(ident, "variable")
					}
				}
			}
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				if ident, ok := n.Key.(*ast.Ident); ok {
					report(ident, "variable")
				}
				if ident, ok := n.Value.(*ast.Ident); ok {
					report(ident, "variable")
				}
			}
		}
		return true
	})
	return findings
}
