package views

import "strings"

// node is markup that is already safe to concatenate: every piece of text and
// every attribute value in it went through escape.
type node string

// attr is one attribute. A flag renders bare (`defer`), like maud does.
type attr struct {
	name, value string
	flag        bool
}

func a(name, value string) attr { return attr{name: name, value: value} }

func flag(name string) attr { return attr{name: name, flag: true} }

// escape covers both contexts the views use, element text and double-quoted
// attribute values. maud escapes exactly these four characters in both, and
// html/template would write `&#34;` instead of `&quot;`.
var escape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace

// text escapes s for use as element content.
func text(s string) node { return node(escape(s)) }

// group concatenates nodes without any whitespace between them.
func group(children ...node) node {
	var b strings.Builder
	for _, child := range children {
		b.WriteString(string(child))
	}
	return node(b.String())
}

func openTag(tag string, attrs []attr) string {
	var b strings.Builder
	b.WriteString("<" + tag)
	for _, at := range attrs {
		b.WriteString(" " + at.name)
		if !at.flag {
			b.WriteString(`="` + escape(at.value) + `"`)
		}
	}
	b.WriteString(">")
	return b.String()
}

// el renders an element with children and a closing tag.
func el(tag string, attrs []attr, children ...node) node {
	return node(openTag(tag, attrs) + string(group(children...)) + "</" + tag + ">")
}

// void renders an element that has no content and no closing tag.
func void(tag string, attrs ...attr) node {
	return node(openTag(tag, attrs))
}
