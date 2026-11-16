package harness

import (
	"fmt"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Element is a handle on a DOM node: the remote object id the browser gave
// it. Once the document it belongs to is gone, every call on it fails; that
// failure is the WebDriver "stale element".
type Element struct {
	browser *Browser
	id      runtime.RemoteObjectID
	what    string
}

// TestID is the CSS selector for an element's data-testid.
func TestID(id string) string {
	return fmt.Sprintf("[data-testid=%s]", jsLiteral(id))
}

// Query finds the first element matching the CSS selector, and fails when
// there is none.
func (b *Browser) Query(selector string) (*Element, error) {
	return queryIn(b, nil, selector)
}

// Optional is Query that reports an absent element as nil, not as an error.
func (b *Browser) Optional(selector string) (*Element, error) {
	return optionalIn(b, nil, selector)
}

// QueryAll finds every element matching the CSS selector.
func (b *Browser) QueryAll(selector string) ([]*Element, error) {
	return queryAllIn(b, nil, selector)
}

// Find finds the first descendant matching the CSS selector.
func (e *Element) Find(selector string) (*Element, error) {
	return queryIn(e.browser, e, selector)
}

// FindOptional is Find that reports an absent descendant as nil.
func (e *Element) FindOptional(selector string) (*Element, error) {
	return optionalIn(e.browser, e, selector)
}

// FindAll finds every descendant matching the CSS selector.
func (e *Element) FindAll(selector string) ([]*Element, error) {
	return queryAllIn(e.browser, e, selector)
}

// String names the element in messages.
func (e *Element) String() string {
	return e.what
}

func queryIn(b *Browser, scope *Element, selector string) (*Element, error) {
	found, err := optionalIn(b, scope, selector)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("no element matches `%s`", selector)
	}
	return found, nil
}

func optionalIn(b *Browser, scope *Element, selector string) (*Element, error) {
	object, err := objectFrom(b, scope, "function(selector) { return this.querySelector(selector); }", selector)
	if err != nil {
		return nil, err
	}
	return wrap(b, object, selector), nil
}

func queryAllIn(b *Browser, scope *Element, selector string) ([]*Element, error) {
	count, err := valueFrom[int](b, scope, "function(selector) { return this.querySelectorAll(selector).length; }", selector)
	if err != nil {
		return nil, err
	}
	elements := make([]*Element, 0, count)
	for index := range count {
		object, err := objectFrom(b, scope, "function(selector, index) { return this.querySelectorAll(selector)[index]; }", selector, index)
		if err != nil {
			return nil, err
		}
		found := wrap(b, object, fmt.Sprintf("%s[%d]", selector, index))
		if found == nil {
			return nil, fmt.Errorf("`%s` matched %d elements, then fewer", selector, count)
		}
		elements = append(elements, found)
	}
	return elements, nil
}

// wrap turns a remote object into an Element, nil for JavaScript null.
func wrap(b *Browser, object *runtime.RemoteObject, what string) *Element {
	if object.ObjectID == "" {
		return nil
	}
	return &Element{browser: b, id: object.ObjectID, what: what}
}

// objectFrom calls function with `this` set to the scope element, or to the
// document when scope is nil, and returns the result as a remote object.
func objectFrom(b *Browser, scope *Element, function string, args ...any) (*runtime.RemoteObject, error) {
	if scope != nil {
		return chromedp.Run(b.ctx, chromedp.CallFunctionOn[*runtime.RemoteObject](function, onObject(scope.id), args...))
	}
	return chromedp.Run(b.ctx, chromedp.Evaluate[*runtime.RemoteObject](onDocument(function, args)))
}

// valueFrom is objectFrom for a result that is a plain value.
func valueFrom[T any](b *Browser, scope *Element, function string, args ...any) (T, error) {
	if scope != nil {
		return chromedp.Run(b.ctx, chromedp.CallFunctionOn[T](function, onObject(scope.id), args...))
	}
	return chromedp.Run(b.ctx, chromedp.Evaluate[T](onDocument(function, args)))
}

func onObject(id runtime.RemoteObjectID) chromedp.CallOption {
	return func(params *runtime.CallFunctionOnParams) {
		params.ObjectID = id
	}
}

func onDocument(function string, args []any) string {
	return fmt.Sprintf("(%s).apply(document, %s)", function, jsLiteral(args))
}

// callOn calls a function with `this` set to the element, and decodes the
// result.
func callOn[T any](e *Element, function string, args ...any) (T, error) {
	return valueFrom[T](e.browser, e, function, args...)
}

// Displayed reports whether the browser renders the element. Comics hides
// things with display:none, so this is enough where WebDriver needed its
// isDisplayed atom.
func (e *Element) Displayed() (bool, error) {
	return callOn[bool](e, "function() { return this.checkVisibility({ opacityProperty: true, visibilityProperty: true }); }")
}

// Text is the element's rendered text: a display:none span inside it does not
// contribute.
func (e *Element) Text() (string, error) {
	return callOn[string](e, "function() { return this.innerText.trim(); }")
}

// Attr reads an attribute, and reports whether it is present.
func (e *Element) Attr(name string) (string, bool, error) {
	value, err := callOn[*string](e, "function(name) { return this.getAttribute(name); }", name)
	if err != nil || value == nil {
		return "", false, err
	}
	return *value, true, nil
}

// Value is the current value of a form control.
func (e *Element) Value() (string, error) {
	return callOn[string](e, "function() { return this.value; }")
}

// Connected reports whether the element is still in its document.
func (e *Element) Connected() (bool, error) {
	return callOn[bool](e, "function() { return this.isConnected; }")
}

// Focus gives the element the keyboard focus.
func (e *Element) Focus() error {
	_, err := callOn[chromedp.Void](e, "function() { this.focus(); }")
	return err
}

// Type focuses the element and types text into it, key by key.
func (e *Element) Type(text string) error {
	if err := e.Focus(); err != nil {
		return err
	}
	return chromedp.Do(e.browser.ctx, chromedp.KeyEvent(text))
}

// clickPoint is where a native click lands.
type clickPoint struct {
	Visible bool    `json:"visible"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
}

// Click is a native click, as WebDriver's Element Click was: the element is
// scrolled into view, then a real mouse press and release go to the centre of
// its box. Whatever covers that point receives them.
func (e *Element) Click() error {
	if err := e.browser.WaitForLoad(); err != nil {
		return err
	}
	point, err := e.scrollToCentre()
	if err != nil {
		return err
	}
	if !point.Visible {
		return fmt.Errorf("element not interactable: %s is not displayed", e)
	}
	return chromedp.Do(e.browser.ctx, chromedp.MouseClickXY(point.X, point.Y))
}

func (e *Element) scrollToCentre() (clickPoint, error) {
	return callOn[clickPoint](e, `function() {
		if (!this.checkVisibility({ opacityProperty: true, visibilityProperty: true })) {
			return { visible: false, x: 0, y: 0 };
		}
		// Instant: the thumbnail rail has scroll-behavior: smooth, and an
		// animated scroll is still moving when the box is measured.
		this.scrollIntoView({ block: 'end', inline: 'nearest', behavior: 'instant' });
		const r = this.getBoundingClientRect();
		return { visible: true, x: r.left + r.width / 2, y: r.top + r.height / 2 };
	}`)
}
