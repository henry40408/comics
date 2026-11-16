package views

// LoginView is the data of the sign-in page.
type LoginView struct {
	Error bool
	// Next is already constrained to a local path by the caller.
	Next string
}

// LoginPage renders the sign-in page.
func LoginPage(view LoginView) string {
	var failure node
	if view.Error {
		failure = el("div", []attr{a("class", "err"), a("data-testid", "login-error")}, text("帳號或密碼錯誤"))
	}
	form := el("form", []attr{a("method", "POST"), a("action", "/login")},
		void("input", a("type", "hidden"), a("name", "next"), a("value", view.Next)),
		el("label", nil, text("Username"),
			void("input", a("name", "username"), a("data-testid", "login-username"), a("autocomplete", "username"), flag("autofocus"), flag("required"))),
		el("label", nil, text("Password"),
			void("input", a("name", "password"), a("data-testid", "login-password"), a("type", "password"), a("autocomplete", "current-password"), flag("required"))),
		el("button", []attr{a("class", "lbtn key"), a("type", "submit"), a("data-testid", "login-submit")}, text("Sign in")),
	)
	box := el("div", []attr{a("class", "loginbox")},
		el("div", []attr{a("class", "brand")}, el("div", []attr{a("class", "mark")}), spine()),
		failure,
		form,
	)
	body := el("body", nil, el("main", []attr{a("class", "login")}, box, themeButton("themebtn js-only")))
	return document("Sign in | "+titleSuffix(), defaultViewport, body)
}
