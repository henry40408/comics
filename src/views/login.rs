use maud::{Markup, html};

use super::layout::{document, theme_button, title_suffix};

pub struct LoginView<'a> {
    pub error: bool,
    /// Already constrained to a local path by the caller.
    pub next: &'a str,
}

pub fn login_page(view: &LoginView<'_>) -> Markup {
    let title = format!("Sign in | {}", title_suffix());
    let body = html! {
        body {
            main class="login" {
                div class="loginbox" {
                    div class="brand" {
                        div class="mark" {}
                        div class="spine" { "漫画書架" span class="en" { "／ COMICS" } }
                    }
                    @if view.error {
                        div class="err" data-testid="login-error" { "帳號或密碼錯誤" }
                    }
                    form method="POST" action="/login" {
                        input type="hidden" name="next" value=(view.next);
                        label {
                            "Username"
                            input name="username" data-testid="login-username" autocomplete="username" autofocus required;
                        }
                        label {
                            "Password"
                            input name="password" data-testid="login-password" type="password" autocomplete="current-password" required;
                        }
                        button class="lbtn key" type="submit" data-testid="login-submit" { "Sign in" }
                    }
                }
                (theme_button("themebtn js-only"))
            }
        }
    };
    document(&title, "width=device-width, initial-scale=1", body)
}
