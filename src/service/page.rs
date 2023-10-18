use axum::response::Html;
use handlebars::Handlebars;
use serde::Serialize;

const SIGNIN_HTML_TEMPLATE: &str = include_str!("page/signin.html");

pub fn get_signin_html(error: impl Into<String>) -> Html<String> {
    #[derive(Serialize)]
    struct Context {
        error: String,
    }
    let context = Context { error: error.into() };
    let text = Handlebars::new()
        .render_template(SIGNIN_HTML_TEMPLATE, &context)
        .expect("could not render signin html");
    Html::from(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_signin_html() {
        let html = get_signin_html("");
        assert!(!html.0.is_empty());
    }
}
