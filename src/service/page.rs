use axum::response::Html;

const SIGNIN_HTML_TEMPLATE: &str = include_str!("page/signin.html");

pub fn get_signin_html() -> Html<&'static str> {
    Html::from(SIGNIN_HTML_TEMPLATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_signin_html() {
        let html = get_signin_html();
        assert!(!html.0.is_empty());
    }
}
