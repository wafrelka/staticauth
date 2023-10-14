use url::Url;

pub fn normalize_path(base: &str, path: &str) -> Option<String> {
    let host = Url::parse("http://localhost").unwrap();
    let full_base = host.join(base).ok()?;
    let full_path = full_base.join(path).ok()?;
    host.make_relative(&full_path).map(|r| format!("/{}", r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_basic() {
        let base = "/a/b/c";
        let path = "d";
        let expected = Some("/a/b/d".into());
        let actual = normalize_path(base, path);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_normalize_path_base_ends_with_slash() {
        let base = "/a/b/c/";
        let path = "d";
        let expected = Some("/a/b/c/d".into());
        let actual = normalize_path(base, path);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_normalize_path_path_from_root() {
        let base = "/a/b/c";
        let path = "/d";
        let expected = Some("/d".into());
        let actual = normalize_path(base, path);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_normalize_path_parent_path() {
        let base = "/a/b/c";
        let path = "../d";
        let expected = Some("/a/d".into());
        let actual = normalize_path(base, path);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_normalize_path_absolute_path() {
        let base = "/a/b/c";
        let path = "https://example.com/x/y/z";
        let expected = None;
        let actual = normalize_path(base, path);
        assert_eq!(expected, actual);
    }
}
