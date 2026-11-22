// Sample clean Rust code adhering to Corral-Lite standards.

pub fn compute_result(val: Option<i32>) -> Result<i32, &'static str> {
    val.ok_or("Value is None")
}

pub fn process_flag(flag: bool) -> &'static str {
    if flag {
        "active flag branch"
    } else {
        "inactive flag branch"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute() {
        assert_eq!(compute_result(Some(42)).unwrap(), 42);
    }
}
