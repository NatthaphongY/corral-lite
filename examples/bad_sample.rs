// Sample Rust code with deliberate defects for Corral-Lite testing.

fn compute_result(val: Option<i32>) -> i32 {
    val.unwrap() // RS001: Unguarded unwrap in production path
}

fn process_flag(flag: bool) -> &'static str {
    // RS002: Identical branch heuristic
    if flag {
        "identical result"
    } else {
        "identical result"
    }
}
