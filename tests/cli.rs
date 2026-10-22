use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn info_prints_version() {
    Command::cargo_bin("sentinela")
        .unwrap()
        .arg("info")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}
