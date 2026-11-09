//! A real container through JDownloader's real key service, by hand (it needs the network and a
//! container of your own, never one in the repository):
//! `MDM_TEST_DLC=/path/to/links.dlc cargo test -p mdm-containers --test dlc_real -- --ignored`.

#[tokio::test]
#[ignore = "the network and a container of your own (MDM_TEST_DLC)"]
async fn a_real_container_opens_through_the_service() {
    let path = std::env::var("MDM_TEST_DLC").expect("MDM_TEST_DLC: a .dlc file");
    let text = std::fs::read_to_string(path).unwrap();
    let service = url::Url::parse(mdm_containers::dlc::SERVICE).unwrap();
    let packages = mdm_containers::dlc::read(&reqwest::Client::new(), &service, &text)
        .await
        .unwrap();
    assert!(!packages.is_empty());
    for p in &packages {
        assert!(!p.links.is_empty());
        // What it found, without the links themselves.
        let hosts: Vec<_> = p
            .links
            .iter()
            .filter_map(|l| url::Url::parse(l).ok()?.host_str().map(str::to_owned))
            .collect();
        println!(
            "package {:?}: {} link(s) on {hosts:?}, {} password(s)",
            p.name,
            p.links.len(),
            p.passwords.len()
        );
    }
}
