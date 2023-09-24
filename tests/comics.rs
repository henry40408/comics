use axum_test::{TestResponse, TestServer};
use clap::Parser;
use cucumber::{given, then, when, World as _};

use comics::{init_route, Cli, Healthz};

const DATA_IDS: [&str; 2] = [
    // Netherworld Nomads Journey to the Jade Jungle
    "abf12a09b5103c972a3893d1b0edcd84850520c9c5056e48bcabca43501da573",
    // Quantum Quest Legacy of the Luminous League
    "582d93470a2a22f29ff9a27c7937969d32a1301943c3ed7e6654a4a6637d30a4",
];

#[derive(cucumber::World, Debug, Default)]
struct World {
    server: Option<TestServer>,
    response: Option<TestResponse>,
    previous_scanned_at: Option<i64>,
}

#[given(expr = "a comics server")]
fn given_several_comic_books(w: &mut World) {
    std::env::remove_var("AUTH_USERNAME");
    std::env::remove_var("AUTH_PASSWORD_HASH");

    let cli = Cli::parse_from(["comics", "--data-dir", "./fixtures/data"]);
    let router = init_route(&cli).unwrap();
    w.server = Some(TestServer::new(router.into_make_service()).unwrap());
}

#[when(expr = "the user visits the front page")]
async fn visit_the_front_page(w: &mut World) {
    let s = w.server.as_ref().unwrap();
    w.response = Some(s.get("/").await);
}

#[then(expr = "they should see comic books")]
fn see_comic_books(w: &mut World) {
    let res = w.response.as_ref().unwrap();
    assert_eq!(200, res.status_code());

    let t = res.text();
    assert!(t.contains("2 book(s)"));
    assert!(t.contains("Netherworld Nomads Journey to the Jade Jungle"));
    assert!(t.contains("Quantum Quest Legacy of the Luminous League"));
}

#[when(expr = "the user visits a comic book")]
async fn visit_a_comic_book(w: &mut World) {
    let book_id = DATA_IDS.first().unwrap();
    let s = w.server.as_ref().unwrap();
    let p = format!("/book/{book_id}");
    w.response = Some(s.get(&p).await);
}

#[when(expr = "they shuffle comic books")]
async fn shuffles_comic_books_from_a_book(w: &mut World) {
    let book_id = DATA_IDS.first().unwrap();
    let s = w.server.as_ref().unwrap();
    let p = format!("/shuffle/{book_id}");
    w.response = Some(s.post(&p).await);
}

#[then(expr = "they should see pages of the comic book")]
fn see_comic_book(w: &mut World) {
    let res = w.response.as_ref().unwrap();
    assert_eq!(200, res.status_code());

    let t = res.text();
    assert!(t.contains("Netherworld Nomads Journey to the Jade Jungle (9P)"));
}

#[when(expr = "the user shuffles comic books")]
async fn shuffles_comic_books(w: &mut World) {
    let s = w.server.as_ref().unwrap();
    w.response = Some(s.post("/shuffle").await);
}

#[then(expr = "they should be redirected to a random book")]
async fn redirected_to_a_random_book(w: &mut World) {
    let res = w.response.as_ref().unwrap();
    assert_eq!(303, res.status_code());

    let splitted = res
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .split('/')
        .collect::<Vec<&str>>();
    assert_eq!(&"book", splitted.get(1).unwrap());
    assert!(DATA_IDS.contains(splitted.get(2).unwrap()));
}

async fn get_healthz(w: &mut World) -> Healthz {
    let s = w.server.as_ref().unwrap();
    let res = s.get("/healthz").await;
    serde_json::from_str(&res.text()).unwrap()
}

#[when(expr = "the user re-scans comic books")]
async fn rescan_comic_books(w: &mut World) {
    let healthz = get_healthz(w).await;
    w.previous_scanned_at = Some(healthz.scanned_at);

    let s = w.server.as_ref().unwrap();
    w.response = Some(s.post("/rescan").await);
}

#[then(expr = "the server should re-scan comic books")]
async fn should_rescan_comic_books(w: &mut World) {
    let healthz = get_healthz(w).await;
    assert!(healthz.scanned_at > w.previous_scanned_at.unwrap());
}

#[then(expr = "they should be redirected to the front page")]
async fn should_be_redirected_to_the_front_page(w: &mut World) {
    let res = w.response.as_ref().unwrap();
    assert_eq!(303, res.status_code());

    let location = res.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!("/", location);
}

#[tokio::main]
async fn main() {
    World::run("features/000_initial.feature").await;
}
