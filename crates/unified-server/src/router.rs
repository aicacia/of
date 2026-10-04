use axum::Router;

pub fn compose_router(idp: Router, management: Router, storage: Router) -> Router {
    idp.merge(management).merge(storage)
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    use super::compose_router;

    #[tokio::test]
    async fn composes_service_routers_without_rewriting_prefixes() {
        let idp = Router::new().route("/idp/health", get(|| async { "idp" }));
        let management = Router::new().route("/management/health", get(|| async { "management" }));
        let storage = Router::new().route("/storage/health", get(|| async { "storage" }));
        let router = compose_router(idp, management, storage);

        for (path, expected) in [
            ("/idp/health", "idp"),
            ("/management/health", "management"),
            ("/storage/health", "storage"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("build health request"),
                )
                .await
                .expect("call composed service router");
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read health response");
            assert_eq!(body.as_ref(), expected.as_bytes());
        }

        let duplicate_storage_prefix = router
            .oneshot(
                Request::builder()
                    .uri("/storage/storage/health")
                    .body(Body::empty())
                    .expect("build duplicate-prefix request"),
            )
            .await
            .expect("call duplicate-prefix route");
        assert_eq!(
            duplicate_storage_prefix.status(),
            http::StatusCode::NOT_FOUND
        );
    }
}
