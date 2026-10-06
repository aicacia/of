use std::{io, path::Path, sync::Arc};

use axum::Router;
use iroh::EndpointId;
use iroh_chain::Server;
use storage_service::{DatabaseRuntime, ScopedFileSystemRuntime};
use tokio_util::sync::CancellationToken;

use crate::{RouterState, StorageReplicationRuntime, openapi_router, resource_router};

pub struct StorageRuntime {
    router: Router,
    replication: Option<StorageReplicationRuntime>,
    cancellation_token: CancellationToken,
}

impl StorageRuntime {
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn data_handler(&self) -> Option<impl iroh::protocol::ProtocolHandler + Clone> {
        self.replication
            .as_ref()
            .map(StorageReplicationRuntime::data_handler)
    }

    pub fn start_background_tasks(&mut self) {
        if let Some(replication) = self.replication.as_mut() {
            replication.start_sync(self.cancellation_token.clone());
        }
    }

    pub async fn shutdown(self) -> io::Result<()> {
        if let Some(replication) = self.replication {
            replication.shutdown().await?;
        }
        Ok(())
    }
}

pub fn build_runtime(
    state: RouterState,
    data_dir: &Path,
    api_prefix: &str,
    resource_prefix: &str,
    server: Option<Server>,
    cancellation_token: CancellationToken,
) -> io::Result<StorageRuntime> {
    let databases = Arc::new(DatabaseRuntime::new(data_dir.join("databases"))?);
    let file_systems = server
        .as_ref()
        .map(|server| {
            ScopedFileSystemRuntime::<EndpointId>::new(
                data_dir.join("filesystems"),
                server.endpoint().id(),
            )
            .map(Arc::new)
        })
        .transpose()
        .map_err(io::Error::other)?;

    let replication = match (
        server,
        state.management_client.clone(),
        file_systems.clone(),
    ) {
        (Some(server), Some(management), Some(file_systems)) => {
            Some(StorageReplicationRuntime::start(
                server,
                management,
                Arc::clone(&databases),
                file_systems,
                data_dir.join("sync-staging"),
                cancellation_token.clone(),
            ))
        }
        _ => None,
    };

    let resource_routes = resource_router(
        state.clone(),
        Some(Arc::clone(&databases)),
        file_systems.clone(),
    );
    let resource_routes = if resource_prefix.is_empty() {
        resource_routes
    } else {
        Router::new().nest(resource_prefix, resource_routes)
    };
    let router = openapi_router(state, api_prefix)
        .split_for_parts()
        .0
        .merge(resource_routes)
        .into();

    Ok(StorageRuntime {
        router,
        replication,
        cancellation_token,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::build_runtime;
    use crate::RouterState;

    #[tokio::test]
    async fn unified_prefix_does_not_repeat_storage_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        let data_dir =
            std::env::temp_dir().join(format!("storage-runtime-{}-{unique}", std::process::id()));
        let runtime = build_runtime(
            RouterState::new("http://storage.local"),
            &data_dir,
            "/storage",
            "",
            None,
            tokio_util::sync::CancellationToken::new(),
        )
        .expect("build Storage runtime");

        let router = runtime.router();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/storage/databases")
                    .header(axum::http::header::AUTHORIZATION, "Bearer token")
                    .body(Body::empty())
                    .expect("build storage route request"),
            )
            .await
            .expect("call storage route");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/storage/storage/databases")
                    .body(Body::empty())
                    .expect("build duplicate-prefix request"),
            )
            .await
            .expect("call duplicate-prefix route");
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);

        runtime.shutdown().await.expect("stop Storage runtime");
        fs::remove_dir_all(data_dir).expect("remove temporary Storage data");
    }
}
