use crate::{
    component::Component,
    components::{
        filter::FilterComponent, forward::ForwardComponent, ip_router::IPRouterComponent,
        listen::ListenComponent, load_balancer::LoadBalancerComponent,
        tcp_tunnel_forward::TcpTunnelForwardComponent, tcp_tunnel_listen::TcpTunnelListenComponent,
    },
    config::ApiConfig,
    router::Router,
};
use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router as AxumRouter,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::ErrorKind,
    path::{Component as PathComponent, Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, net::TcpListener, sync::Notify, task::JoinHandle};
use tracing::{info, warn};

type ApiError = (StatusCode, String);
type ApiJson = Result<Json<Value>, ApiError>;

#[derive(Clone)]
struct ApiState {
    router: Arc<Router>,
    h5_root: Option<PathBuf>,
}

pub struct ApiServer {
    shutdown: Arc<Notify>,
    handle: JoinHandle<()>,
}

#[derive(Debug, Deserialize)]
struct IPRouterActionQuery {
    action: Option<String>,
}

impl ApiServer {
    pub async fn start(config: ApiConfig, router: Arc<Router>) -> Result<Self> {
        let host = if config.host.trim().is_empty() {
            "0.0.0.0"
        } else {
            config.host.trim()
        };
        let port = if config.port == 0 { 8080 } else { config.port };
        let bind_addr = format!("{host}:{port}");
        let listener = TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("failed to bind API server at {bind_addr}"))?;
        let local_addr = listener
            .local_addr()
            .context("failed to query API bind address")?;

        let h5_root = if config.h5_files_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(config.h5_files_path))
        };

        let state = ApiState { router, h5_root };
        let app = AxumRouter::new()
            .route("/api/components", get(get_components))
            .route("/api/components/:tag", get(get_component_by_tag))
            .route("/api/listen/:tag", get(get_listen_connections))
            .route("/api/forward/:tag", get(get_forward_connections))
            .route(
                "/api/tcp_tunnel_listen/:tag",
                get(get_tcp_tunnel_listen_connections),
            )
            .route(
                "/api/tcp_tunnel_forward/:tag",
                get(get_tcp_tunnel_forward_connections),
            )
            .route("/api/load_balancer/:tag", get(get_load_balancer_traffic))
            .route("/api/filter/:tag", get(get_filter_info))
            .route("/api/ip_router/:tag", get(get_ip_router_info))
            .route("/api/ip_router_action/:tag", post(post_ip_router_action))
            .route("/h5", get(get_h5_index))
            .route("/h5/", get(get_h5_index))
            .route("/h5/*file_path", get(get_h5_file))
            .with_state(state);

        let shutdown = Arc::new(Notify::new());
        let shutdown_signal = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_signal.notified().await;
                })
                .await
            {
                warn!("API server exited with error: {err}");
            }
        });

        info!("API server listening on {local_addr}");
        Ok(Self { shutdown, handle })
    }

    pub async fn stop(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

async fn get_components(State(state): State<ApiState>) -> ApiJson {
    let mut out = Vec::new();
    for service in &state.router.config.services {
        let Some(tag) = service_tag(service) else {
            continue;
        };
        if !state.router.has_component(tag) {
            continue;
        }
        if let Some(item) = component_info_for_tag(&state, tag) {
            out.push(item);
        }
    }
    Ok(Json(Value::Array(out)))
}

async fn get_component_by_tag(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let info = component_info_for_tag(&state, &tag)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("component not found: {tag}")))?;
    Ok(Json(info))
}

async fn get_listen_connections(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let listen = component
        .as_any()
        .downcast_ref::<ListenComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not listen: {tag}"),
            )
        })?;
    Ok(Json(listen.api_connections().await))
}

async fn get_forward_connections(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let forward = component
        .as_any()
        .downcast_ref::<ForwardComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not forward: {tag}"),
            )
        })?;
    Ok(Json(forward.api_connections().await))
}

async fn get_tcp_tunnel_listen_connections(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let tunnel = component
        .as_any()
        .downcast_ref::<TcpTunnelListenComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not tcp_tunnel_listen: {tag}"),
            )
        })?;
    Ok(Json(tunnel.api_connections().await))
}

async fn get_tcp_tunnel_forward_connections(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let tunnel = component
        .as_any()
        .downcast_ref::<TcpTunnelForwardComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not tcp_tunnel_forward: {tag}"),
            )
        })?;
    Ok(Json(tunnel.api_connections().await))
}

async fn get_load_balancer_traffic(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let lb = component
        .as_any()
        .downcast_ref::<LoadBalancerComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not load_balancer: {tag}"),
            )
        })?;
    Ok(Json(lb.api_traffic().await))
}

async fn get_filter_info(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let filter = component
        .as_any()
        .downcast_ref::<FilterComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not filter: {tag}"),
            )
        })?;
    Ok(Json(filter.api_info()))
}

async fn get_ip_router_info(
    AxumPath(tag): AxumPath<String>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let ip_router = component
        .as_any()
        .downcast_ref::<IPRouterComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not ip_router: {tag}"),
            )
        })?;
    Ok(Json(ip_router.api_info()))
}

async fn post_ip_router_action(
    AxumPath(tag): AxumPath<String>,
    Query(query): Query<IPRouterActionQuery>,
    State(state): State<ApiState>,
) -> ApiJson {
    let component = require_component(&state, &tag)?;
    let ip_router = component
        .as_any()
        .downcast_ref::<IPRouterComponent>()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("component is not ip_router: {tag}"),
            )
        })?;

    let action = query.action.unwrap_or_default();
    if action != "geoip_update" {
        return Err((StatusCode::BAD_REQUEST, format!("unknown action: {action}")));
    }

    ip_router.geoip_update().await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("geoip_update failed: {err}"),
        )
    })?;

    Ok(Json(json!("ok")))
}

async fn get_h5_index(State(state): State<ApiState>) -> Result<Response, ApiError> {
    serve_h5_file(&state, "").await
}

async fn get_h5_file(
    AxumPath(file_path): AxumPath<String>,
    State(state): State<ApiState>,
) -> Result<Response, ApiError> {
    serve_h5_file(&state, &file_path).await
}

async fn serve_h5_file(state: &ApiState, requested_path: &str) -> Result<Response, ApiError> {
    let Some(root) = &state.h5_root else {
        return Err((
            StatusCode::NOT_FOUND,
            "h5_files_path is not configured".to_string(),
        ));
    };

    let file_path = if requested_path.trim().is_empty() {
        "index.html".to_string()
    } else {
        requested_path.trim_start_matches('/').to_string()
    };

    let relative = Path::new(&file_path);
    let invalid = relative.components().any(|part| {
        matches!(
            part,
            PathComponent::ParentDir | PathComponent::RootDir | PathComponent::Prefix(_)
        )
    });
    if invalid {
        return Err((StatusCode::BAD_REQUEST, "invalid file path".to_string()));
    }

    let mut target = root.join(relative);
    if let Ok(metadata) = fs::metadata(&target).await {
        if metadata.is_dir() {
            target = target.join("index.html");
        }
    }

    let body = fs::read(&target).await.map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            (
                StatusCode::NOT_FOUND,
                format!("file not found: {}", target.display()),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to read file {}: {err}", target.display()),
            )
        }
    })?;

    let mime = mime_guess::from_path(&target)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let mut response = Response::new(Body::from(body));
    let header_value = HeaderValue::from_str(&mime)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header_value);
    Ok(response)
}

fn component_info_for_tag(state: &ApiState, tag: &str) -> Option<Value> {
    let component = state.router.get_component(tag)?;
    let available = component.is_available();
    let service = find_service_by_tag(&state.router, tag)?;
    let service_type = service_type(&service).unwrap_or_default();

    let info = match service_type {
        "listen" => component
            .as_any()
            .downcast_ref::<ListenComponent>()
            .map(|v| v.api_info()),
        "forward" => component
            .as_any()
            .downcast_ref::<ForwardComponent>()
            .map(|v| v.api_info()),
        "filter" => component
            .as_any()
            .downcast_ref::<FilterComponent>()
            .map(|v| v.api_info()),
        "load_balancer" => Some(merge_json(yaml_to_json(&service), json!({"tag": tag}))),
        "ip_router" => component
            .as_any()
            .downcast_ref::<IPRouterComponent>()
            .map(|v| v.api_info()),
        "tcp_tunnel_listen" => component
            .as_any()
            .downcast_ref::<TcpTunnelListenComponent>()
            .map(|v| v.api_info()),
        "tcp_tunnel_forward" => component
            .as_any()
            .downcast_ref::<TcpTunnelForwardComponent>()
            .map(|v| v.api_info()),
        _ => Some(yaml_to_json(&service)),
    }?;

    Some(merge_json(info, json!({"available": available})))
}

fn require_component(state: &ApiState, tag: &str) -> Result<Arc<dyn Component>, ApiError> {
    state
        .router
        .get_component(tag)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("component not found: {tag}")))
}

fn find_service_by_tag(router: &Router, tag: &str) -> Option<serde_yaml::Value> {
    for service in &router.config.services {
        if service_tag(service) == Some(tag) {
            return Some(service.clone());
        }
    }
    None
}

fn service_tag(value: &serde_yaml::Value) -> Option<&str> {
    value.get("tag").and_then(|v| v.as_str())
}

fn service_type(value: &serde_yaml::Value) -> Option<&str> {
    value.get("type").and_then(|v| v.as_str())
}

fn yaml_to_json(value: &serde_yaml::Value) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn merge_json(base: Value, overlay: Value) -> Value {
    let mut base_obj = match base {
        Value::Object(v) => v,
        _ => return overlay,
    };
    let overlay_obj = match overlay {
        Value::Object(v) => v,
        _ => return Value::Object(base_obj),
    };

    for (k, v) in overlay_obj {
        base_obj.insert(k, v);
    }
    Value::Object(base_obj)
}
