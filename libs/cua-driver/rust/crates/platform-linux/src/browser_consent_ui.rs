// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Exact Linux AT-SPI handling for Chromium's browser-owned debugging consent.

use std::time::{Duration, Instant};

use cua_driver_core::browser::platform::BrowserConsentAction;
use cua_driver_core::browser::{
    BrowserConsentOutcome, BrowserConsentRequest, BrowserRefusal, BrowserRefusalCode,
};

use crate::atspi::AtspiNode;
use crate::dialog_matcher::{
    exact_button_center, has_nonempty_accessible_text, is_descendant_of, role_is,
    trusted_prompt_nodes,
};
use crate::interaction::{session_policy, with_target_foreground};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConsentButtonCandidate {
    element_index: usize,
    parent_element_index: usize,
    rect: (i32, i32, i32, i32),
    focused: bool,
    depth: usize,
}

fn exact_native_prompt_root(nodes: &[AtspiNode]) -> Result<Option<usize>, BrowserRefusal> {
    let roots = trusted_prompt_nodes(nodes)
        .filter(|node| {
            role_is(node, &["alert"])
                && node.element_index.is_some()
                && has_nonempty_accessible_text(node)
                && node.parent_element_index.is_some_and(|parent_index| {
                    nodes
                        .iter()
                        .find(|candidate| candidate.element_index == Some(parent_index))
                        .is_some_and(|parent| role_is(parent, &["frame", "window"]))
                })
        })
        .filter_map(|root| {
            let root_index = root.element_index?;
            let heading_count = trusted_prompt_nodes(nodes)
                .filter(|node| {
                    is_descendant_of(nodes, node, root_index)
                        && role_is(node, &["heading"])
                        && has_nonempty_accessible_text(node)
                })
                .count();
            let explanatory_surface_present = trusted_prompt_nodes(nodes).any(|node| {
                is_descendant_of(nodes, node, root_index)
                    && !role_is(node, &["heading", "push button", "button"])
                    && has_nonempty_accessible_text(node)
            });
            (heading_count == 1 && explanatory_surface_present).then_some(root_index)
        })
        .collect::<Vec<_>>();
    match roots.as_slice() {
        [] => Ok(None),
        [root] => Ok(Some(*root)),
        _ => Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the approved Chromium window exposed multiple native consent alerts",
        )),
    }
}

fn native_prompt_surface_present(nodes: &[AtspiNode]) -> bool {
    exact_native_prompt_root(nodes).ok().flatten().is_some()
}

fn redacted_native_prompt_snapshot(
    nodes: &[AtspiNode],
    bounds: &[(usize, i32, i32, u32, u32)],
) -> serde_json::Value {
    serde_json::Value::Array(
        trusted_prompt_nodes(nodes)
            .filter(|node| {
                has_nonempty_accessible_text(node)
                    || !node.actions.is_empty()
                    || node.focused == Some(true)
            })
            // Chromium appends browser-owned transient UI after its persistent
            // toolbar controls in the AT-SPI tree. Prefer that end when the
            // redacted diagnostic must stay bounded, otherwise the first 64
            // entries contain only the omnibox/toolbars and hide the prompt
            // topology we need to refuse safely.
            .rev()
            .take(64)
            .map(|node| {
                let parent_role = node.parent_element_index.and_then(|parent_index| {
                    nodes
                        .iter()
                        .find(|candidate| candidate.element_index == Some(parent_index))
                        .map(|parent| parent.role.as_str())
                });
                let node_bounds = node.element_index.and_then(|element_index| {
                    bounds
                        .iter()
                        .find(|(index, ..)| *index == element_index)
                        .map(|(_, x, y, width, height)| {
                            serde_json::json!({
                                "x": x,
                                "y": y,
                                "width": width,
                                "height": height,
                            })
                        })
                });
                serde_json::json!({
                    "role": &node.role,
                    "depth": node.depth,
                    "element_index": node.element_index,
                    "parent_element_index": node.parent_element_index,
                    "parent_role": parent_role,
                    "actions": &node.actions,
                    "focused": node.focused,
                    "enabled": node.enabled,
                    "has_text": has_nonempty_accessible_text(node),
                    "bounds": node_bounds,
                })
            })
            .collect(),
    )
}

fn edge_gap(first: (i32, i32, i32, i32), second: (i32, i32, i32, i32)) -> Option<i64> {
    let (first_left, first_top, first_right, first_bottom) = first;
    let (second_left, second_top, second_right, second_bottom) = second;
    if first_top != second_top || first_bottom != second_bottom {
        return None;
    }
    if first_right <= second_left {
        Some(i64::from(second_left) - i64::from(first_right))
    } else if second_right <= first_left {
        Some(i64::from(first_left) - i64::from(second_right))
    } else {
        None
    }
}

/// The prompt's allow and cancel controls, each an `element_index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsentActions {
    allow: usize,
    cancel: usize,
}

fn select_language_independent_actions(
    candidates: &[ConsentButtonCandidate],
) -> Result<ConsentActions, BrowserRefusal> {
    // Chromium's dialog row on Linux is the extra action ("Turn off in
    // settings"), then Cancel, then Allow, in that child order in every
    // locale. RTL locales mirror the row on screen but keep the order, so
    // order names the buttons and geometry only has to agree that Cancel sits
    // between the other two. Names are localized and never read. Focus is
    // contradiction evidence only: Chromium focuses Cancel, an inactive
    // browser focuses nothing.
    let mut ordered = candidates.to_vec();
    ordered.sort_by_key(|candidate| candidate.element_index);
    let [extra, cancel, allow] = ordered.as_slice() else {
        return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the native Chromium consent prompt did not expose exactly three distinct dialog buttons",
        ));
    };
    if [cancel, allow]
        .iter()
        .any(|candidate| candidate.parent_element_index != extra.parent_element_index)
    {
        return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the native Chromium consent buttons did not share one exact action container",
        ));
    }
    let center = |candidate: &ConsentButtonCandidate| {
        i64::from(candidate.rect.0) + i64::from(candidate.rect.2)
    };
    let one_row = edge_gap(extra.rect, cancel.rect).is_some()
        && edge_gap(cancel.rect, allow.rect).is_some()
        && edge_gap(extra.rect, allow.rect).is_some();
    let cancel_between = (center(extra) < center(cancel) && center(cancel) < center(allow))
        || (center(allow) < center(cancel) && center(cancel) < center(extra));
    if !one_row || !cancel_between {
        return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the native Chromium consent buttons did not form one row with cancel between its neighbours",
        ));
    }
    let focused = ordered
        .iter()
        .filter(|candidate| candidate.focused)
        .collect::<Vec<_>>();
    match focused.as_slice() {
        [] => {}
        [focused] if focused.element_index == cancel.element_index => {}
        _ => return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the native Chromium consent prompt focus contradicted its structural cancel button",
        )),
    }
    Ok(ConsentActions {
        allow: allow.element_index,
        cancel: cancel.element_index,
    })
}

fn exact_consent_actions(
    nodes: &[AtspiNode],
    bounds: &[(usize, i32, i32, u32, u32)],
) -> Result<Option<ConsentActions>, BrowserRefusal> {
    let Some(prompt_root) = exact_native_prompt_root(nodes)? else {
        return Ok(None);
    };
    let mut candidates = Vec::new();
    for node in trusted_prompt_nodes(nodes).filter(|node| {
        is_descendant_of(nodes, node, prompt_root)
            && role_is(node, &["push button", "button"])
            && !node.actions.is_empty()
            && node.enabled != Some(false)
            && node.element_index.is_some()
            && node.parent_element_index.is_some()
    }) {
        let element_index = node.element_index.expect("filtered actionable index");
        let parent_element_index = node
            .parent_element_index
            .expect("filtered action-container index");
        let Some((_, x, y, width, height)) =
            bounds.iter().find(|(index, ..)| *index == element_index)
        else {
            continue;
        };
        let (Ok(width), Ok(height)) = (i32::try_from(*width), i32::try_from(*height)) else {
            continue;
        };
        if width <= 1 || height <= 1 {
            continue;
        }
        let Some(right) = x.checked_add(width) else {
            continue;
        };
        let Some(bottom) = y.checked_add(height) else {
            continue;
        };
        let candidate = ConsentButtonCandidate {
            element_index,
            parent_element_index,
            rect: (*x, *y, right, bottom),
            focused: node.focused == Some(true),
            depth: node.depth,
        };
        if let Some(existing) = candidates
            .iter_mut()
            .find(|existing: &&mut ConsentButtonCandidate| existing.rect == candidate.rect)
        {
            if candidate.depth > existing.depth {
                *existing = candidate;
            }
        } else {
            candidates.push(candidate);
        }
    }
    select_language_independent_actions(&candidates).map(Some)
}

fn exact_allow_button(
    nodes: &[AtspiNode],
    bounds: &[(usize, i32, i32, u32, u32)],
) -> Result<Option<usize>, BrowserRefusal> {
    Ok(exact_consent_actions(nodes, bounds)?.map(|actions| actions.allow))
}

fn exact_cancel_button(
    nodes: &[AtspiNode],
    bounds: &[(usize, i32, i32, u32, u32)],
) -> Result<Option<usize>, BrowserRefusal> {
    Ok(exact_consent_actions(nodes, bounds)?.map(|actions| actions.cancel))
}

fn prove_window_owner(pid: u32, window_id: u64) -> Result<(), BrowserRefusal> {
    let owned = crate::wayland::list_windows_dispatch(Some(pid))
        .into_iter()
        .any(|window| window.xid == window_id);
    if !owned {
        return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserBindingStale,
            "the approved browser window changed ownership before consent",
        ));
    }
    Ok(())
}

fn trusted_allow_click(pid: u32, window_id: u64) -> anyhow::Result<()> {
    with_target_foreground(pid, window_id, session_policy().setup, || {
        let tree = crate::atspi::walk_tree_no_web_content(pid, window_id, None);
        let index = exact_allow_button(&tree.nodes, &tree.bounds)
            .map_err(|error| anyhow::anyhow!(error.message))?
            .ok_or_else(|| {
                anyhow::anyhow!("the exact Chromium remote-debugging consent action became stale")
            })?;
        let (center_x, center_y) = exact_button_center(&tree.bounds, index)?;
        if crate::desktop::desktop() != crate::desktop::Desktop::X11 {
            crate::wayland::click_focused((center_x, center_y).into(), 1, 1)
        } else {
            crate::input::send_click_xtest_desktop(center_x, center_y, 1, 1)
        }
    })
}

/// The node at element `index` of a walk of the consent window, which an
/// exact action addresses through its own object.
fn walked_node(nodes: &[AtspiNode], index: usize) -> Result<AtspiNode, BrowserRefusal> {
    nodes
        .iter()
        .find(|node| node.element_index == Some(index))
        .cloned()
        .ok_or_else(|| {
            BrowserRefusal::new(
                BrowserRefusalCode::BrowserWrongTargetRefused,
                "the exact browser consent control left its walk",
            )
        })
}

pub fn dismiss(pid: u32, window_id: u64) -> Result<bool, BrowserRefusal> {
    prove_window_owner(pid, window_id)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut dismissed = false;
    loop {
        prove_window_owner(pid, window_id)?;
        let tree = crate::atspi::walk_tree_no_web_content(pid, window_id, None);
        let prompt_present = native_prompt_surface_present(&tree.nodes);
        if !prompt_present {
            return Ok(dismissed);
        }
        let index = exact_cancel_button(&tree.nodes, &tree.bounds)?.ok_or_else(|| {
            BrowserRefusal::new(
                BrowserRefusalCode::BrowserWrongTargetRefused,
                "the exact remote-debugging consent prompt exposed no semantic cancel action",
            )
        })?;
        let node = walked_node(&tree.nodes, index)?;
        // A cancel that failed after it was sent may have dismissed the
        // prompt: the next pass reads that back instead of refusing.
        crate::atspi::action_sent(crate::atspi::perform_action_walked(pid, window_id, &node))
            .map_err(|error| {
                BrowserRefusal::new(
                    BrowserRefusalCode::BrowserWrongTargetRefused,
                    format!("the exact browser consent cancel action failed: {error}"),
                )
            })?;
        dismissed = true;
        if Instant::now() >= deadline {
            return Err(BrowserRefusal::new(
                BrowserRefusalCode::BrowserWrongTargetRefused,
                "the remote-debugging consent prompt remained after its exact cancel action",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn check_deadline(deadline: Instant) -> Result<(), BrowserRefusal> {
    if Instant::now() >= deadline {
        return Err(BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "Chromium remote-debugging consent did not settle within its bounded attempt",
        ));
    }
    Ok(())
}

async fn consent_action<T: Send + 'static>(
    action: &BrowserConsentAction,
    deadline: Instant,
    operation: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Result<T, BrowserRefusal> {
    check_deadline(deadline)?;
    // Commit before scheduling: dropping a running blocking task cannot cancel it.
    let worker = action.perform(|| {
        // The worker waits on the one foreground transaction and runs under
        // no action of its own, so it binds this one: every wait it makes,
        // that one included, ends at the consent deadline instead of
        // outliving the attempt it serves.
        let bound =
            crate::input::action::Action::new(deadline.saturating_duration_since(Instant::now()));
        tokio::task::spawn_blocking(move || {
            let _bound = crate::input::action::bind(bound);
            check_deadline(deadline)?;
            operation().map_err(|error| {
                BrowserRefusal::new(
                    BrowserRefusalCode::BrowserWrongTargetRefused,
                    format!("the exact browser consent action failed: {error}"),
                )
            })
        })
    });
    let result = worker.await.map_err(|error| {
        BrowserRefusal::new(
            BrowserRefusalCode::BrowserRouteUnavailable,
            format!("could not dispatch the exact browser consent action: {error}"),
        )
    })??;
    // The native helper may outlast our deadline. Join it, then refuse without fallback.
    check_deadline(deadline)?;
    Ok(result)
}

const DEFAULT_CONSENT_WAIT_MS: u64 = 10_000;
const MIN_CONSENT_WAIT_MS: u64 = 500;
const MAX_CONSENT_WAIT_MS: u64 = 30_000;

fn resolve_wait_duration(wait_ms: Option<u64>) -> Duration {
    let ms = wait_ms
        .unwrap_or(DEFAULT_CONSENT_WAIT_MS)
        .clamp(MIN_CONSENT_WAIT_MS, MAX_CONSENT_WAIT_MS);
    Duration::from_millis(ms)
}

async fn handle_with_ops<FInspect, FA11y, FTrusted>(
    request: &BrowserConsentRequest,
    mut prove_owner: impl FnMut() -> Result<(), BrowserRefusal>,
    mut inspect_tree: impl FnMut() -> FInspect,
    mut perform_a11y: impl FnMut(AtspiNode) -> FA11y,
    mut perform_trusted: impl FnMut() -> FTrusted,
) -> Result<BrowserConsentOutcome, BrowserRefusal>
where
    FInspect: std::future::Future<
        Output = Result<(Vec<AtspiNode>, Vec<(usize, i32, i32, u32, u32)>), BrowserRefusal>,
    >,
    FA11y: std::future::Future<Output = Result<(), BrowserRefusal>>,
    FTrusted: std::future::Future<Output = Result<(), BrowserRefusal>>,
{
    prove_owner()?;
    let deadline = Instant::now() + resolve_wait_duration(request.wait_ms);
    let mut saw_prompt = false;
    let mut accessibility_action_at = None;
    let mut trusted_click_attempted = false;
    // Names are withheld: the snapshot shows the topology of the last walk
    // that failed to settle without leaking page or prompt text.
    let mut last_snapshot = serde_json::Value::Null;
    let mut last_transient_refusal: Option<BrowserRefusal> = None;
    loop {
        if let Err(refusal) = check_deadline(deadline) {
            return Err(last_transient_refusal.unwrap_or(refusal).with_detail(
                serde_json::json!({
                    "redacted_native_nodes": last_snapshot,
                }),
            ));
        }
        prove_owner()?;
        let (nodes, bounds) = inspect_tree().await?;
        last_snapshot = redacted_native_prompt_snapshot(&nodes, &bounds);
        if let Err(refusal) = check_deadline(deadline) {
            return Err(last_transient_refusal.unwrap_or(refusal).with_detail(
                serde_json::json!({
                    "redacted_native_nodes": last_snapshot,
                }),
            ));
        }
        let prompt_present = native_prompt_surface_present(&nodes);
        saw_prompt |= prompt_present;
        match exact_allow_button(&nodes, &bounds) {
            Ok(Some(index)) if accessibility_action_at.is_none() => {
                last_transient_refusal = None;
                let node = walked_node(&nodes, index)?;
                // Like an accepted action, one that failed after it was sent
                // is read back from the prompt below.
                perform_a11y(node).await?;
                accessibility_action_at = Some(Instant::now());
            }
            Ok(Some(_))
                if !trusted_click_attempted
                    && accessibility_action_at.is_some_and(|attempted| {
                        attempted.elapsed() >= Duration::from_millis(150)
                    }) =>
            {
                last_transient_refusal = None;
                perform_trusted().await?;
                trusted_click_attempted = true;
            }
            Ok(Some(_)) => {
                last_transient_refusal = None;
            }
            Ok(None) if saw_prompt && !prompt_present => {
                if accessibility_action_at.is_some() {
                    return Ok(BrowserConsentOutcome::Accepted);
                }
                return Err(BrowserRefusal::new(
                    BrowserRefusalCode::BrowserConsentRevoked,
                    "the person dismissed the browser consent prompt",
                ));
            }
            Ok(None) => {}
            Err(refusal) if refusal.code == BrowserRefusalCode::BrowserWrongTargetRefused => {
                // Transient layout state (e.g. alert rendered before all 3 buttons
                // finish laying out): keep polling until the deadline expires.
                last_transient_refusal = Some(refusal);
            }
            Err(refusal) => return Err(refusal),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn handle(
    request: BrowserConsentRequest,
) -> Result<BrowserConsentOutcome, BrowserRefusal> {
    let pid = u32::try_from(request.pid).map_err(|_| {
        BrowserRefusal::new(
            BrowserRefusalCode::BrowserWrongTargetRefused,
            "the approved browser pid is outside the Linux process-id range",
        )
    })?;
    let window_id = request.window_id;
    let action = request.action.clone();
    handle_with_ops(
        &request,
        || prove_window_owner(pid, window_id),
        || async move {
            let tree = tokio::task::spawn_blocking(move || {
                crate::atspi::walk_tree_no_web_content(pid, window_id, None)
            })
            .await
            .map_err(|error| {
                BrowserRefusal::new(
                    BrowserRefusalCode::BrowserRouteUnavailable,
                    format!("could not inspect the browser consent UI: {error}"),
                )
            })?;
            Ok((tree.nodes, tree.bounds))
        },
        |node| {
            let action = action.clone();
            let deadline = Instant::now() + resolve_wait_duration(request.wait_ms);
            async move {
                consent_action(&action, deadline, move || {
                    crate::atspi::action_sent(crate::atspi::perform_action_walked(
                        pid, window_id, &node,
                    ))
                })
                .await
            }
        },
        || {
            let action = action.clone();
            let deadline = Instant::now() + resolve_wait_duration(request.wait_ms);
            async move {
                consent_action(&action, deadline, move || {
                    trusted_allow_click(pid, window_id)
                })
                .await
            }
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_action_never_enters_native_helper() {
        let result = consent_action(&BrowserConsentAction::default(), Instant::now(), || {
            panic!("expired action entered the native helper");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await;
        assert_eq!(
            result.unwrap_err().code,
            BrowserRefusalCode::BrowserWrongTargetRefused
        );
    }

    #[test]
    fn queued_action_checks_deadline_before_native_helper() {
        use std::future::Future;
        use std::task::Poll;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.recv().unwrap();
        runtime.block_on(async {
            let action = BrowserConsentAction::default();
            let deadline = Instant::now() + Duration::from_millis(100);
            let mut consent = Box::pin(consent_action(&action, deadline, || {
                panic!("expired queued action entered the native helper");
                #[allow(unreachable_code)]
                Ok(())
            }));
            std::future::poll_fn(|cx| {
                assert!(consent.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::sleep(Duration::from_millis(120)).await;
            release_tx.send(()).unwrap();
            assert_eq!(
                consent.await.unwrap_err().code,
                BrowserRefusalCode::BrowserWrongTargetRefused
            );
            blocker.await.unwrap();
        });
    }

    #[tokio::test]
    async fn running_action_is_joined_and_late_success_refused() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = completed.clone();
        let deadline = Instant::now() + Duration::from_millis(100);
        let result = consent_action(&BrowserConsentAction::default(), deadline, move || {
            std::thread::sleep(Duration::from_millis(120));
            worker_completed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(
            completed.load(Ordering::SeqCst),
            "native worker was detached"
        );
        assert_eq!(
            result.unwrap_err().code,
            BrowserRefusalCode::BrowserWrongTargetRefused
        );
    }

    fn node(role: &str, name: &str, actions: &[&str]) -> AtspiNode {
        AtspiNode {
            element_index: (!actions.is_empty()).then_some(7),
            role: role.to_owned(),
            name: Some(name.to_owned()),
            value: None,
            checked: None,
            enabled: None,
            selected: None,
            focused: None,
            description: None,
            document_uri: None,
            actions: actions.iter().map(|value| (*value).to_owned()).collect(),
            element_key: 0,
            identity: None,
            depth: 0,
            parent_element_index: None,
            in_web_content: false,
            object_ref: None,
        }
    }

    fn indexed_node(
        index: usize,
        role: &str,
        name: &str,
        actions: &[&str],
        parent: Option<usize>,
        depth: usize,
    ) -> AtspiNode {
        let mut result = node(role, name, actions);
        result.element_index = Some(index);
        result.element_key = index as u64;
        result.parent_element_index = parent;
        result.depth = depth;
        result
    }

    /// Button rows Chromium 156 rendered for this prompt on Linux, read over
    /// AT-SPI: `[extra, cancel, allow]` as `(x, width)` on one row. The extra
    /// action is "Turn off in settings"; Arabic mirrors the row.
    const EN_US_ROW: [(i32, u32); 3] = [(331, 161), (569, 81), (658, 81)];
    const DE_ROW: [(i32, u32); 3] = [(283, 268), (561, 109), (678, 109)];
    const AR_ROW: [(i32, u32); 3] = [(542, 197), (404, 65), (331, 65)];
    const JA_ROW: [(i32, u32); 3] = [(331, 110), (511, 110), (629, 110)];
    const ROW_Y: i32 = 297;
    const ROW_HEIGHT: u32 = 38;

    const EXTRA: usize = 183;
    const CANCEL: usize = 184;
    const ALLOW: usize = 185;

    /// The prompt's AT-SPI topology with every name made opaque: an alert
    /// under the browser frame, one heading, explanatory text, and the three
    /// buttons in one action container. Cancel holds focus, as Chromium sets.
    fn prompt_with(names: [&str; 5]) -> Vec<AtspiNode> {
        let [title, body, extra, cancel, allow] = names;
        let mut cancel = indexed_node(
            CANCEL,
            "push button",
            cancel,
            &["press", "showContextMenu"],
            Some(182),
            6,
        );
        cancel.focused = Some(true);
        vec![
            indexed_node(0, "frame", "browser", &["doDefault"], None, 0),
            indexed_node(172, "alert", title, &["doDefault"], Some(0), 1),
            indexed_node(173, "panel", "", &["doDefault"], Some(172), 2),
            indexed_node(174, "panel", "", &["doDefault"], Some(173), 3),
            indexed_node(175, "panel", "", &["doDefault"], Some(174), 4),
            indexed_node(176, "heading", title, &["doDefault"], Some(175), 5),
            indexed_node(177, "panel", "", &["doDefault"], Some(174), 4),
            indexed_node(180, "static", body, &["doDefault"], Some(177), 5),
            indexed_node(182, "panel", "", &["doDefault"], Some(177), 5),
            indexed_node(
                EXTRA,
                "push button",
                extra,
                &["press", "showContextMenu"],
                Some(182),
                6,
            ),
            cancel,
            indexed_node(
                ALLOW,
                "push button",
                allow,
                &["press", "showContextMenu"],
                Some(182),
                6,
            ),
        ]
    }

    fn prompt() -> Vec<AtspiNode> {
        prompt_with([
            "opaque title",
            "opaque body",
            "opaque extra",
            "opaque cancel",
            "opaque allow",
        ])
    }

    fn row_bounds(row: [(i32, u32); 3]) -> Vec<(usize, i32, i32, u32, u32)> {
        [EXTRA, CANCEL, ALLOW]
            .into_iter()
            .zip(row)
            .map(|(index, (x, width))| (index, x, ROW_Y, width, ROW_HEIGHT))
            .collect()
    }

    fn set_focus(nodes: &mut [AtspiNode], focused: Option<usize>) {
        for node in nodes {
            node.focused = Some(node.element_index.is_some() && node.element_index == focused);
        }
    }

    fn actions(
        nodes: &[AtspiNode],
        bounds: &[(usize, i32, i32, u32, u32)],
    ) -> Result<Option<(usize, usize)>, BrowserRefusalCode> {
        Ok((
            exact_allow_button(nodes, bounds).map_err(|error| error.code)?,
            exact_cancel_button(nodes, bounds).map_err(|error| error.code)?,
        ))
        .map(|pair| match pair {
            (Some(allow), Some(cancel)) => Some((allow, cancel)),
            (None, None) => None,
            other => panic!("allow and cancel disagreed on the prompt: {other:?}"),
        })
    }

    #[test]
    fn allow_and_cancel_are_distinct_in_every_captured_locale() {
        for (locale, names, row) in [
            (
                "en-US",
                ["Allow remote debugging?", "An external app wants full control over this Chrome session to debug it.", "Turn off in settings", "Cancel", "Allow"],
                EN_US_ROW,
            ),
            (
                "de",
                ["Remote-Fehlerbehebung zulassen?", "Eine externe App möchte die vollständige Kontrolle über diese Chrome-Sitzung erhalten.", "In den Einstellungen deaktivieren", "Abbrechen", "Zulassen"],
                DE_ROW,
            ),
            (
                "ar",
                ["\u{200f}السماح بتصحيح الأخطاء عن بُعد؟", "\u{200f}يريد تطبيق خارجي التحكّم بالكامل في جلسة Chrome هذه", "\u{200f}الإيقاف من خلال \"الإعدادات\"", "\u{200f}إلغاء", "\u{200f}سماح"],
                AR_ROW,
            ),
            (
                "ja",
                ["リモート デバッグを許可しますか？", "外部アプリが、この Chrome セッションをデバッグするため完全に制御することを求めています。", "[設定] でオフにする", "キャンセル", "許可する"],
                JA_ROW,
            ),
        ] {
            assert_eq!(
                actions(&prompt_with(names), &row_bounds(row)),
                Ok(Some((ALLOW, CANCEL))),
                "{locale}"
            );
        }
    }

    #[test]
    fn cancel_never_resolves_to_allow_when_focus_moves() {
        let bounds = row_bounds(EN_US_ROW);
        let mut unfocused = prompt();
        set_focus(&mut unfocused, None);
        assert_eq!(
            actions(&unfocused, &bounds),
            Ok(Some((ALLOW, CANCEL))),
            "an inactive browser focuses no button; geometry alone still names both"
        );

        for focused in [ALLOW, EXTRA] {
            let mut moved = prompt();
            set_focus(&mut moved, Some(focused));
            assert_eq!(
                actions(&moved, &bounds),
                Err(BrowserRefusalCode::BrowserWrongTargetRefused),
                "focus on {focused} contradicts the structural cancel button"
            );
        }
    }

    #[test]
    fn matcher_refuses_a_two_button_page_confirm_dialog() {
        // Chromium's JavaScript confirm() is a native dialog with OK focused
        // beside Cancel. It has no extra action, so it is never consent.
        let mut nodes = prompt();
        nodes.retain(|node| node.element_index != Some(EXTRA));
        let bounds = row_bounds(EN_US_ROW)
            .into_iter()
            .filter(|(index, ..)| *index != EXTRA)
            .collect::<Vec<_>>();
        for focused in [CANCEL, ALLOW] {
            set_focus(&mut nodes, Some(focused));
            assert_eq!(
                actions(&nodes, &bounds),
                Err(BrowserRefusalCode::BrowserWrongTargetRefused)
            );
        }
    }

    #[test]
    fn matcher_refuses_when_geometry_disagrees_with_child_order() {
        // Cancel must sit between its neighbours on screen; a row whose
        // second child is at an end is not the consent row.
        let bounds = vec![
            (EXTRA, 420, ROW_Y, 81, ROW_HEIGHT),
            (CANCEL, 331, ROW_Y, 81, ROW_HEIGHT),
            (ALLOW, 509, ROW_Y, 81, ROW_HEIGHT),
        ];
        let mut nodes = prompt();
        set_focus(&mut nodes, None);
        assert_eq!(
            actions(&nodes, &bounds),
            Err(BrowserRefusalCode::BrowserWrongTargetRefused)
        );
    }

    #[test]
    fn matcher_ignores_browser_toolbar_buttons_outside_the_exact_alert() {
        let mut nodes = prompt();
        nodes.push(indexed_node(
            50,
            "push button",
            "toolbar",
            &["click"],
            Some(0),
            1,
        ));
        let mut bounds = row_bounds(EN_US_ROW);
        bounds.push((50, 20, 20, 32, 32));
        assert_eq!(actions(&nodes, &bounds), Ok(Some((ALLOW, CANCEL))));
    }

    #[test]
    fn matcher_refuses_buttons_split_across_action_containers() {
        let mut nodes = prompt();
        nodes
            .iter_mut()
            .find(|node| node.element_index == Some(ALLOW))
            .expect("fixture allow")
            .parent_element_index = Some(177);
        assert_eq!(
            actions(&nodes, &row_bounds(EN_US_ROW)),
            Err(BrowserRefusalCode::BrowserWrongTargetRefused)
        );
    }

    #[test]
    fn matcher_refuses_multiple_native_alert_roots() {
        let mut nodes = prompt();
        nodes.extend([
            indexed_node(272, "alert", "another", &["doDefault"], Some(0), 1),
            indexed_node(273, "panel", "another body", &["doDefault"], Some(272), 2),
            indexed_node(274, "heading", "another", &["doDefault"], Some(273), 3),
        ]);
        assert_eq!(
            actions(&nodes, &row_bounds(EN_US_ROW)),
            Err(BrowserRefusalCode::BrowserWrongTargetRefused)
        );
    }

    #[test]
    fn matcher_refuses_a_fourth_button_in_the_row() {
        let mut nodes = prompt();
        nodes.push(indexed_node(
            186,
            "push button",
            "more",
            &["press"],
            Some(182),
            6,
        ));
        let mut bounds = row_bounds(EN_US_ROW);
        bounds.push((186, 747, ROW_Y, 81, ROW_HEIGHT));
        assert_eq!(
            actions(&nodes, &bounds),
            Err(BrowserRefusalCode::BrowserWrongTargetRefused)
        );
    }

    #[test]
    fn matcher_requires_accessible_text_to_bind_the_native_surface() {
        let mut nodes = prompt();
        for node in &mut nodes {
            node.name = None;
        }
        assert_eq!(actions(&nodes, &row_bounds(EN_US_ROW)), Ok(None));
        assert_eq!(
            actions(&[node("push button", "Allow", &["click"])], &[]),
            Ok(None)
        );
    }

    #[test]
    fn matcher_collapses_duplicate_atspi_paths_for_one_physical_button() {
        let mut nodes = prompt();
        nodes.push(indexed_node(
            186,
            "push button",
            "opaque allow",
            &["press"],
            Some(182),
            7,
        ));
        let mut bounds = row_bounds(EN_US_ROW);
        bounds.push((186, 658, ROW_Y, 81, ROW_HEIGHT));
        assert_eq!(actions(&nodes, &bounds), Ok(Some((186, CANCEL))));
    }

    #[test]
    fn matcher_ignores_a_spoofed_prompt_inside_web_content() {
        let mut nodes = prompt();
        let mut document = node("document web", "Example page", &[]);
        document.element_index = Some(42);
        nodes[0].parent_element_index = Some(42);
        nodes.insert(0, document);
        for child in &mut nodes[1..] {
            child.in_web_content = true;
        }
        assert_eq!(actions(&nodes, &row_bounds(EN_US_ROW)), Ok(None));
    }

    #[test]
    fn exact_button_center_requires_nonempty_bounds() {
        assert_eq!(
            exact_button_center(&[(7, 10, 20, 80, 30)], 7).unwrap(),
            (50, 35)
        );
        assert!(exact_button_center(&[(7, 10, 20, 1, 30)], 7).is_err());
        assert!(exact_button_center(&[(8, 10, 20, 80, 30)], 7).is_err());
    }

    #[test]
    fn resolve_wait_duration_defaults_and_clamps() {
        assert_eq!(resolve_wait_duration(None), Duration::from_millis(10_000));
        assert_eq!(resolve_wait_duration(Some(100)), Duration::from_millis(500));
        assert_eq!(
            resolve_wait_duration(Some(5_000)),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            resolve_wait_duration(Some(60_000)),
            Duration::from_millis(30_000)
        );
    }

    #[tokio::test]
    async fn transient_incomplete_buttons_retries_until_ready() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let request = BrowserConsentRequest {
            action: BrowserConsentAction::default(),
            pid: 4242,
            window_id: 77,
            attempt: 0,
            wait_ms: Some(1_000),
        };
        let pass = Arc::new(AtomicUsize::new(0));
        let clicked_index = Arc::new(AtomicUsize::new(0));

        let pass_inspect = pass.clone();
        let clicked_a11y = clicked_index.clone();
        let outcome = handle_with_ops(
            &request,
            || Ok(()),
            || {
                let current = pass_inspect.fetch_add(1, Ordering::SeqCst);
                async move {
                    match current {
                        // First pass: alert is present, but only 2 buttons are laid out.
                        0 => {
                            let mut incomplete = prompt();
                            incomplete.retain(|n| n.element_index != Some(ALLOW));
                            Ok((incomplete, row_bounds(EN_US_ROW)))
                        }
                        // Second pass: all 3 buttons are ready.
                        1 => Ok((prompt(), row_bounds(EN_US_ROW))),
                        // Third pass: prompt dismissed after Allow click.
                        _ => Ok((Vec::new(), Vec::new())),
                    }
                }
            },
            |node| {
                let clicked = clicked_a11y.clone();
                async move {
                    clicked.store(node.element_index.unwrap_or(0), Ordering::SeqCst);
                    Ok(())
                }
            },
            || async { Ok(()) },
        )
        .await;

        assert_eq!(outcome.unwrap(), BrowserConsentOutcome::Accepted);
        assert_eq!(clicked_index.load(Ordering::SeqCst), ALLOW);
        assert!(pass.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn persistent_incomplete_buttons_refuses_after_wait_ms_deadline() {
        let request = BrowserConsentRequest {
            action: BrowserConsentAction::default(),
            pid: 4242,
            window_id: 77,
            attempt: 0,
            wait_ms: Some(500),
        };
        let result = handle_with_ops(
            &request,
            || Ok(()),
            || async {
                let mut incomplete = prompt();
                incomplete.retain(|n| n.element_index != Some(ALLOW));
                Ok((incomplete, row_bounds(EN_US_ROW)))
            },
            |_node| async { Ok(()) },
            || async { Ok(()) },
        )
        .await;

        let refusal = result.unwrap_err();
        assert_eq!(refusal.code, BrowserRefusalCode::BrowserWrongTargetRefused);
    }
}
