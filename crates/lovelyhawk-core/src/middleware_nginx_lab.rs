//! Invoked only by tools/lab/probe-nginx-process.mjs against its owned fixture.
use super::*;
use crate::{services::BackendServices, ssh::HostKeyConfirmations};

async fn observed(services: &BackendServices, session: &BoundSshSession, command: &str) -> String {
    let result = services
        .ssh()
        .execute_bound(session, command.to_owned(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!result.timed_out);
    assert_eq!(result.exit_code, Some(0));
    result.output
}

fn change(draft: &MiddlewareDraft, name: &str, replacement: &str) -> MiddlewareDraft {
    let nodes: Vec<_> = draft
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.name.as_deref() == Some(name))
        .collect();
    assert_eq!(nodes.len(), 1, "fixture must have one selected directive");
    draft
        .apply_node_edit(nodes[0].0, replacement.to_owned())
        .unwrap()
}

fn check(label: &str) {
    println!("NGINX_CORE_CHECK {label}");
}

#[tokio::test]
#[ignore = "requires the uniquely owned WSL/Docker fixture from tools/lab/probe-nginx-process.mjs"]
async fn owned_nginx_process_repair() {
    let root = std::env::var("LOVELYHAWK_NGINX_LAB_ROOT").expect("owned fixture data root");
    let run = std::env::var("LOVELYHAWK_NGINX_LAB_RUN").expect("owned fixture run UUID");
    assert!(Uuid::parse_str(&run).is_ok());
    assert!(
        std::path::Path::new(&root)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("lovelyres-nginx-process-")
    );
    let services = BackendServices::new(PortableStore::prepare(root.into()).unwrap()).unwrap();
    let mut connection = services
        .ssh()
        .connect(&run, HostKeyConfirmations::default())
        .await;
    for _ in 0..2 {
        if connection.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        connection = services
            .ssh()
            .connect(&run, HostKeyConfirmations::default())
            .await;
    }
    let status = connection.unwrap();
    let guard = services
        .activate_target(TargetIdentity::new(&run).unwrap())
        .unwrap();
    let session = services
        .bind_active_ssh_session(&guard, &status.session_id)
        .await
        .unwrap();
    // The outer harness verifies full Docker identity/mounts before launching;
    // this separate marker prevents a reused SSH port from selecting another host.
    assert_eq!(
        observed(&services, &session, "cat /tmp/lovelyres-nginx-run")
            .await
            .trim(),
        run
    );
    let service = services.middleware();
    let instances = service.discover(&session).await.unwrap();
    assert_eq!(instances.len(), 1);
    let instance = &instances[0];
    assert_eq!(instance.runtime(), MiddlewareRuntimeKind::NginxProcess);
    check("discovery falls back when systemctl is installed without systemd");
    let bundle = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    assert_eq!(bundle.unresolved_includes().len(), 0);
    let index = bundle
        .files
        .iter()
        .position(|file| file.path.as_str() == "/etc/nginx/conf.d/lovelyres-process.conf")
        .unwrap();
    let original = &bundle.files[index];
    let draft = original.create_draft().unwrap();
    let sftp = services
        .sftp()
        .bind_session(guard.clone(), session.session_id())
        .await
        .unwrap();
    let original_bytes = services
        .sftp()
        .read_file(&sftp, &original.path)
        .await
        .unwrap();
    assert!(
        observed(
            &services,
            &session,
            "curl --max-time 3 -sS http://127.0.0.1:8080/listing/"
        )
        .await
        .contains("item.txt")
    );
    check("relative include graph and initial real directory exposure captured");

    let mut unconfirmed = service
        .plan_change(&session, &bundle, index, change(&draft, "autoindex", "off"))
        .await
        .unwrap();
    let history_before = service.history(&guard).unwrap();
    assert!(unconfirmed.execute_and_verify().await.is_err());
    assert_eq!(service.history(&guard).unwrap(), history_before);
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        original_bytes
    );
    check("unconfirmed operation cannot change remote bytes or create a false recovery record");

    let mut invalid = service
        .plan_change(
            &session,
            &bundle,
            index,
            change(&draft, "autoindex", "invalid-value"),
        )
        .await
        .unwrap();
    invalid
        .confirm(DangerousConfirmation::approve(invalid.definition()))
        .unwrap();
    let failure = invalid.execute_and_verify().await.unwrap_err();
    assert_eq!(invalid.state(), OperationState::Restored, "{failure}");
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        original_bytes
    );
    assert!(
        service
            .history(&guard)
            .unwrap()
            .iter()
            .any(|record| record.state == MiddlewareChangeState::AutomaticallyRestored)
    );
    assert!(
        observed(
            &services,
            &session,
            "curl --max-time 3 -sS http://127.0.0.1:8080/listing/"
        )
        .await
        .contains("item.txt")
    );
    check("native syntax rejection restores exact original bytes and serving fixture");

    // Port 22 belongs to this fixture's sshd. nginx -t accepts this syntax, but
    // HUP cannot bind the new listener and must keep serving the old config.
    let before_reload_failure = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    let blocked_listener = change(
        &before_reload_failure.files[index].create_draft().unwrap(),
        "listen",
        "127.0.0.1:22",
    );
    let mut blocked_reload = service
        .plan_change(&session, &before_reload_failure, index, blocked_listener)
        .await
        .unwrap();
    blocked_reload
        .confirm(DangerousConfirmation::approve(blocked_reload.definition()))
        .unwrap();
    let failure = blocked_reload.execute_and_verify().await.unwrap_err();
    assert!(failure.to_string().contains("新工作进程"), "{failure}");
    assert_eq!(
        blocked_reload.state(),
        OperationState::Restored,
        "{failure}"
    );
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        original_bytes
    );
    assert!(
        observed(
            &services,
            &session,
            "curl --max-time 3 -sS http://127.0.0.1:8080/listing/"
        )
        .await
        .contains("item.txt")
    );
    check(
        "syntax-valid listener conflict fails verification and restores the serving configuration",
    );

    let bundle = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    let draft = bundle.files[index].create_draft().unwrap();
    let draft = change(&change(&draft, "autoindex", "off"), "server_tokens", "off");
    let mut plan = service
        .plan_change(&session, &bundle, index, draft)
        .await
        .unwrap();
    assert_ne!(plan.preview().old_sha256, plan.preview().new_sha256);
    assert!(
        plan.confirm(DangerousConfirmation::approve(unconfirmed.definition()))
            .is_err()
    );
    plan.confirm(DangerousConfirmation::approve(plan.definition()))
        .unwrap();
    let outcome = plan.execute_and_verify().await.unwrap();
    assert!(
        outcome.verification.passed && outcome.history_persisted && !outcome.automatically_restored
    );
    assert_eq!(outcome.record.state, MiddlewareChangeState::Applied);
    assert!(plan.execute_and_verify().await.is_err());
    assert_eq!(
        service
            .history(&guard)
            .unwrap()
            .into_iter()
            .find(|record| record.id == outcome.record.id)
            .unwrap()
            .state,
        MiddlewareChangeState::Applied
    );
    check("replayed execution cannot downgrade the applied recovery record");
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &outcome.record.remote_backup)
            .await
            .unwrap(),
        original_bytes
    );
    let response = observed(
        &services,
        &session,
        "curl --max-time 3 -sSI http://127.0.0.1:8080/listing/",
    )
    .await;
    assert!(
        response.contains("403 Forbidden")
            && response.contains("Server: nginx\r\n")
            && !response.contains("nginx/1.")
    );
    check(
        "exact confirmed repair creates backup, switches workers, disables listing and hides version",
    );
    let repaired = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    assert!(
        service
            .plan_change(
                &session,
                &repaired,
                index,
                repaired.files[index].create_draft().unwrap()
            )
            .await
            .is_err()
    );
    check("unchanged repair is rejected without another write or reload");

    let mut restore = service
        .plan_restore(&session, &outcome.record.id)
        .await
        .unwrap();
    restore
        .confirm(DangerousConfirmation::approve(restore.definition()))
        .unwrap();
    assert!(
        restore
            .execute_and_verify()
            .await
            .unwrap()
            .verification
            .passed
    );
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        original_bytes
    );
    assert!(
        observed(
            &services,
            &session,
            "curl --max-time 3 -sS http://127.0.0.1:8080/listing/"
        )
        .await
        .contains("item.txt")
    );
    check("durable restoration revalidates process evidence and restores original response");

    let recipe_graph = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    let candidates = recipe_graph.nginx_hardening_candidates().unwrap();
    assert_eq!(candidates.len(), 2);
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.setting() == NginxHardeningSetting::Autoindex)
        .unwrap();
    let mut recipe = service
        .plan_nginx_hardening(&session, &recipe_graph, candidate)
        .await
        .unwrap();
    recipe
        .confirm(DangerousConfirmation::approve(recipe.definition()))
        .unwrap();
    let recipe_outcome = recipe.execute_and_verify().await.unwrap();
    assert!(
        observed(
            &services,
            &session,
            "curl --max-time 3 -sSI http://127.0.0.1:8080/listing/"
        )
        .await
        .contains("403 Forbidden")
    );
    let changed_graph = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    assert!(
        service
            .plan_nginx_hardening(&session, &changed_graph, candidate)
            .await
            .is_err()
    );
    let mut recipe_restore = service
        .plan_restore(&session, &recipe_outcome.record.id)
        .await
        .unwrap();
    recipe_restore
        .confirm(DangerousConfirmation::approve(recipe_restore.definition()))
        .unwrap();
    recipe_restore.execute_and_verify().await.unwrap();
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        original_bytes
    );
    check(
        "closed hardening recipe repairs exact node, rejects old candidate, and restores original file",
    );

    let fresh = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    let mut stale = service
        .plan_change(
            &session,
            &fresh,
            index,
            change(
                &fresh.files[index].create_draft().unwrap(),
                "autoindex",
                "off",
            ),
        )
        .await
        .unwrap();
    stale
        .confirm(DangerousConfirmation::approve(stale.definition()))
        .unwrap();
    observed(
        &services,
        &session,
        "printf '\n# concurrent fixture edit\n' >> /etc/nginx/conf.d/lovelyres-process.conf",
    )
    .await;
    let concurrent = services
        .sftp()
        .read_file(&sftp, &original.path)
        .await
        .unwrap();
    assert!(stale.execute_and_verify().await.is_err());
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        concurrent
    );
    check("changed file rejects old confirmed plan and preserves concurrent bytes");

    let before_restart = service
        .load_configuration(&session, instance)
        .await
        .unwrap();
    let mut stale_process = service
        .plan_change(
            &session,
            &before_restart,
            index,
            change(
                &before_restart.files[index].create_draft().unwrap(),
                "autoindex",
                "off",
            ),
        )
        .await
        .unwrap();
    stale_process
        .confirm(DangerousConfirmation::approve(stale_process.definition()))
        .unwrap();
    observed(&services, &session, "nginx -s quit && sleep 1 && nginx").await;
    let replacement = service.discover(&session).await.unwrap();
    assert_eq!(replacement.len(), 1);
    assert_ne!(replacement[0].main_pid(), instance.main_pid());
    assert!(stale_process.execute_and_verify().await.is_err());
    assert_eq!(
        services
            .sftp()
            .read_file(&sftp, &original.path)
            .await
            .unwrap(),
        concurrent
    );
    check("restarted master rejects old confirmed plan without changing configuration");
    services.ssh().disconnect(&status.session_id).await.unwrap();
    println!("NGINX_CORE_SUITE_COMPLETE");
}
