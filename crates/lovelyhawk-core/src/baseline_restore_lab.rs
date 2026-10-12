//! Real SSH integration, only against the outer probe's owned disposable target.
use super::*;
use crate::{BackendServices, operations::JournalPhase, ssh::HostKeyConfirmations};

async fn read(services: &BackendServices, session: &BoundSshSession, command: &str) -> String {
    let result = services
        .ssh()
        .execute_bound(session, command.to_owned(), Duration::from_secs(15))
        .await
        .unwrap();
    assert!(!result.timed_out);
    assert_eq!(result.exit_code, Some(0), "{}", result.output);
    result.output
}

async fn write(services: &BackendServices, session: &BoundSshSession, file: &str, value: &str) {
    assert!(
        [
            "/etc/ssh/sshd_config",
            "/etc/redis/redis.conf",
            "/etc/redis.conf"
        ]
        .contains(&file)
    );
    read(
        services,
        session,
        &format!("printf '%s' {} > {}", shq(value), shq(file)),
    )
    .await;
}

fn check(label: &str) {
    println!("BASELINE_RESTORE_CHECK {label}");
}

// This is explicit fixture history with independently constructed complete
// before/after evidence. It does not enable a Redis generic writer in production.
async fn candidate_record(
    services: &BackendServices,
    session: &BoundSshSession,
    missing_second: bool,
) -> BaselineChangeRecord {
    let files = vec![
        "/etc/redis.conf".to_owned(),
        "/etc/redis/redis.conf".to_owned(),
    ];
    let id = Uuid::new_v4().to_string();
    let remote_root = expected_remote_root(&id).unwrap();
    let before = "# full original configuration\nprotected-mode yes\nbind 127.0.0.1\n";
    write(services, session, &files[1], before).await;
    if missing_second {
        read(services, session, "rm -f -- /etc/redis.conf").await;
    } else {
        write(
            services,
            session,
            &files[0],
            "enable-debug-command no\n# original complete second file\n",
        )
        .await;
    }
    let backup_output = read(
        services,
        session,
        &backup_prelude(&remote_root, &files).unwrap(),
    )
    .await;
    let backups = parse_backup_evidence(&backup_output, &files).unwrap();
    write(
        services,
        session,
        &files[1],
        "protected-mode no\nbind 0.0.0.0\n# applied fixture\n",
    )
    .await;
    write(
        services,
        session,
        &files[0],
        "enable-debug-command yes\n# applied second fixture\n",
    )
    .await;
    let applied_files = parse_file_evidence(
        &read(
            services,
            session,
            &format!(
                "set -eu; {}",
                files_read_body(&files, "APPLIED_FILE=", true).unwrap()
            ),
        )
        .await,
        &files,
        "APPLIED_FILE=",
    )
    .unwrap();
    let changes = vec![
        PlannedBaselineChange {
            item_id: "redis-protected-mode".to_owned(),
            before: BaselineObservedValue::Value("on".to_owned()),
            after: "off".to_owned(),
            file: files[1].clone(),
        },
        PlannedBaselineChange {
            item_id: "redis-debug-command".to_owned(),
            before: if missing_second {
                BaselineObservedValue::Missing
            } else {
                BaselineObservedValue::Value("off".to_owned())
            },
            after: "on".to_owned(),
            file: files[0].clone(),
        },
    ];
    let record = BaselineChangeRecord {
        id,
        operation_id: Uuid::new_v4().to_string(),
        last_operation_id: Uuid::new_v4().to_string(),
        target: session.target().identity.clone(),
        digest: record_digest(
            &changes,
            &files,
            &backups,
            &applied_files,
            BaselineReloadPolicy::Defer,
        )
        .unwrap(),
        changes,
        files,
        backups,
        applied_files,
        remote_root,
        reload_policy: BaselineReloadPolicy::Defer,
        state: BaselineChangeState::Applied,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    services.baseline().insert_record(record.clone()).unwrap();
    record
}

#[derive(Debug)]
struct IntervenedRestore<'a> {
    inner: RestoreExecutor<'a>,
}
#[async_trait]
impl OperationExecutor for IntervenedRestore<'_> {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        let receipt = self.inner.execute(plan).await?;
        let output = self
            .inner
            .service
            .ssh
            .execute_bound(
                self.inner.session,
                "printf '\\n# changed after restoration\\n' >> /etc/redis/redis.conf".to_owned(),
                Duration::from_secs(10),
            )
            .await?;
        assert_eq!(output.exit_code, Some(0));
        Ok(receipt)
    }
    async fn verify(
        &self,
        plan: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.inner.verify(plan, receipt).await
    }
    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        panic!("a failed restoration must not dispatch a second mutation")
    }
}

#[tokio::test]
#[ignore = "requires the uniquely owned fixture from tools/lab/probe-baseline-restore.mjs"]
async fn owned_baseline_restore() {
    let root = std::env::var("LOVELYHAWK_BASELINE_RESTORE_ROOT").expect("owned data root");
    let run = std::env::var("LOVELYHAWK_BASELINE_RESTORE_RUN").expect("owned run id");
    assert!(Uuid::parse_str(&run).is_ok());
    assert!(
        std::path::Path::new(&root)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("lovelyres-baseline-restore-")
    );
    let services = BackendServices::new(PortableStore::prepare(root.into()).unwrap()).unwrap();
    let status = services
        .ssh()
        .connect(&run, HostKeyConfirmations::default())
        .await
        .unwrap();
    let guard = services
        .activate_target(TargetIdentity::new(&run).unwrap())
        .unwrap();
    let session = services
        .bind_active_ssh_session(&guard, &status.session_id)
        .await
        .unwrap();
    assert_eq!(
        read(
            &services,
            &session,
            "cat /tmp/lovelyres-baseline-restore-run"
        )
        .await
        .trim(),
        run
    );
    let service = services.baseline();

    // First create genuine new history through the product's plan and executor.
    let original = read(&services, &session, "cat /etc/ssh/sshd_config").await;
    let plan = service
        .plan_changes(
            &session,
            vec![BaselineChangeRequest::new("ssh-max-auth-tries", "4").unwrap()],
            BaselineReloadPolicy::Defer,
        )
        .await
        .unwrap();
    let applied = service
        .execute_changes(
            &session,
            plan.clone(),
            DangerousConfirmation::approve(plan.definition()),
        )
        .await
        .unwrap();
    assert!(
        applied
            .record
            .applied_files
            .iter()
            .all(|file| file.sha256.is_some() && file.attributes.is_some())
    );
    check("real plan and apply record complete file hashes and identity");
    let applied_bytes = read(&services, &session, "cat /etc/ssh/sshd_config").await;
    write(
        &services,
        &session,
        "/etc/ssh/sshd_config",
        &format!("{applied_bytes}\n# subsequent business edit\n"),
    )
    .await;
    let restore = service.plan_restore(&session, &applied.record.id).unwrap();
    assert!(
        service
            .execute_restore(
                &session,
                restore.clone(),
                DangerousConfirmation::approve(restore.definition())
            )
            .await
            .is_err()
    );
    assert!(
        read(&services, &session, "cat /etc/ssh/sshd_config")
            .await
            .contains("subsequent business edit")
    );
    check("later unrelated content is not overwritten");
    write(&services, &session, "/etc/ssh/sshd_config", &applied_bytes).await;
    let mode = applied.record.applied_files[0]
        .attributes
        .as_ref()
        .unwrap()
        .split(':')
        .next()
        .unwrap();
    read(&services, &session, "chmod 0600 /etc/ssh/sshd_config").await;
    // The image may already use mode 0600; select a different controlled mode.
    if mode == "600" {
        read(&services, &session, "chmod 0644 /etc/ssh/sshd_config").await;
    }
    assert!(
        service
            .execute_restore(
                &session,
                restore.clone(),
                DangerousConfirmation::approve(restore.definition())
            )
            .await
            .is_err()
    );
    read(
        &services,
        &session,
        &format!("chmod {} /etc/ssh/sshd_config", shq(mode)),
    )
    .await;
    check("later permission changes require a new review");
    read(&services, &session, "mv /etc/ssh/sshd_config /tmp/lr-sshd-original-inode; cp -p /tmp/lr-sshd-original-inode /etc/ssh/sshd_config").await;
    assert!(
        service
            .execute_restore(
                &session,
                restore.clone(),
                DangerousConfirmation::approve(restore.definition())
            )
            .await
            .is_err()
    );
    read(
        &services,
        &session,
        "rm -f -- /etc/ssh/sshd_config; mv /tmp/lr-sshd-original-inode /etc/ssh/sshd_config",
    )
    .await;
    check("same bytes in a replaced inode do not reuse restore authority");
    let restored = service
        .execute_restore(
            &session,
            restore.clone(),
            DangerousConfirmation::approve(restore.definition()),
        )
        .await
        .unwrap();
    assert!(restored.verification.passed);
    assert_eq!(
        read(&services, &session, "cat /etc/ssh/sshd_config").await,
        original
    );
    check("confirmed history restore independently verifies the full original file");

    let record = candidate_record(&services, &session, false).await;
    let current = read(&services, &session, "cat /etc/redis.conf").await;
    let backup = format!("{}/file-1.before", record.remote_root);
    let saved_backup = read(&services, &session, &format!("cat {}", shq(&backup))).await;
    read(
        &services,
        &session,
        &format!("printf 'damaged backup' > {}", shq(&backup)),
    )
    .await;
    let plan = service.plan_restore(&session, &record.id).unwrap();
    assert!(
        service
            .execute_restore(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition())
            )
            .await
            .is_err()
    );
    assert_eq!(
        read(&services, &session, "cat /etc/redis.conf").await,
        current
    );
    read(
        &services,
        &session,
        &format!("printf '%s' {} > {}", shq(&saved_backup), shq(&backup)),
    )
    .await;
    check("every backup is checked before any file is restored");
    read(&services, &session, "mv /etc/redis/redis.conf /tmp/lr-redis-original-inode; printf 'sentinel' > /tmp/lr-redis-sentinel; ln -s /tmp/lr-redis-sentinel /etc/redis/redis.conf").await;
    assert!(
        service
            .execute_restore(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition())
            )
            .await
            .is_err()
    );
    assert_eq!(
        read(&services, &session, "cat /tmp/lr-redis-sentinel").await,
        "sentinel"
    );
    assert_eq!(
        read(&services, &session, "cat /etc/redis.conf").await,
        current
    );
    read(
        &services,
        &session,
        "rm -f -- /etc/redis/redis.conf; mv /tmp/lr-redis-original-inode /etc/redis/redis.conf",
    )
    .await;
    check("symlink substitution is refused without touching other files");
    let result = service
        .execute_restore(
            &session,
            plan.clone(),
            DangerousConfirmation::approve(plan.definition()),
        )
        .await
        .unwrap();
    assert!(result.verification.passed);
    assert!(
        read(&services, &session, "cat /etc/redis/redis.conf")
            .await
            .contains("# full original configuration")
    );
    assert!(
        service
            .scan(&session)
            .await
            .unwrap()
            .statuses
            .iter()
            .any(|status| status.item_id == "redis-protected-mode"
                && status.observed == BaselineObservedValue::Unverified)
    );
    assert_eq!(
        read(
            &services,
            &session,
            "redis-cli --raw CONFIG GET protected-mode"
        )
        .await
        .trim(),
        "protected-mode\nno"
    );
    check("candidate parser changes cannot undo a verified full-file restoration");
    check("file restoration does not claim the running Redis state changed");

    let record = candidate_record(&services, &session, true).await;
    let plan = service.plan_restore(&session, &record.id).unwrap();
    assert!(
        service
            .execute_restore(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition())
            )
            .await
            .unwrap()
            .verification
            .passed
    );
    assert_eq!(
        read(
            &services,
            &session,
            "if [ ! -e /etc/redis.conf ] && [ ! -L /etc/redis.conf ]; then printf absent; fi"
        )
        .await,
        "absent"
    );
    check("an originally missing file is removed and independently verified absent");

    let record = candidate_record(&services, &session, false).await;
    let plan = service.plan_restore(&session, &record.id).unwrap();
    let executor = IntervenedRestore {
        inner: RestoreExecutor {
            service,
            session: &session,
            plan: &plan,
        },
    };
    let verification = run_planned_operation(
        &service.target,
        &service.journal,
        plan.operation.clone(),
        DangerousConfirmation::approve(plan.definition()),
        &executor,
    )
    .await
    .unwrap();
    assert!(!verification.passed);
    assert!(
        read(&services, &session, "cat /etc/redis/redis.conf")
            .await
            .contains("changed after restoration")
    );
    assert_eq!(
        service
            .record_by_id(session.target(), &record.id)
            .unwrap()
            .state,
        BaselineChangeState::Applied
    );
    assert!(
        services
            .operation_journal()
            .entries()
            .unwrap()
            .iter()
            .any(|entry| entry.operation_id == plan.operation.id
                && entry.phase == JournalPhase::VerificationFailed)
    );
    check("an intervening edit during readback is retained and never automatically reapplied");
    services.ssh().disconnect(&status.session_id).await.unwrap();
    println!("BASELINE_RESTORE_SUITE_COMPLETE");
}
