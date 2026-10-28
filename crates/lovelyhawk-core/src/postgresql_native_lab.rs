//! Invoked only by the owned WSL/Docker native PostgreSQL probe.
use super::*;
use crate::{
    BackendServices,
    database::{DatabaseProfileChanges, DatabaseProfileConfig, DatabaseSecretChange},
    ssh::{BoundSshSession, HostKeyConfirmations},
    store::PortableStore,
    target::TargetIdentity,
};
use tokio::task::JoinHandle;
use uuid::Uuid;

const PASSWORD: &str = "Lab'\"Native中#2026";

fn check(label: &str) {
    println!("POSTGRESQL_NATIVE_CHECK {label}");
}

async fn command(services: &BackendServices, session: &BoundSshSession, command: &str) -> String {
    let output = services
        .ssh()
        .execute_bound(session, command.to_owned(), Duration::from_secs(20))
        .await
        .unwrap();
    assert!(!output.timed_out);
    assert_eq!(output.exit_code, Some(0), "owned fixture command failed");
    output.output.trim().to_owned()
}

fn sql_command(sql: &str) -> String {
    format!(
        "runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres -c '{}'",
        sql.replace('\'', "'\\''")
    )
}

async fn sql(services: &BackendServices, session: &BoundSshSession, query: &str) -> String {
    command(services, session, &sql_command(query)).await
}

async fn until_sql(
    services: &BackendServices,
    session: &BoundSshSession,
    query: &str,
    expected: &str,
) {
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if sql(services, session, query).await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("independent PostgreSQL state observation timed out");
}

async fn no_native_backends(services: &BackendServices, session: &BoundSshSession) {
    until_sql(
        services,
        session,
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'LovelyHawk runtime review'",
        "0",
    )
    .await;
}

async fn bind(services: &BackendServices, id: &str) -> BoundSshSession {
    let status = services
        .ssh()
        .connect(id, HostKeyConfirmations::default())
        .await
        .unwrap();
    let guard = services
        .activate_target(TargetIdentity::new(id).unwrap())
        .unwrap();
    services
        .bind_active_ssh_session(&guard, &status.session_id)
        .await
        .unwrap()
}

fn save(services: &BackendServices, profile: &DatabaseProfileConfig, password: &str) {
    services
        .database()
        .upsert_profile(
            profile.clone(),
            DatabaseProfileChanges {
                password: DatabaseSecretChange::Replace(SecretValue::new(password)),
            },
        )
        .unwrap();
}

async fn rejected(
    services: &BackendServices,
    session: &BoundSshSession,
    profile: &DatabaseProfileConfig,
    expected: &str,
) {
    let error = services
        .database()
        .read_runtime_parameters(session, &profile.id, DatabaseConfigProduct::PostgreSql)
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains(expected),
        "unexpected sanitized failure: {text}"
    );
    assert!(!text.contains(PASSWORD));
    no_native_backends(services, session).await;
}

async fn block_settings(
    services: &BackendServices,
    session: &BoundSshSession,
) -> JoinHandle<CoreResult<crate::ssh::SshCommandOutput>> {
    let ssh = services.ssh().clone();
    let bound = session.clone();
    let command = sql_command(
        "BEGIN; SET application_name = 'LovelyHawk fixture blocker'; LOCK TABLE pg_catalog.pg_settings IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(15); ROLLBACK",
    );
    let blocker = tokio::spawn(async move {
        ssh.execute_bound(&bound, command, Duration::from_secs(18))
            .await
    });
    until_sql(services, session, "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'LovelyHawk fixture blocker' AND wait_event = 'PgSleep'", "1").await;
    blocker
}

async fn unblock(
    services: &BackendServices,
    session: &BoundSshSession,
    blocker: JoinHandle<CoreResult<crate::ssh::SshCommandOutput>>,
) {
    sql(services, session, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'LovelyHawk fixture blocker'").await;
    let _ = blocker.await.expect("fixture blocker task panicked");
}

#[tokio::test]
#[ignore = "requires tools/lab/probe-postgresql-native.mjs and its uniquely owned disposable target"]
async fn owned_postgresql_native_runtime() {
    let root = std::env::var("LOVELYHAWK_PG_NATIVE_ROOT").expect("owned fixture data root");
    let run = std::env::var("LOVELYHAWK_PG_NATIVE_RUN").expect("owned fixture UUID");
    let denied_id =
        std::env::var("LOVELYHAWK_PG_NATIVE_NO_FORWARD").expect("owned no-forward SSH profile");
    assert!(Uuid::parse_str(&run).is_ok() && Uuid::parse_str(&denied_id).is_ok());
    assert!(
        std::path::Path::new(&root)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("lovelyres-pg-native-")
    );
    let ca = std::fs::read_to_string(std::path::Path::new(&root).join("fixture-ca.pem")).unwrap();
    let wrong_ca =
        std::fs::read_to_string(std::path::Path::new(&root).join("fixture-other-ca.pem")).unwrap();
    let services = BackendServices::new(PortableStore::prepare(root.into()).unwrap()).unwrap();
    let mut session = bind(&services, &run).await;
    assert_eq!(
        command(&services, &session, "cat /tmp/lovelyres-pg-native-run").await,
        run
    );
    let mut profile = DatabaseProfileConfig::new(
        "Owned PostgreSQL native fixture",
        DatabaseEngine::Postgresql,
    );
    profile.connection.username = Some("lr_scram".to_owned());
    profile.postgresql_tls = Some(PostgresqlTlsSettings {
        mode: PostgresqlTlsMode::VerifyFull,
        ca_certificate_pem: Some(ca.clone()),
    });
    save(&services, &profile, PASSWORD);

    for (username, mode) in [
        ("lr_scram", PostgresqlTlsMode::VerifyFull),
        ("lr_md5", PostgresqlTlsMode::VerifyFull),
        ("lr_scram", PostgresqlTlsMode::SshLoopback),
    ] {
        profile.connection.username = Some(username.to_owned());
        profile.postgresql_tls = Some(PostgresqlTlsSettings {
            mode,
            ca_certificate_pem: (mode == PostgresqlTlsMode::VerifyFull).then(|| ca.clone()),
        });
        save(&services, &profile, PASSWORD);
        let snapshot = services
            .database()
            .read_runtime_parameters(&session, &profile.id, DatabaseConfigProduct::PostgreSql)
            .await
            .unwrap();
        services
            .database()
            .validate_runtime_parameters_snapshot(&snapshot)
            .unwrap();
        assert_eq!(snapshot.postgresql_tls_mode(), Some(mode));
        assert_eq!(snapshot.product(), DatabaseConfigProduct::PostgreSql);
        assert!(snapshot.document().rows().len() >= 300);
        let row = snapshot
            .document()
            .rows()
            .iter()
            .find(|row| row.name() == "ssl")
            .unwrap();
        assert_eq!(row.value().public_value(), Some("on"));
        assert_eq!(row.source(), Some("configuration file"));
        assert_eq!(row.pending_restart(), Some(false));
        assert!(!format!("{snapshot:?}").contains(PASSWORD));
        no_native_backends(&services, &session).await;
        check(match (username, mode) {
            ("lr_md5", _) => {
                "native MD5 over verified TLS returns real pg_settings and closes its connection"
            }
            (_, PostgresqlTlsMode::SshLoopback) => {
                "explicit SSH loopback SCRAM returns real pg_settings without a remote client"
            }
            _ => "native SCRAM and verified CA/IP return real pg_settings and close the connection",
        });
    }

    profile.postgresql_tls = Some(PostgresqlTlsSettings {
        mode: PostgresqlTlsMode::VerifyFull,
        ca_certificate_pem: Some(ca.clone()),
    });
    save(&services, &profile, "WrongNativePasswordCanary");
    rejected(&services, &session, &profile, "口令认证失败").await;
    check("wrong password is rejected with closed text and no lingering backend");
    profile.postgresql_tls.as_mut().unwrap().ca_certificate_pem = Some(wrong_ca);
    save(&services, &profile, PASSWORD);
    rejected(&services, &session, &profile, "连接或认证失败").await;
    check("an unrelated CA does not authenticate the database");
    profile.postgresql_tls.as_mut().unwrap().ca_certificate_pem = None;
    save(&services, &profile, PASSWORD);
    rejected(&services, &session, &profile, "连接或认证失败").await;
    check("a private fixture certificate is not silently trusted by default");
    profile.postgresql_tls.as_mut().unwrap().ca_certificate_pem = Some(ca.clone());
    profile.connection.host = "localhost".to_owned();
    save(&services, &profile, PASSWORD);
    rejected(&services, &session, &profile, "连接或认证失败").await;
    check("a valid CA cannot bypass the certificate hostname check");
    profile.connection.host = "127.0.0.1".to_owned();
    profile.connection.username = Some("lr_denied".to_owned());
    save(&services, &profile, PASSWORD);
    rejected(&services, &session, &profile, "权限不足").await;
    check("runtime query permission denial is reported without server details");
    profile.connection.username = Some("lr_scram".to_owned());
    save(&services, &profile, PASSWORD);

    // Lock a catalog view on this disposable database so the real closed query
    // waits. Independent pg_stat_activity proves the operation actually started.
    for action in ["cancel", "target", "profile", "timeout", "disconnect"] {
        let blocker = block_settings(&services, &session).await;
        let database = services.database().clone();
        let bound = session.clone();
        let id = profile.id.clone();
        let pending = tokio::spawn(async move {
            database
                .read_runtime_parameters(&bound, &id, DatabaseConfigProduct::PostgreSql)
                .await
        });
        until_sql(&services, &session, "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'LovelyHawk runtime review' AND wait_event_type = 'Lock'", "1").await;
        match action {
            "cancel" => {
                pending.abort();
                assert!(pending.await.unwrap_err().is_cancelled());
            }
            "target" => {
                services
                    .activate_target(TargetIdentity::new(&run).unwrap())
                    .unwrap();
                let error = tokio::time::timeout(Duration::from_secs(1), pending)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                assert!(matches!(error, CoreError::TargetChanged { .. }));
                let guard = services.target().current_guard().unwrap();
                session = services
                    .bind_active_ssh_session(&guard, session.session_id())
                    .await
                    .unwrap();
            }
            "profile" => {
                profile.name.push_str(" revised");
                services
                    .database()
                    .upsert_profile(profile.clone(), DatabaseProfileChanges::default())
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), pending)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
            }
            "timeout" => {
                let error = tokio::time::timeout(Duration::from_secs(5), pending)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                assert!(error.to_string().contains("锁等待达到时限"));
                assert!(!error.to_string().contains(PASSWORD));
            }
            "disconnect" => {
                services
                    .ssh()
                    .disconnect(session.session_id())
                    .await
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), pending)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
                session = bind(&services, &run).await;
            }
            _ => unreachable!(),
        }
        no_native_backends(&services, &session).await;
        unblock(&services, &session, blocker).await;
        check(match action {
            "cancel" => {
                "dropping a live native request closes transport; PostgreSQL leaves its bounded lock wait"
            }
            "target" => {
                "switching target generation rejects the live result and releases its database connection"
            }
            "profile" => {
                "editing the profile cancels the in-flight snapshot without accepting stale results"
            }
            "timeout" => {
                "the real pg_settings query observes its lock timeout and releases the connection"
            }
            _ => {
                "SSH disconnect ends the native request; reconnect can independently verify cleanup"
            }
        });
    }

    let old = services
        .database()
        .read_runtime_parameters(&session, &profile.id, DatabaseConfigProduct::PostgreSql)
        .await
        .unwrap();
    profile.name.push_str(" newer");
    services
        .database()
        .upsert_profile(profile.clone(), DatabaseProfileChanges::default())
        .unwrap();
    assert!(
        services
            .database()
            .validate_runtime_parameters_snapshot(&old)
            .is_err()
    );
    check("a completed snapshot is invalidated by a later profile edit");

    sql(&services, &session, "ALTER SYSTEM SET ssl = 'off'").await;
    sql(&services, &session, "SELECT pg_reload_conf()").await;
    until_sql(&services, &session, "SHOW ssl", "off").await;
    rejected(&services, &session, &profile, "连接或认证失败").await;
    check("required TLS does not downgrade when PostgreSQL disables SSL");
    services
        .ssh()
        .disconnect(session.session_id())
        .await
        .unwrap();
    let denied_session = bind(&services, &denied_id).await;
    rejected(&services, &denied_session, &profile, "SSH").await;
    check("sshd forwarding denial produces a bounded error without invoking a database CLI");
    services
        .ssh()
        .disconnect(denied_session.session_id())
        .await
        .unwrap();
    println!("POSTGRESQL_NATIVE_SUITE_COMPLETE");
}
